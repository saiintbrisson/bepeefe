use crate::verifier::event::PayloadSlot;

use super::*;

/// One traversal of one path, forked at each branch and run to an exit or a
/// prune.
#[derive(Clone)]
pub struct Walk<'v, 'a> {
    verifier: &'v Verifier<'a>,

    frame: Frame,

    /// pc of the instruction currently being checked. Read via
    /// [`Self::this_pc`] or [`Self::next_pc`].
    pc: usize,
    /// Instructions to advance before the next check, 1 across a `ld_imm64`.
    skip: usize,
    /// Whether the walk is ready to exit. Set when encountering a JMP, except
    /// for pseudo calls.
    exit: bool,

    /// How deep this walker is.
    depth: usize,
    /// How this walk was born.
    origin: WalkOrigin,
    /// Stable id, drawn from the verifier in [`Self::fork_at`] and emitted on
    /// the enter event. Snapshots carry it so a `StatePruned` can name the
    /// walk that covered one.
    walk_id: usize,

    /// Registers the current instruction read, reset before each check.
    /// `insn_reads` is a `Cell` because [`Self::reg`] gathers reads
    /// behind a shared borrow.
    insn_reads: Cell<RegMask>,
    /// Registers the current instruction wrote, reset before each check.
    insn_writes: RegMask,
}

/// Where walker `matched` sat relative to a [`StateSnapshot`]'s `fork_pc`,
/// which tells the reader how to reach the pruned walk's continuation without
/// first resolving `matched`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub enum PruneSite {
    /// `fork_pc` is a jump `matched` branched at. The continuation is the arms
    /// `matched` spawned there, its children, which share this `fork_pc`.
    Jump,
    /// `fork_pc` is `matched`'s own entry. `matched` is itself the arm the
    /// pruned walk merges into.
    Arm,
}

/// A verifier state recorded at a pc so a later, equivalent state reaching the
/// same pc can be pruned against it.
pub struct StateSnapshot {
    registers: [RegisterState; 11],
    stack_objects: BTreeMap<u32, StackSlot>,
    /// Id of the walk that recorded this state, reported as `matched` when a
    /// later walk is pruned against it.
    walk_id: usize,
    /// Whether this pc is `walk_id`'s branch jump or its entry, reported as the
    /// `site` of the resulting prune.
    site: PruneSite,
}

impl StateSnapshot {
    fn is_equivalent(&self, sub: &Walk<'_, '_>) -> bool {
        // if registers are equal, ok
        //
        // if old is unknown and new is range/specific, it has to have visited
        // more states than the new verifier ever will, as it didnt have any
        // assumptions it could rule out.
        //
        // if old is uninit and new is init, because all other registers are also OK,
        // we know that no code under this branch will ever read this register
        // before initializing it, so it is also OK. the only problem this
        // could cause is if some range somewhere used the knowledge contained
        // in the new reg (like a ptr), but that's irrelevant since the previous
        // run would have either: resulted in an error if a branch tried refining
        // it, or it just wouldnt have reached a insn that reads it anyway since
        // the previous run has to have been the same or LESS precise than this.
        let registers_are_equivalent =
            self.registers
                .iter()
                .zip(sub.frame.registers.iter())
                .all(|(old, new)| match (old, new) {
                    _ if old == new => true,

                    (RegisterState::Uninit | RegisterState::Scalar(Scalar::Unknown), _) => true,

                    _ => false,
                });

        registers_are_equivalent && self.stack_objects == sub.frame.stack_objects
    }
}

/// Registers `insn` reads, judged from the opcode alone.
///
/// Insn events prefer the state-based accounting gathered while an
/// instruction is checked, which knows, for example, that a MOV destination
/// is never read. This covers the cases that accounting cannot see: jumps
/// recorded before their check runs and subprogram calls, whose argument
/// reads flow through the raw register array rather than the tracked
/// accessors.
fn static_jmp_reads(insn: &Insn) -> RegMask {
    if !matches!(insn.class(), BPF_JMP | BPF_JMP32) {
        return RegMask::empty();
    }

    match insn.opcode() & JMP_OP_MASK {
        BPF_EXIT => RegMask::R0,
        BPF_CALL | BPF_JA => RegMask::empty(),
        _ => {
            let mut mask = RegMask::single(insn.dst_reg());
            if insn.opcode() & BPF_X == BPF_X {
                mask |= RegMask::single(insn.src_reg());
            }
            mask
        }
    }
}

impl<'v, 'a> Walk<'v, 'a> {
    /// The root walk of a verification, entry frame at pc 0, walk id 0.
    pub fn root(verifier: &'v Verifier<'a>, registers: [RegisterState; 11]) -> Self {
        Walk {
            verifier,
            frame: Frame::root(registers, verifier.prog.func.return_type),
            pc: 0,
            skip: 0,
            exit: false,
            depth: 0,
            origin: WalkOrigin::Call,
            walk_id: 0,
            insn_reads: Cell::new(RegMask::empty()),
            insn_writes: RegMask::empty(),
        }
    }

    /// A child walk of the given `origin`, over `frame`, entering `pc`.
    fn spawn(&self, frame: Frame, pc: usize, origin: WalkOrigin) -> Self {
        Walk {
            verifier: self.verifier,
            frame,
            pc,
            skip: 0,
            exit: false,
            depth: self.depth + 1,
            origin,
            walk_id: self.verifier.fresh_walk_id(),
            insn_reads: Cell::new(RegMask::empty()),
            insn_writes: RegMask::empty(),
        }
    }

    /// Fork a sibling walk continuing from `pc` in the same frame, with the
    /// arm's comparison refinement applied to the cloned frame.
    fn fork_at(&self, pc: usize, origin: WalkOrigin) -> Self {
        let mut fork = self.spawn(self.frame.clone(), pc, origin);
        if let WalkOrigin::Branch {
            refined: Some((idx, state)),
            ..
        }
        | WalkOrigin::Fallthrough {
            refined: Some((idx, state)),
            ..
        } = origin
        {
            fork.set_reg(idx, state);
        }
        fork
    }

    /// Enter a subprogram at `target`. Fresh frame with the callee's
    /// registers and its own call stack.
    pub fn enter_subprog(
        &self,
        target: usize,
        expected_return: Option<BtfTypeId>,
        registers: [RegisterState; 11],
    ) -> Self {
        let frame = Frame::enter(registers, target, &self.frame.call_stack, expected_return);
        let mcd = &self.verifier.max_call_depth;
        mcd.set(mcd.get().max(frame.call_stack.len()));
        self.spawn(frame, target, WalkOrigin::Call)
    }

    /// The instruction currently being checked.
    #[inline]
    pub fn this_pc(&self) -> usize {
        self.pc
    }

    /// The instruction after the current one, e.g. a jump's fallthrough or the
    /// base a jump offset is applied to.
    #[inline]
    pub fn next_pc(&self) -> usize {
        self.pc + 1
    }

    #[inline]
    pub fn regs(&self) -> &[RegisterState; 11] {
        &self.frame.registers
    }

    /// # Panics
    ///
    /// Panics if `idx` is out of bounds (>= 11).
    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "register index is caller-validated to be < 11"
    )]
    pub fn reg(&self, idx: u8) -> RegisterState {
        self.insn_reads
            .set(self.insn_reads.get() | RegMask::single(idx));
        self.frame.registers[idx as usize]
    }

    /// # Panics
    ///
    /// Panics if `idx` is out of bounds (>= 11).
    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "register index is caller-validated to be < 11"
    )]
    pub fn set_reg(&mut self, idx: u8, val: RegisterState) {
        self.insn_writes |= RegMask::single(idx);
        self.frame.registers[idx as usize] = val;
    }
}

impl<'v, 'a> Walk<'v, 'a> {
    /// Walks instructions from the entry pc to an exit.
    ///
    /// This function is responsible for emitting the Enter and Exist branch
    /// pairs, as well as the Call ones. But first, it checks if that
    /// instruction was already visited in a equivalent state. If so, this walk
    /// is pruned and a single `StatePruned` event is emitted instead.
    ///
    /// For each instruction in the stream, we also check if an equivalent state
    /// was visited and stop if one is found.
    pub fn run(mut self) -> Result<VerificationOutput, VerifierError> {
        if self.prune_if_visited(self.this_pc()) {
            return Ok(self.output());
        }

        self.record_walk_enter();

        let prog = &self.verifier.prog.clone();
        let mut iter = prog.insns.iter().enumerate().skip(self.this_pc());

        while let Some((idx, insn)) = iter.by_ref().nth(self.skip) {
            self.pc = idx;
            if self.prune_if_visited(self.this_pc()) {
                break;
            }

            self.skip = 0;
            self.insn_reads.set(RegMask::empty());
            self.insn_writes = RegMask::empty();

            let record_early = Self::records_before_check(insn);
            if record_early {
                self.record_insn(idx, insn);
            }
            self.check_insn(insn)?;
            if !record_early {
                self.record_insn(idx, insn);
            }

            if self.exit {
                break;
            }
        }

        guard!(self, self.exit, "program ended without calling exit");

        self.record_walk_exit();

        Ok(self.output())
    }

    fn output(&self) -> VerificationOutput {
        VerificationOutput {
            max_call_depth: self.verifier.max_call_depth.get(),
            r0: self.reg(0),
        }
    }

    /// Prunes and ends the walk when an earlier walk already covered `idx`'s
    /// state. `matched` names the walk that recorded the covering snapshot.
    fn prune_if_visited(&mut self, idx: usize) -> bool {
        let matched = self
            .verifier
            .snapshots
            .borrow()
            .get(&idx)
            .and_then(|states| {
                states
                    .iter()
                    .find(|s| s.is_equivalent(self))
                    .map(|s| (s.walk_id, s.site))
            });
        if let Some((matched, site)) = matched
            && matched != self.walk_id
        {
            self.record(VerifierEvent::StatePruned {
                depth: self.depth,
                fork_pc: idx,
                matched,
                site,
            });
            self.mark_exit();
            true
        } else {
            false
        }
    }

    /// Records this walk's state at the current pc so a later walk reaching it
    /// with an equal or narrower state can be pruned against it. `site` is the
    /// role of that pc, the branch jump for [`PruneSite::Jump`] (recorded by
    /// the parent mid-jump) or an arm's entry for [`PruneSite::Arm`]
    /// (recorded by the fork before it runs), which is also how the prune
    /// reads `matched`.
    fn snapshot_state(&self, site: PruneSite) {
        self.verifier
            .snapshots
            .borrow_mut()
            .entry(self.this_pc())
            .or_default()
            .push(StateSnapshot {
                registers: self.frame.registers,
                stack_objects: self.frame.stack_objects.clone(),
                walk_id: self.walk_id,
                site,
            });
    }

    fn record(&self, event: VerifierEvent<'_>) {
        if let Some(cap) = self.verifier.config.capture.as_ref() {
            cap.record(Event::Verifier(event));
        }
    }

    /// Frames the walk in the event stream according to this walk's origin,
    /// paired with [`Self::record_walk_exit`].
    fn record_walk_enter(&self) {
        match self.origin {
            WalkOrigin::Branch { .. } | WalkOrigin::Fallthrough { .. } => {
                self.record(VerifierEvent::BranchEnter {
                    depth: self.depth,
                    id: self.walk_id,
                    target_pc: self.this_pc(),
                    kind: self.origin,
                })
            }
            WalkOrigin::Call => {
                let sig = self.verifier.prog.subprogs.get(&self.this_pc());
                self.record(VerifierEvent::CallEnter {
                    depth: self.depth,
                    id: self.walk_id,
                    target_pc: self.this_pc(),
                    name: sig.map(|s| Cow::from(s.name.as_str())).unwrap_or_default(),
                    btf_id: sig.and_then(|s| s.btf_id),
                    registers: self.regs(),
                });
            }
        }
    }

    fn record_walk_exit(&self) {
        match self.origin {
            WalkOrigin::Branch { .. } | WalkOrigin::Fallthrough { .. } => {
                self.record(VerifierEvent::BranchExit { depth: self.depth })
            }
            WalkOrigin::Call => self.record(VerifierEvent::CallExit {
                depth: self.depth,
                r0: self.reg(0),
            }),
        }
    }

    /// Records a ruled-out arm of the jump this walk is sitting on. The
    /// `origin` carries the jump's pc, so all arms of one branch share it.
    fn record_branch_dead(&self, target_pc: usize, origin: WalkOrigin) {
        self.record(VerifierEvent::BranchDead {
            depth: self.depth + 1,
            target_pc,
            kind: origin,
        });
    }

    /// Records a check instruction with its read and written registers.
    fn record_insn(&self, pc: usize, insn: &Insn) {
        let mut written = [(0u8, RegisterState::Uninit); 11];
        let mut count = 0;
        for (idx, state) in self.frame.registers.iter().enumerate() {
            if self.insn_writes.contains(RegMask::single(idx as u8))
                && let Some(slot) = written.get_mut(count)
            {
                *slot = (idx as u8, *state);
                count += 1;
            }
        }

        self.record(VerifierEvent::Insn {
            depth: self.depth,
            pc,
            read: self.insn_reads.get() | static_jmp_reads(insn) | self.pseudo_call_reads(insn),
            written: written.get(..count).unwrap_or_default(),
        });
    }

    /// Emits the static view of a `bpf_perf_event_output` payload.
    ///
    /// The written stack slots inside the region the data pointer covers, the
    /// payload type may not appear in BTF, so this is the only structural
    /// information a consumer can get about it, field boundaries without
    /// types.
    pub fn record_perf_event_layout(&self) {
        if self.verifier.config.capture.is_none() {
            return;
        }

        let RegisterState::PtrToMap { map_fd } = self.reg(2) else {
            return;
        };

        let size = match self.reg(5) {
            RegisterState::Scalar(Scalar::U32(r)) => r.single_val(),
            RegisterState::Scalar(Scalar::U64(r)) => {
                r.single_val().and_then(|v| u32::try_from(v).ok())
            }
            _ => None,
        };

        let region = match (self.reg(4), size) {
            (RegisterState::PtrToStack { offset }, Some(len)) => offset
                .single_val()
                .map(|base| (base, base.saturating_add(len))),
            _ => None,
        };

        let slots: Vec<PayloadSlot> = region
            .map(|(base, end)| {
                self.frame
                    .stack_objects
                    .range(base..end)
                    .filter(|&(&addr, slot)| addr.saturating_add(slot.size) <= end)
                    .map(|(&addr, slot)| PayloadSlot {
                        offset: addr - base,
                        size: slot.size,
                        state: slot.state,
                        pc: slot.pc,
                    })
                    .collect()
            })
            .unwrap_or_default();

        self.record(VerifierEvent::PerfEventLayout {
            depth: self.depth,
            pc: self.this_pc(),
            map_fd,
            size,
            slots: &slots,
        });
    }

    /// Whether checking `insn` spawns nested walks (branch arms or a
    /// subprogram).
    ///
    /// Those record their Insn event before the check so the nested events
    /// follow them in the stream. Everything else records after, with the
    /// registers reflecting what the instruction wrote.
    fn records_before_check(insn: &Insn) -> bool {
        if !matches!(insn.class(), BPF_JMP | BPF_JMP32) {
            return false;
        }
        insn.opcode() & JMP_OP_MASK != BPF_CALL || insn.src_reg() == BPF_PSEUDO_CALL
    }

    pub fn warn(&self, message: impl Into<Cow<'static, str>>) {
        self.record(VerifierEvent::Warning {
            pc: self.this_pc(),
            message: message.into(),
        });
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "this_pc() is the current instruction, always in 0..insns.len()"
    )]
    pub fn err(&self, msg: &'static str) -> VerifierError {
        let insn_off = self.this_pc();
        let insn = self.verifier.prog.insns[insn_off];

        VerifierError::Other {
            insn,
            insn_off,
            msg,
            registers: Box::new(*self.regs()),
        }
    }

    /// Run a fork to completion and absorb its outputs.
    fn run_fork(&mut self, pc: usize, origin: WalkOrigin) -> Result<(), VerifierError> {
        let fork = self.fork_at(pc, origin);

        match origin {
            WalkOrigin::Branch { .. } => fork.snapshot_state(PruneSite::Arm),
            WalkOrigin::Fallthrough { .. } => {}
            _ => return Err(self.err("called run_fork for Call walker")),
        }

        let out = fork.run()?;
        self.set_reg(0, out.r0);

        Ok(())
    }

    /// Executes branching based on a decision.
    pub fn run_decision(&mut self, insn: &Insn, branch: BranchResult) -> Result<(), VerifierError> {
        let offset = if insn.opcode() == BPF_JMP32 | BPF_K | BPF_JA {
            insn.imm()
        } else {
            insn.offset() as i32
        };

        let target_pc = (self.next_pc() as isize + offset as isize) as usize;

        let narrow = |reg: RegisterState| -> RegisterState {
            if insn.class() != BPF_JMP32 {
                return reg;
            }

            match reg {
                RegisterState::Scalar(Scalar::U64(r)) => {
                    RegisterState::Scalar(Scalar::U32(ScalarRange {
                        min: r.min as u32,
                        max: r.max as u32,
                        stride: r.stride as u32,
                    }))
                }
                other => other,
            }
        };

        self.snapshot_state(PruneSite::Jump);

        let fork_pc = self.this_pc();
        let branch_origin = WalkOrigin::Branch {
            refined: branch.branch_reg.map(|reg| (insn.dst_reg(), narrow(reg))),
            fork_pc,
        };

        let fallthrough_origin = WalkOrigin::Fallthrough {
            refined: branch
                .fallthrough_reg
                .map(|reg| (insn.dst_reg(), narrow(reg))),
            fork_pc,
        };

        match branch.decision {
            BranchDecision::Both => {
                self.run_fork(target_pc, branch_origin)?;
                self.run_fork(self.next_pc(), fallthrough_origin)?;
            }
            BranchDecision::SkipBranch => {
                self.record_branch_dead(target_pc, branch_origin);
                self.run_fork(self.next_pc(), fallthrough_origin)?;
            }
            BranchDecision::SkipFallthrough => {
                self.run_fork(target_pc, branch_origin)?;
                self.record_branch_dead(self.next_pc(), fallthrough_origin);
            }
        }

        self.mark_exit();

        Ok(())
    }

    /// Argument registers a subprogram call reads. r1 through the last
    /// parameter the callee's BTF signature declares.
    fn pseudo_call_reads(&self, insn: &Insn) -> RegMask {
        let is_pseudo_call = matches!(insn.class(), BPF_JMP | BPF_JMP32)
            && insn.opcode() & JMP_OP_MASK == BPF_CALL
            && insn.src_reg() == BPF_PSEUDO_CALL;
        if !is_pseudo_call {
            return RegMask::empty();
        }
        let target_pc = (self.next_pc() as isize + insn.imm() as isize) as usize;
        let argc = self
            .verifier
            .prog
            .subprogs
            .get(&target_pc)
            .map_or(5, |sig| sig.params_types.len().min(5));
        (1..=argc).fold(RegMask::empty(), |mask, i| mask | RegMask::single(i as u8))
    }
}

impl<'v, 'a> Walk<'v, 'a> {
    pub fn verifier(&self) -> &'v Verifier<'a> {
        self.verifier
    }

    pub fn frame(&self) -> &Frame {
        &self.frame
    }

    /// Mutable handle to the current frame's stack slots, for the store check.
    pub fn stack_mut(&mut self) -> &mut BTreeMap<u32, StackSlot> {
        &mut self.frame.stack_objects
    }

    /// The argument registers a helper call reads.
    pub fn arg_regs(&self) -> helpers::ArgRegs<'_> {
        helpers::ArgRegs::new(&self.frame.registers, &self.insn_reads)
    }

    /// Skip the next instruction word, used after a `ld_imm64` consumes two.
    pub fn skip_next(&mut self) {
        self.skip = 1;
    }

    /// End the walk at the current instruction, used by the exit check.
    pub fn mark_exit(&mut self) {
        self.exit = true;
    }
}
