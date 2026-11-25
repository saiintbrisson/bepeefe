mod alu;
mod helper;
mod mem;

use super::*;

impl<'v, 'a> Walk<'v, 'a> {
    fn mark_unknown(&mut self, reg: u8) -> Result<(), VerifierError> {
        guard!(self, reg < 10, "tried marking r10 as unknown");
        self.set_reg(reg, RegisterState::Scalar(Scalar::Unknown));
        Ok(())
    }

    fn dst_state(&self, insn: &Insn) -> RegisterState {
        self.reg(insn.dst_reg())
    }

    fn src_state(&self, insn: &Insn) -> Result<RegisterState, VerifierError> {
        guard!(self, insn.src_reg() <= 10, "invalid src register value");

        let Some(Src::Reg(reg)) = insn.source() else {
            guard!(self, "instruction doesn't take src register")
        };

        Ok(self.reg(reg))
    }

    /// Emits warning events for common pitfalls a developer might make.
    fn hook_advisory(&self, reg: RegisterState, offset: i32, size: u32) {
        let Some(prog_type) = self.verifier().prog.hook.as_ref().map(|h| h.prog_type) else {
            return;
        };

        match (prog_type, reg) {
            (ProgType::Tracepoint, RegisterState::PtrToCtx { offset: base, .. })
                if let Some(read_min) = base.min.checked_add_signed(offset) =>
            {
                /// For tracepoint programs, the context's first field is
                /// `struct trace_entry ent`. This struct carries a four
                /// properties regarding that trace execution (type, PID, etc),
                /// but those properties are not what you think they are.
                ///
                /// On tracepoint dispatch however, the Kernel overwrites this
                /// entire struct with a pointer to `pt_regs`, which is needed
                /// by some helpers, e.g. `bpf_perf_event_output`. So the
                /// convetion is to avoid accessing any fields in the first 8
                /// bytes.
                ///
                /// Ref: <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=98b5c2c65c2951772a8fc661f50d675e450e8bce>
                const TRACE_ENTRY_SIZE: u32 = 8;

                if read_min + size <= TRACE_ENTRY_SIZE {
                    self.warn(
                        "reading from trace_entry: kernel overwrites struct with a pointer to pt_regs",
                    );
                }
            }
            _ => {}
        }
    }

    pub fn check_insn(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        guard!(
            self,
            crate::isa::opcode_name(insn.opcode()) != "unknown",
            "VM does not support this instruction"
        );
        guard!(self, insn.src_reg() <= 10, "insn with invalid src register");
        guard!(
            self,
            insn.dst_reg() < 10 || matches!(insn.class(), BPF_ST | BPF_STX if insn.dst_reg() == 10),
            "insn with invalid dst register"
        );

        match insn.class() {
            BPF_ALU32 | BPF_ALU64 => self.check_alu(insn)?,
            BPF_LD => self.check_non_conventional_ld(insn)?,
            BPF_LDX => self.check_ldx(insn)?,
            BPF_ST | BPF_STX => self.check_st(insn)?,
            BPF_JMP32 | BPF_JMP => self.check_jmp(insn)?,
            _ => guard!(self, "unsupported instruction class"),
        }

        Ok(())
    }

    fn check_jmp(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        let jmp_op = insn.opcode() & JMP_OP_MASK;

        if jmp_op == BPF_CALL {
            return self.check_jmp_call(insn);
        }

        if jmp_op == BPF_EXIT {
            guard!(self, insn.offset() == 0, "reserved offset field");
            guard!(self, insn.src_reg() == 0, "reserved offset field");
            guard!(
                self,
                insn.opcode() & 0b1111 == BPF_JMP | BPF_K,
                "must be BPF_JMP | BPF_K"
            );

            if matches!(self.reg(0), RegisterState::PtrToStack { .. }) {
                return Err(self.err("cannot return a pointer to the stack"));
            }

            if let Some(ty) = self.frame().expected_return {
                let btf_type = self.verifier().prog.btf.resolve_must(ty);
                let ok = match btf_type.kind() {
                    BtfKind::Int(_) => self.reg(0).is_scalar(),
                    BtfKind::Ptr(_) => self.reg(0).is_pointer(),
                    _ => true,
                };
                if !ok {
                    return Err(self.err("return value does not match declared return type"));
                }
            }

            self.mark_exit();
            return Ok(());
        }

        let Some(offset) = insn.jump_offset() else {
            guard!(self, "jump without a target")
        };
        let target_pc = self.next_pc() as isize + offset as isize;

        guard!(self, offset != -1, "infinite halt");
        guard!(
            self,
            target_pc >= self.frame().starting_pc as isize
                && target_pc < self.verifier().prog.insns.len() as isize,
            "invalid offset"
        );

        if jmp_op == BPF_JA {
            return self.run_decision(insn, BranchResult::skip_fallthrough());
        }

        let signed = matches!(jmp_op, BPF_JSGT | BPF_JSGE | BPF_JSLT | BPF_JSLE);
        let jmp32 = insn.width().is_32();

        let known_val = |val: u64| {
            let val = if jmp32 {
                if signed {
                    val as u32 as i32 as i64 as u64
                } else {
                    val as u32 as u64
                }
            } else {
                val
            };
            ExprVal::Known(ExprRange {
                min: val,
                max: val,
                stride: 1,
            })
        };

        let scalar_to_expr = |s: Scalar| -> ExprVal {
            let mask = if jmp32 { u32::MAX as u64 } else { u64::MAX };
            let (min, max, stride) = match s {
                Scalar::U32(r) => (r.min as u64, r.max as u64, r.stride as u64),
                Scalar::U64(r) => (r.min & mask, r.max & mask, r.stride & mask),
                Scalar::Unknown => return ExprVal::Unkown,
            };
            if signed {
                let (smin, smax) = if jmp32 {
                    (
                        min as u32 as i32 as i64 as u64,
                        max as u32 as i32 as i64 as u64,
                    )
                } else {
                    (min, max)
                };
                if smin as i64 > smax as i64 {
                    return ExprVal::Unkown;
                }
                ExprVal::Known(ExprRange {
                    min: smin,
                    max: smax,
                    stride,
                })
            } else {
                ExprVal::Known(ExprRange { min, max, stride })
            }
        };

        let lhs = match self.dst_state(insn) {
            RegisterState::Scalar(s) => scalar_to_expr(s),
            RegisterState::PtrToMapValueOrNull { map_fd } => ExprVal::PtrToMapValueOrNull(map_fd),
            RegisterState::PtrToPacket { id, offset, .. } => ExprVal::Packet { id, offset },
            RegisterState::PtrToPacketEnd => ExprVal::PacketEnd,

            // There's no refinement to be done
            RegisterState::PtrToMapValue { .. } => {
                return self.run_decision(insn, BranchResult::both());
            }

            _ => guard!(self, "unsupported dst register for comparison"),
        };

        let rhs = match insn.source() {
            Some(Src::Reg(_)) => match self.src_state(insn)? {
                RegisterState::Scalar(s) => scalar_to_expr(s),
                RegisterState::PtrToMapValueOrNull { map_fd } => {
                    ExprVal::PtrToMapValueOrNull(map_fd)
                }
                RegisterState::PtrToPacket { id, offset, .. } => ExprVal::Packet { id, offset },
                RegisterState::PtrToPacketEnd => ExprVal::PacketEnd,

                // There's no refinement to be done
                RegisterState::PtrToMapValue { .. } => {
                    return self.run_decision(insn, BranchResult::both());
                }

                _ => guard!(self, "unsupported src register for comparison"),
            },
            _ => known_val(insn.imm() as u32 as u64),
        };

        let branch = decide_branch(jmp_op, lhs, rhs, jmp32).map_err(|msg| self.err(msg))?;

        self.run_decision(insn, branch)
    }

    fn check_jmp_call(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        guard!(
            self,
            insn.opcode() & 0b1111 == BPF_JMP | BPF_K,
            "call must be BPF_JMP | BPF_K"
        );

        match insn.call_kind() {
            Some(CallKind::Subprog(_)) => self.check_pseudo_call(insn)?,
            Some(CallKind::Helper(id)) => {
                let helper = helpers::lookup(id)
                    .ok_or_else(|| self.err("BPF_HELPER_CALL refers to invalid helper ID"))?;
                self.check_helper_args(helper.sig())?;

                if id == helpers::PerfEventOutput::ID {
                    self.record_perf_event_layout();
                }

                let retval = helper
                    .retval(self.verifier().vm, self.arg_regs())
                    .map_err(|msg| self.err(msg))?;
                self.set_reg(0, retval);
            }
            _ => {}
        }

        Ok(())
    }

    fn check_pseudo_call(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        let Some(target_pc) = insn.jump_target(self.this_pc()) else {
            guard!(self, "call target is not a subprogram call")
        };
        let target_pc = target_pc as usize;
        let callee_sig = self
            .verifier()
            .prog
            .subprogs
            .get(&target_pc)
            .cloned()
            .ok_or_else(|| self.err("call target not aligned to a BTF-described subprogram"))?;

        guard!(
            self,
            !self.frame().call_stack.contains(&target_pc),
            "recursive subprogram call"
        );

        guard!(
            self,
            self.frame().call_stack.len() + 1 < MAX_CALL_FRAMES,
            "subprogram call depth exceeds maximum"
        );

        let btf = &self.verifier().prog.btf;
        let callee_registers = registers_from_params(btf, &callee_sig.params_types)
            .map_err(|_| self.err("callee has unsupported parameter type"))?;

        for (expected, actual) in callee_registers
            .iter()
            .zip(self.regs())
            .skip(1)
            .take(callee_sig.params_types.len())
        {
            let compatible = matches!(
                (actual, expected),
                (RegisterState::Scalar(_), RegisterState::Scalar(_))
                    | (
                        RegisterState::PtrToCtx { .. },
                        RegisterState::PtrToCtx { .. }
                    )
                    | (
                        RegisterState::PtrToStack { .. }
                            | RegisterState::PtrToMapValue { .. }
                            | RegisterState::PtrToMap { .. },
                        RegisterState::PtrToCtx { .. },
                    )
            );

            if !compatible {
                return Err(self.err("argument type mismatch at subprogram call"));
            }
        }

        let sub = self.enter_subprog(target_pc, callee_sig.return_type, callee_registers);
        let sub_out = sub.run()?;
        // TODO: ensure this is a scalar
        self.set_reg(0, sub_out.r0);

        for i in 1..=5 {
            self.set_reg(i, RegisterState::Uninit);
        }

        Ok(())
    }
}
