use super::*;

impl<'v, 'a> Walk<'v, 'a> {
    fn mark_unknown(&mut self, reg: u8) -> Result<(), VerifierError> {
        guard!(self, reg < 10, "tried marking r10 as unknown");
        self.set_reg(reg, RegisterState::Scalar(Scalar::Unknown));
        Ok(())
    }

    fn dst_reg(&self, insn: &Insn) -> RegisterState {
        self.reg(insn.dst_reg())
    }

    fn src_reg(&self, insn: &Insn) -> Result<RegisterState, VerifierError> {
        guard!(self, insn.src_reg() <= 10, "invalid src register value");

        let jmp_op = insn.opcode() & JMP_OP_MASK;
        let is_x = insn.opcode() & BPF_X == BPF_X;

        let has_src = match insn.class() {
            BPF_ALU32 | BPF_ALU64 => is_x,
            BPF_LDX => true,
            BPF_ST | BPF_STX => insn.class() == BPF_STX,
            BPF_JMP32 | BPF_JMP if jmp_op == BPF_CALL => false,
            BPF_JMP32 | BPF_JMP => is_x,
            _ => false,
        };

        guard!(self, has_src, "instruction doesn't take src register");
        Ok(self.reg(insn.src_reg()))
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
            _ => {}
        }

        Ok(())
    }

    fn check_alu(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        let op = insn.opcode() & ALU_OP_MASK;

        let src = if let Ok(src_state) = self.src_reg(insn) {
            guard!(self, insn.imm() == 0, "illegal reserved imm field");

            guard!(
                self,
                src_state != RegisterState::Uninit,
                "illegal uninit src register"
            );

            Some(src_state)
        } else {
            guard!(
                self,
                insn.src_reg() == 0,
                "illegal reserved src register field"
            );

            None
        };

        let size = if insn.class() == BPF_ALU32 { 32 } else { 64 };

        match (op, src) {
            (BPF_MOV, _) => return self.check_alu_mov(insn),

            (BPF_MOD | BPF_DIV, None) if insn.imm() == 0 => guard!(self, "division by IMM=0"),
            (BPF_LSH | BPF_RSH | BPF_ARSH, None) if insn.imm() < 0 || insn.imm() >= size => {
                guard!(self, "shift out of bounds");
            }

            _ => {}
        }

        guard!(
            self,
            insn.offset() == 0 || matches!(op, BPF_MOD | BPF_DIV if insn.offset() == 1),
            "illegal reserved offset field"
        );

        let dst = self.dst_reg(insn);
        guard!(
            self,
            dst != RegisterState::Uninit,
            "illegal uninit dst register"
        );

        if insn.class() != BPF_ALU64 {
            guard!(
                self,
                !dst.is_pointer() && src.is_none_or(|src| !src.is_pointer()),
                "ALU32 cannot perform pointer arithmetic"
            );

            // TODO: track scalar operations like add, sub, mul, etc
            // 32bit ALU operations produce scalars

            return self.mark_unknown(insn.dst_reg());
        }

        let (ptr, scalar) = match (dst, src) {
            (RegisterState::Scalar(_), None | Some(RegisterState::Scalar(_))) => {
                // 64bit scalar operation tracking
                return self.check_alu_scalars(insn);
            }

            (RegisterState::Scalar(dst), Some(src)) if src.is_pointer() => {
                guard!(self, op == BPF_ADD, "scalar + pointer only allowed for ADD");
                (src, dst)
            }

            (dst, None) if dst.is_pointer() => {
                (dst, Scalar::U32(ScalarRange::exact(insn.imm() as u32)))
            }
            (dst, Some(RegisterState::Scalar(src))) if dst.is_pointer() => (dst, src),

            _ => guard!(self, "illegal registers"),
        };

        if matches!(
            ptr,
            RegisterState::PtrToPacket { .. } | RegisterState::PtrToPacketMeta { .. }
        ) {
            // Packet pointer ALU operations diverge from the rules for unknown scalars
            return self.check_alu_pkt_ptr(insn, ptr, scalar, op);
        }

        let (scalar_min, scalar_max, scalar_stride) = match scalar {
            Scalar::U32(r) => (r.min as i32, r.max as i32, r.stride as i32),
            // TODO check if upper bits are set, disallow if so.
            Scalar::U64(r) => (r.min as u32 as i32, r.max as u32 as i32, r.stride as i32),
            _ => guard!(self, "pointer arithmetic with unknown scalar"),
        };

        match op {
            BPF_ADD => {
                self.set_reg(
                    insn.dst_reg(),
                    match ptr {
                        RegisterState::PtrToCtx {
                            btf_id,
                            offset,
                            size,
                        } => {
                            let offset = offset
                                .checked_add_signed_range(scalar_min, scalar_max, scalar_stride)
                                .ok_or(self.err("new ptr overflows ctx"))?;
                            guard!(self, size > offset.max, "new ptr overflows ctx");
                            RegisterState::PtrToCtx {
                                btf_id,
                                offset,
                                size,
                            }
                        }
                        RegisterState::PtrToStack { offset } => {
                            // `checked_add_signed_range` already fails on
                            // underflow below the stack floor (STACK_RANGE.start
                            // is 0), so no further lower-bound check is needed.
                            let offset = offset
                                .checked_add_signed_range(scalar_min, scalar_max, scalar_stride)
                                .ok_or(self.err("new ptr overflows stack"))?;
                            RegisterState::PtrToStack { offset }
                        }
                        RegisterState::PtrToMapValue { map_fd, offset } => {
                            let offset = offset
                                .checked_add_signed_range(scalar_min, scalar_max, scalar_stride)
                                .ok_or(self.err("new ptr to map value overflows map"))?;
                            RegisterState::PtrToMapValue { map_fd, offset }
                        }
                        _ => guard!(self, "invalid pointer arithmetic operation"),
                    },
                );
            }
            BPF_SUB => {
                let (sub_min, sub_max) = (
                    scalar_max
                        .checked_neg()
                        .ok_or(self.err("ptr sub overflows"))?,
                    scalar_min
                        .checked_neg()
                        .ok_or(self.err("ptr sub overflows"))?,
                );
                self.set_reg(
                    insn.dst_reg(),
                    match ptr {
                        RegisterState::PtrToCtx {
                            btf_id,
                            offset,
                            size,
                        } => {
                            let offset = offset
                                .checked_add_signed_range(sub_min, sub_max, scalar_stride)
                                .ok_or(self.err("new ptr overflows ctx"))?;
                            guard!(self, size > offset.max, "new ptr overflows ctx");
                            RegisterState::PtrToCtx {
                                btf_id,
                                offset,
                                size,
                            }
                        }
                        RegisterState::PtrToMapValue { map_fd, offset } => {
                            let offset = offset
                                .checked_add_signed_range(sub_min, sub_max, scalar_stride)
                                .ok_or(self.err("new ptr to map value overflows map"))?;
                            RegisterState::PtrToMapValue { map_fd, offset }
                        }
                        _ => guard!(self, "invalid pointer arithmetic operation"),
                    },
                );
            }

            _ => guard!(self, "illegal pointer arithmetic operation"),
        }

        Ok(())
    }

    /// Pointer arithmetic on packet pointers (data and meta).
    ///
    /// A packet pointer is a pair `(id, offset)`. The id pins the pointer to a
    /// specific runtime value: any two pointers sharing an id are equal at
    /// runtime, so a bounds check on one refines all of them. The offset tracks
    /// the verifier-known displacement from that anchor.
    ///
    /// Adding or subtracting a single-valued scalar shifts the offset and keeps
    /// the id, the runtime anchor is unchanged. Anything else (an unknown
    /// scalar, or a non-trivial range) generates a fresh id with offset zero,
    /// since the new pointer's runtime value is no longer the same as any
    /// previously checked one.
    fn check_alu_pkt_ptr(
        &mut self,
        insn: &Insn,
        ptr: RegisterState,
        scalar: Scalar,
        op: u8,
    ) -> Result<(), VerifierError> {
        guard!(
            self,
            matches!(op, BPF_ADD | BPF_SUB),
            "illegal pointer arithmetic operation"
        );

        let (id, offset) = match ptr {
            RegisterState::PtrToPacket { id, offset }
            | RegisterState::PtrToPacketMeta { id, offset } => (id, offset),
            _ => return Err(self.err("caller filtered to packet pointers")),
        };

        let single = match scalar {
            Scalar::U32(r) => r.single_val().map(|v| v as i32 as i64),
            Scalar::U64(r) => r.single_val().map(|v| v as i64),
            Scalar::Unknown => None,
        };

        let (new_id, new_offset) = match single {
            Some(v) => {
                let delta = if op == BPF_SUB {
                    v.checked_neg().ok_or(self.err("ptr arith overflows"))?
                } else {
                    v
                };
                let delta =
                    i32::try_from(delta).map_err(|_| self.err("ptr arith does not fit in i32"))?;
                let new_offset = offset
                    .checked_add_signed_range(delta, delta, 1)
                    .ok_or(self.err("new ptr overflows packet offset"))?;
                (id, new_offset)
            }
            None => (self.verifier().fresh_pkt_id(), ScalarRange::exact(0)),
        };

        let new_ptr = match ptr {
            RegisterState::PtrToPacket { .. } => RegisterState::PtrToPacket {
                id: new_id,
                offset: new_offset,
            },
            RegisterState::PtrToPacketMeta { .. } => RegisterState::PtrToPacketMeta {
                id: new_id,
                offset: new_offset,
            },
            _ => return Err(self.err("caller filtered to packet pointers")),
        };

        self.set_reg(insn.dst_reg(), new_ptr);
        Ok(())
    }

    /// Checks ALU operations for ADD, SUB, LSH, RSH, ARSH and adjusts the
    /// registers.
    ///
    /// Known scalars are stored as ranges with a min, max, and stride fields.
    /// This function performs adjustments on both ends, min and max, and
    /// adjusts the stride when needed.
    ///
    /// For now, we only adjust if SRC represents a single value, either the
    /// immediate or a scalar with min==max.
    ///
    /// * ADD/SUB keeps the stride if the absolute SRC value is a multiple of
    ///   it, otherwise resets to 1.
    /// * LSH shifts the stride to the left. On overflow, it resets to 1.
    /// * RSH/ARSH shifts the stride to the right. On underflow, it resets to 1.
    ///
    /// If SRC is a range or if an operation fails for any reason, DST is marked
    /// as unknown.
    ///
    /// Ref: <https://github.com/torvalds/linux/blob/ea1013c1539270e372fc99854bc6e4d94eaeff66/kernel/bpf/verifier.c#L15505>
    fn check_alu_scalars(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        let src_val = match self.src_reg(insn) {
            Ok(RegisterState::Scalar(Scalar::U32(r))) => match r.single_val() {
                Some(v) => v as i32 as i64,
                None => return self.mark_unknown(insn.dst_reg()),
            },
            Err(_) => insn.imm() as i64,
            _ => return self.mark_unknown(insn.dst_reg()),
        };

        // TODO: track scalar operations like mul, neg, and, or, xor
        let alu_fn = match insn.opcode() & ALU_OP_MASK {
            BPF_ADD => Scalar::alu_add,
            BPF_SUB => Scalar::alu_sub,
            BPF_LSH => Scalar::alu_lsh,
            BPF_RSH => Scalar::alu_rsh,
            BPF_ARSH => Scalar::alu_arsh,
            _ => return self.mark_unknown(insn.dst_reg()),
        };

        if let RegisterState::Scalar(s) = self.dst_reg(insn) {
            if let Some(result) = alu_fn(s, src_val) {
                self.set_reg(insn.dst_reg(), RegisterState::Scalar(result));
                Ok(())
            } else {
                self.mark_unknown(insn.dst_reg())
            }
        } else {
            self.mark_unknown(insn.dst_reg())
        }
    }

    /// Checks an ALU MOV instruction and updates registers.
    ///
    /// * Moving a pointer simply copies the pointer to DST, only ALU64 can
    ///   perform pointer moves.
    /// * When moving known scalars, the value is trimmed according to the ALU
    ///   class. If the insn is a MOVSX (sign-extension), the offset is checked
    ///   and the known value is sign-extended accordingly.
    /// * Moving unknown scalars simply copy the unknown status.
    /// * Moving IMMs result in known scalars with size according to the class.
    fn check_alu_mov(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        let state = match self.src_reg(insn) {
            Ok(src) if src.is_pointer() => {
                guard!(self, insn.class() == BPF_ALU64, "partial copy of pointer");
                guard!(self, insn.offset() == 0, "sign extension on pointer");

                src
            }
            Ok(RegisterState::Scalar(scalar)) if scalar.is_known() => {
                let scalar = match (insn.class(), scalar) {
                    (BPF_ALU32, Scalar::U64(r)) => Scalar::U32(ScalarRange::exact(r.min as u32)),
                    (BPF_ALU64, Scalar::U32(r)) => Scalar::U64(ScalarRange::exact(r.min as u64)),
                    _ => scalar,
                };

                let scalar = match (insn.offset() as u32, scalar) {
                    (0, _) => scalar,
                    (offset @ (8 | 16), Scalar::U32(r)) => {
                        let shift = u32::BITS - offset;
                        Scalar::U32(ScalarRange::exact(
                            ((r.min as i32) << shift >> shift) as u32,
                        ))
                    }
                    (offset @ (8 | 16 | 32), Scalar::U64(r)) => {
                        let shift = u64::BITS - offset;
                        Scalar::U64(ScalarRange::exact(
                            ((r.min as i64) << shift >> shift) as u64,
                        ))
                    }
                    _ => guard!(self, "mov with invalid offset"),
                };

                RegisterState::Scalar(scalar)
            }
            Ok(src) if src.is_scalar() => src,
            Ok(_) => guard!(self, "mov with invalid src register"),
            Err(_) => {
                if insn.class() == BPF_ALU32 {
                    RegisterState::Scalar(Scalar::U32(ScalarRange::exact(insn.imm() as u32)))
                } else {
                    RegisterState::Scalar(Scalar::U64(ScalarRange::exact(insn.imm() as u64)))
                }
            }
        };

        self.set_reg(insn.dst_reg(), state);

        Ok(())
    }

    fn check_ldx(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        match insn.opcode() & LOAD_MODE_MASK {
            MODE_MEM => {
                let load_size = match insn.opcode() & LOAD_SIZE_MASK {
                    SIZE_DW => 8,
                    SIZE_W => 4,
                    SIZE_H => 2,
                    SIZE_B => 1,
                    _ => return Err(self.err("invalid load size")),
                };

                let src = self.src_reg(insn)?;

                self.hook_advisory(src, insn.offset() as i32, load_size);

                match src {
                    RegisterState::PtrToCtx {
                        btf_id,
                        offset,
                        size,
                    } => {
                        let read_min = offset
                            .min
                            .checked_add_signed(insn.offset() as i32)
                            .ok_or(self.err("tried reading out of ctx bounds"))?;
                        let read_max = offset
                            .max
                            .checked_add_signed(insn.offset() as i32)
                            .ok_or(self.err("tried reading out of ctx bounds"))?;
                        guard!(
                            self,
                            read_max + load_size <= size,
                            "tried reading out of ctx bounds"
                        );

                        // If the host supplied a rule for (container, offset)
                        // and the load size matches the field's member size,
                        // materialize the specialized pointer kind.
                        if offset.single_val().is_some()
                            && let Some(rule) = self
                                .verifier()
                                .config
                                .field_rules
                                .get(&(btf_id, read_min))
                                .copied()
                                .filter(|r| r.access.allows_read())
                            && let Some(load_reg) = rule.load_reg
                        {
                            let btf = &self.verifier().prog.btf;
                            let member_size = btf
                                .get_type_at_offset(btf_id, read_min)
                                .map(|f| f.kind.size(btf));
                            if member_size == Some(load_size) {
                                let dst_state = match load_reg {
                                    FieldRegKind::PacketData => RegisterState::PtrToPacket {
                                        id: 0,
                                        offset: ScalarRange::exact(0),
                                    },
                                    FieldRegKind::PacketDataMeta => {
                                        RegisterState::PtrToPacketMeta {
                                            id: 0,
                                            offset: ScalarRange::exact(0),
                                        }
                                    }
                                    FieldRegKind::PacketDataEnd => RegisterState::PtrToPacketEnd,
                                };
                                self.set_reg(insn.dst_reg(), dst_state);
                                return Ok(());
                            }
                        }
                    }
                    RegisterState::PtrToStack { offset } => {
                        guard!(
                            self,
                            offset.single_val().is_some(),
                            "stack access requires exact pointer offset"
                        );
                        let dst = offset
                            .min
                            .checked_add_signed(insn.offset() as i32)
                            .ok_or(self.err("tried reading out of stack bounds"))?;
                        let slot = *self
                            .frame()
                            .stack_objects
                            .get(&dst)
                            .ok_or(self.err("tried reading out of uninit stack slot"))?;
                        guard!(
                            self,
                            slot.size == load_size,
                            "load size does not match stack slot size"
                        );
                        self.set_reg(insn.dst_reg(), slot.state);
                        return Ok(());
                    }
                    RegisterState::PtrToMap { map_fd: _ } => {
                        return Err(self.err("load through PtrToMap is not supported"));
                    }
                    RegisterState::PtrToMapValue { map_fd, offset } => {
                        let bpf_map = self.verifier().vm.get_map(map_fd);
                        let map_val = bpf_map
                            .spec
                            .value
                            .ok_or(self.err("map has no associated value BTF type"))?;
                        let read_min = offset
                            .min
                            .checked_add_signed(insn.offset() as i32)
                            .ok_or(self.err("load overflows map value"))?;
                        let read_max = offset
                            .max
                            .checked_add_signed(insn.offset() as i32)
                            .ok_or(self.err("load overflows map value"))?;
                        guard!(
                            self,
                            bpf_map.btf.is_access_valid(map_val, read_min, load_size),
                            "tried reading from ptr to map value with invalid offset"
                        );
                        guard!(
                            self,
                            bpf_map.btf.is_access_valid(map_val, read_max, load_size),
                            "tried reading from ptr to map value with invalid offset"
                        );
                    }
                    _ => guard!(self, "invalid memory location"),
                }

                self.mark_unknown(insn.dst_reg())
            }
            MODE_MEMSX => guard!(self, "sign-extension loads are not supported yet"),
            _ => guard!(self, "unsupported load mode"),
        }
    }

    /// Checks for LD IMM64 instructions. For now, only IMM and MAP FD loads
    /// are supported. Signals for the verifier to skip next instruction.
    fn check_non_conventional_ld(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        guard!(
            self,
            insn.opcode() & LOAD_MODE_MASK == MODE_IMM,
            "ld class is reserved for ld_imm64"
        );
        guard!(
            self,
            insn.opcode() & LOAD_SIZE_MASK == SIZE_DW,
            "ld class is reserved for ld_imm64"
        );

        let next = self
            .verifier()
            .prog
            .insns
            .get(self.next_pc())
            .ok_or_else(|| self.err("ld_imm64 expects one more word"))?;

        match insn.src_reg() {
            0 => {
                let imm64 =
                    (insn.imm() as u64 & 0xFFFF_FFFF) | ((next.imm() as u64 & 0xFFFF_FFFF) << 32);
                self.set_reg(
                    insn.dst_reg(),
                    RegisterState::Scalar(Scalar::U64(ScalarRange::exact(imm64))),
                );
            }
            BPF_PSEUDO_MAP_FD => {
                guard!(
                    self,
                    insn.imm() >> u16::BITS == 0,
                    "map fd is larger than allowed"
                );
                let map_fd = insn.imm() as u16;
                guard!(
                    self,
                    self.verifier().vm.has_map(map_fd),
                    "referenced non-existing map FD"
                );
                self.set_reg(insn.dst_reg(), RegisterState::PtrToMap { map_fd })
            }
            BPF_PSEUDO_MAP_VALUE => {
                let offset = next.imm() as u32;
                guard!(
                    self,
                    insn.imm() >> u16::BITS == 0,
                    "map fd is larger than allowed"
                );
                let map_fd = insn.imm() as u16;
                guard!(
                    self,
                    self.verifier().vm.has_map(map_fd),
                    "referenced non-existing map FD"
                );
                self.set_reg(
                    insn.dst_reg(),
                    RegisterState::PtrToMapValue {
                        map_fd,
                        offset: ScalarRange::exact(offset),
                    },
                );
            }
            _ => guard!(self, "unsupported pseudo function"),
        }

        self.skip_next();
        Ok(())
    }

    fn check_st(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        let mode = insn.opcode() & LOAD_MODE_MASK;
        guard!(
            self,
            mode == MODE_MEM || mode == MODE_ATOMIC,
            "unsupported store mode"
        );
        let dst_reg = self.dst_reg(insn);
        guard!(self, dst_reg.is_pointer(), "store to non-pointer register");

        let store_size = match insn.opcode() & LOAD_SIZE_MASK {
            SIZE_DW => 8,
            SIZE_W => 4,
            SIZE_H => 2,
            SIZE_B => 1,
            _ => return Err(self.err("invalid store size")),
        };

        match dst_reg {
            RegisterState::Uninit => guard!(self, "store to uninit register"),
            RegisterState::PtrToStack { offset } => {
                guard!(
                    self,
                    offset.single_val().is_some(),
                    "stack access requires exact pointer offset"
                );
                let dst = offset
                    .min
                    .checked_add_signed(insn.offset() as i32)
                    .ok_or(self.err("store overflows stack"))?;
                guard!(
                    self,
                    dst.is_multiple_of(store_size),
                    "unaligned stack write"
                );
                guard!(
                    self,
                    STACK_RANGE.contains(&dst) && STACK_RANGE.contains(&(dst + store_size - 1)),
                    "store outside stack bounds"
                );

                let write_end = dst + store_size;

                let src_state = self
                    .src_reg(insn)
                    .unwrap_or(scalar_reg(ScalarRange::exact(insn.imm() as u64)));

                let overlapping: Vec<u32> = self
                    .frame()
                    .stack_objects
                    .range(dst.saturating_sub(7)..write_end)
                    .filter_map(|(&addr, slot)| {
                        slot.partially_overwritten_by(addr, dst, store_size)
                            .then_some(addr)
                    })
                    .collect();

                if !overlapping.is_empty() {
                    if src_state.is_pointer() {
                        guard!(self, "pointer store partially overlaps existing stack slot");
                    }

                    for &addr in &overlapping {
                        let existing =
                            *self.frame().stack_objects.get(&addr).ok_or_else(|| {
                                self.err("overlapping stack addr is out of bounds")
                            })?;
                        guard!(
                            self,
                            !existing.state.is_pointer(),
                            "scalar store clobbers pointer on stack"
                        );
                        self.stack_mut().remove(&addr);
                    }
                }

                let pc = self.this_pc();
                self.stack_mut().insert(
                    dst,
                    StackSlot {
                        size: store_size,
                        state: src_state,
                        pc,
                    },
                );
            }
            RegisterState::PtrToMapValue { map_fd, offset } => {
                let bpf_map = self.verifier().vm.get_map(map_fd);
                let map_val = bpf_map
                    .spec
                    .value
                    .ok_or(self.err("map has no associated value BTF type"))?;
                let write_min = offset
                    .min
                    .checked_add_signed(insn.offset() as i32)
                    .ok_or(self.err("store overflows map value"))?;
                let write_max = offset
                    .max
                    .checked_add_signed(insn.offset() as i32)
                    .ok_or(self.err("store overflows map value"))?;
                guard!(
                    self,
                    bpf_map.btf.is_access_valid(map_val, write_min, store_size),
                    "store at invalid map value offset"
                );
                guard!(
                    self,
                    bpf_map.btf.is_access_valid(map_val, write_max, store_size),
                    "store at invalid map value offset"
                );
            }
            RegisterState::PtrToCtx {
                btf_id,
                offset,
                size,
            } => {
                guard!(
                    self,
                    offset.single_val().is_some(),
                    "ctx store requires exact pointer offset"
                );
                let access_off = offset
                    .min
                    .checked_add_signed(insn.offset() as i32)
                    .ok_or(self.err("store overflows ctx"))?;
                guard!(self, access_off + store_size <= size, "store overflows ctx");

                let rule = self
                    .verifier()
                    .config
                    .field_rules
                    .get(&(btf_id, access_off))
                    .copied()
                    .ok_or(self.err("ctx store to field without a verifier rule"))?;
                guard!(self, rule.access.allows_write(), "ctx store not permitted");

                let btf = &self.verifier().prog.btf;
                let member_size = btf
                    .get_type_at_offset(btf_id, access_off)
                    .map(|f| f.kind.size(btf))
                    .ok_or(self.err("ctx store target has no resolvable BTF size"))?;
                guard!(
                    self,
                    member_size == store_size,
                    "ctx store size does not match member size"
                );
            }
            _ => guard!(self, "unsupported store target"),
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

        let offset = if insn.opcode() == BPF_JMP32 | BPF_K | BPF_JA {
            insn.imm()
        } else {
            insn.offset() as i32
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
            // TODO: this is an unconditional jump we shouldnt run it in a separate state
            // just override the current PC
            return self.run_decision(insn, BranchResult::skip_fallthrough());
        }

        let signed = matches!(jmp_op, BPF_JSGT | BPF_JSGE | BPF_JSLT | BPF_JSLE);

        let known_val = |val: u64| {
            let val = if insn.class() == BPF_JMP32 {
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

        let scalar_to_expr = |s: Scalar, class: u8| -> ExprVal {
            let jmp32 = class == BPF_JMP32;
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

        let lhs = match self.dst_reg(insn) {
            RegisterState::Scalar(s) => scalar_to_expr(s, insn.class()),
            RegisterState::PtrToMapValueOrNull { map_fd } => ExprVal::PtrToMapValueOrNull(map_fd),

            // There's no refinement to be done
            RegisterState::PtrToMapValue { .. } => {
                return self.run_decision(insn, BranchResult::both());
            }

            _ => guard!(self, "unsupported dst register for comparison"),
        };

        let rhs = match self.src_reg(insn) {
            Err(_) => known_val(insn.imm() as u32 as u64),
            Ok(RegisterState::Scalar(s)) => scalar_to_expr(s, insn.class()),
            Ok(RegisterState::PtrToMapValueOrNull { map_fd }) => {
                ExprVal::PtrToMapValueOrNull(map_fd)
            }

            // There's no refinement to be done
            Ok(RegisterState::PtrToMapValue { .. }) => {
                return self.run_decision(insn, BranchResult::both());
            }

            Ok(_) => guard!(self, "unsupported src register for comparison"),
        };

        let branch = decide_branch(jmp_op, lhs, rhs, insn.class() == BPF_JMP32)
            .map_err(|msg| self.err(msg))?;

        self.run_decision(insn, branch)
    }

    fn check_jmp_call(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        guard!(
            self,
            insn.opcode() & 0b1111 == BPF_JMP | BPF_K,
            "call must be BPF_JMP | BPF_K"
        );

        match insn.src_reg() {
            BPF_PSEUDO_CALL => self.check_pseudo_call(insn)?,
            BPF_HELPER_CALL => {
                let helper = helpers::lookup(insn.imm())
                    .ok_or_else(|| self.err("BPF_HELPER_CALL refers to invalid helper ID"))?;
                let args = self.arg_regs();
                helper
                    .params(self.verifier().vm, args, *insn)
                    .map_err(|_| self.err("helper parameter validation failed"))?;

                if insn.imm() == helpers::PerfEventOutput::ID {
                    self.record_perf_event_layout();
                }

                let retval = helper
                    .retval(self.verifier().vm, args, *insn)
                    .map_err(|msg| self.err(msg))?;
                self.set_reg(0, retval);
            }
            _ => {}
        }

        Ok(())
    }

    fn check_pseudo_call(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        let target_pc = (self.next_pc() as isize + insn.imm() as isize) as usize;
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
        self.set_reg(0, sub_out.r0);

        for i in 1..=5 {
            self.set_reg(i, RegisterState::Uninit);
        }

        Ok(())
    }
}
