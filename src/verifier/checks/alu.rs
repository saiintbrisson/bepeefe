use super::*;

impl<'v, 'a> Walk<'v, 'a> {
    pub(super) fn check_alu(&mut self, insn: &Insn) -> Result<(), VerifierError> {
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
}
