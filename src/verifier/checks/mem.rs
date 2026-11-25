use super::*;

impl<'v, 'a> Walk<'v, 'a> {
    pub(super) fn check_ldx(&mut self, insn: &Insn) -> Result<(), VerifierError> {
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
    pub(super) fn check_non_conventional_ld(&mut self, insn: &Insn) -> Result<(), VerifierError> {
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

    pub(super) fn check_st(&mut self, insn: &Insn) -> Result<(), VerifierError> {
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
}
