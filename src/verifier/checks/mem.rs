use super::*;

impl<'v, 'a> Walk<'v, 'a> {
    pub(super) fn check_ldx(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        match insn.mem_mode() {
            Some(MemMode::Mem) => {
                let load_size = insn.mem_size().bytes();

                let src = self.src_state(insn)?;

                self.hook_advisory(src, insn.offset() as i32, load_size);

                let state = match src {
                    RegisterState::PtrToCtx {
                        btf_id,
                        offset,
                        size,
                    } => self.check_ldx_ctx(insn, load_size, btf_id, offset, size),
                    RegisterState::PtrToStack { offset } => {
                        self.check_ldx_stack(insn, load_size, offset)
                    }
                    RegisterState::PtrToMapValue { map_fd, offset } => {
                        self.check_ldx_map_value(insn, load_size, map_fd, offset)
                    }
                    RegisterState::PtrToPacket {
                        offset,
                        known_ceiling: Some(known_ceiling),
                        access,
                        ..
                    } => self.check_ldx_pkt(insn, offset, known_ceiling, access),

                    RegisterState::PtrToMap { map_fd: _ } => {
                        return Err(self.err("load through PtrToMap is not supported"));
                    }
                    _ => guard!(self, "invalid memory location"),
                }?;

                if let Some(state) = state {
                    self.set_reg(insn.dst_reg(), state);
                } else {
                    self.mark_unknown(insn.dst_reg())?;
                }

                Ok(())
            }
            Some(MemMode::Memsx) => {
                let load_size = insn.mem_size().bytes();
                guard!(
                    self,
                    matches!(load_size, 1 | 2 | 4),
                    "sign extension load only supports B, H and W sizes"
                );
                // TODO: improve this in the future, if need be
                self.mark_unknown(insn.dst_reg())
            }
            _ => guard!(self, "unsupported load mode"),
        }
    }

    fn check_ldx_ctx(
        &self,
        insn: &Insn,
        load_size: u32,
        btf_id: BtfTypeId,
        offset: ScalarRange<u32>,
        size: u32,
    ) -> Result<Option<RegisterState>, VerifierError> {
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

            guard!(
                self,
                member_size == Some(load_size),
                "reading from ptr to ctx with field size mismatch"
            );

            let dst_state = match load_reg {
                FieldRegKind::PacketData => RegisterState::PtrToPacket {
                    id: 0,
                    offset: ScalarRange::exact(0),
                    known_ceiling: None,
                    access: rule.access,
                },
                FieldRegKind::PacketDataMeta => RegisterState::PtrToPacketMeta {
                    id: 0,
                    offset: ScalarRange::exact(0),
                    known_ceiling: None,
                    access: rule.access,
                },
                FieldRegKind::PacketDataEnd => RegisterState::PtrToPacketEnd,
            };

            Ok(Some(dst_state))
        } else {
            Ok(None)
        }
    }

    fn check_ldx_stack(
        &self,
        insn: &Insn,
        load_size: u32,
        offset: ScalarRange<u32>,
    ) -> Result<Option<RegisterState>, VerifierError> {
        guard!(
            self,
            offset.single_val().is_some(),
            "stack access requires exact pointer offset"
        );

        let dst = offset
            .min
            .checked_add_signed(insn.offset() as i32)
            .ok_or(self.err("tried reading out of stack bounds"))?;
        let read = dst..dst.saturating_add(load_size);

        let Some((_, &slot, overlap)) = self.frame().slots_overlapping(read).next() else {
            guard!(self, "tried reading out of uninit stack slot")
        };

        let state = match overlap {
            StackSlotOverlap::Exact => slot.state,
            StackSlotOverlap::Partial(Bounds::Within) => {
                guard!(
                    self,
                    slot.state.is_scalar(),
                    "partial stack read would leak a pointer"
                );
                RegisterState::Scalar(Scalar::Unknown)
            }
            _ => guard!(self, "stack read crosses a slot boundary"),
        };

        Ok(Some(state))
    }

    fn check_ldx_map_value(
        &self,
        insn: &Insn,
        load_size: u32,
        map_fd: u16,
        offset: ScalarRange<u32>,
    ) -> Result<Option<RegisterState>, VerifierError> {
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
        Ok(None)
    }

    fn check_ldx_pkt(
        &self,
        insn: &Insn,
        offset: ScalarRange<u32>,
        known_ceiling: ScalarRange<u32>,
        access: FieldAccess,
    ) -> Result<Option<RegisterState>, VerifierError> {
        guard!(
            self,
            matches!(access, FieldAccess::Read | FieldAccess::ReadWrite),
            "tried reading from a write-only pointer"
        );
        let read_max = offset
            .max
            .checked_add_signed(insn.offset() as i32)
            .ok_or(self.err("load overflows packet space"))?;
        guard!(
            self,
            known_ceiling.max >= read_max,
            "tried reading ptr to packet with invalid offset"
        );
        Ok(None)
    }

    /// Checks for LD IMM64 instructions. For now, only IMM and MAP FD loads
    /// are supported. Signals for the verifier to skip next instruction.
    pub(super) fn check_non_conventional_ld(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        guard!(
            self,
            insn.mem_mode() == Some(MemMode::Imm) && insn.mem_size() == MemSize::Dword,
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
        guard!(
            self,
            matches!(insn.mem_mode(), Some(MemMode::Mem | MemMode::Atomic)),
            "unsupported store mode"
        );
        let dst_reg = self.dst_state(insn);
        guard!(self, dst_reg.is_pointer(), "store to non-pointer register");

        let store_size = insn.mem_size().bytes();

        match dst_reg {
            RegisterState::Uninit => guard!(self, "store to uninit register"),
            RegisterState::PtrToStack { offset } => self.check_st_stack(insn, store_size, offset),
            RegisterState::PtrToMapValue { map_fd, offset } => {
                self.check_st_map_value(insn, store_size, map_fd, offset)
            }
            RegisterState::PtrToCtx {
                btf_id,
                offset,
                size,
            } => self.check_st_ctx(insn, store_size, btf_id, offset, size),
            RegisterState::PtrToPacket {
                offset,
                known_ceiling: Some(known_ceiling),
                access,
                ..
            } => self.check_st_pkt(insn, offset, known_ceiling, access),

            _ => guard!(self, "unsupported store target"),
        }
    }

    fn check_st_ctx(
        &self,
        insn: &Insn,
        store_size: u32,
        btf_id: BtfTypeId,
        offset: ScalarRange<u32>,
        size: u32,
    ) -> Result<(), VerifierError> {
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
        Ok(())
    }

    fn check_st_stack(
        &mut self,
        insn: &Insn,
        store_size: u32,
        offset: ScalarRange<u32>,
    ) -> Result<(), VerifierError> {
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
            dst.saturating_add(store_size).saturating_sub(1) < STACK_SIZE as u32,
            "store outside stack bounds"
        );

        let write_end = dst + store_size;

        let src_state = match insn.source() {
            Some(Src::Reg(_)) => self.src_state(insn)?,
            _ => RegisterState::Scalar(Scalar::U64(ScalarRange::exact(insn.imm() as u64))),
        };

        let overlapping: Vec<u32> = self
            .frame()
            .slots_overlapping(dst..write_end)
            .filter(|(_, _, overlap)| matches!(overlap, StackSlotOverlap::Partial(_)))
            .map(|(addr, _, _)| addr)
            .collect();

        if !overlapping.is_empty() {
            if src_state.is_pointer() {
                guard!(self, "pointer store partially overlaps existing stack slot");
            }

            for &addr in &overlapping {
                let existing = *self
                    .frame()
                    .stack_objects
                    .get(&addr)
                    .ok_or_else(|| self.err("overlapping stack addr is out of bounds"))?;
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
                size: insn.mem_size(),
                state: src_state,
                pc,
            },
        );

        Ok(())
    }

    fn check_st_map_value(
        &self,
        insn: &Insn,
        store_size: u32,
        map_fd: u16,
        offset: ScalarRange<u32>,
    ) -> Result<(), VerifierError> {
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
        Ok(())
    }

    fn check_st_pkt(
        &self,
        insn: &Insn,
        offset: ScalarRange<u32>,
        known_ceiling: ScalarRange<u32>,
        access: FieldAccess,
    ) -> Result<(), VerifierError> {
        guard!(
            self,
            matches!(access, FieldAccess::Write | FieldAccess::ReadWrite),
            "tried reading from a read-only pointer"
        );
        let write_max = offset
            .max
            .checked_add_signed(insn.offset() as i32)
            .ok_or(self.err("store overflows packet space"))?;
        guard!(
            self,
            known_ceiling.max >= write_max,
            "tried writing ptr to packet with invalid offset"
        );
        Ok(())
    }
}
