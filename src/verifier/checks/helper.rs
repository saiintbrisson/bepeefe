use super::*;
use crate::vm::helpers::{Access, ArgSpec};

fn is_null(reg: RegisterState) -> bool {
    match reg {
        RegisterState::Scalar(Scalar::U32(r)) => r.single_val() == Some(0),
        RegisterState::Scalar(Scalar::U64(r)) => r.single_val() == Some(0),
        _ => false,
    }
}

impl<'v, 'a> Walk<'v, 'a> {
    pub(super) fn check_helper_args(&mut self, sig: &[ArgSpec]) -> Result<(), VerifierError> {
        let mut reg = 1u8;
        let mut map_fd = None;

        for &spec in sig {
            guard!(
                self,
                reg + spec.regs() <= 6,
                "helper signature uses more than five registers"
            );

            match spec {
                ArgSpec::DontCare => {}
                ArgSpec::Anything => guard!(
                    self,
                    !matches!(self.arg_regs().get(reg), RegisterState::Uninit),
                    "helper argument is uninitialized"
                ),
                ArgSpec::Scalar => guard!(
                    self,
                    self.arg_regs().get(reg).is_scalar(),
                    "helper argument must be a scalar"
                ),
                ArgSpec::Ctx => guard!(
                    self,
                    matches!(self.arg_regs().get(reg), RegisterState::PtrToCtx { .. }),
                    "helper argument must point to ctx"
                ),
                ArgSpec::Map => {
                    let RegisterState::PtrToMap { map_fd: fd } = self.arg_regs().get(reg) else {
                        guard!(self, "helper argument must point to a map")
                    };
                    map_fd = Some(fd);
                }
                ArgSpec::MapKey | ArgSpec::MapValue | ArgSpec::UninitMapValue => {
                    let fd = map_fd
                        .ok_or_else(|| self.err("helper map argument has no preceding map"))?;
                    let (key_size, value_size) = self.map_sizes(fd)?;
                    let (len, access) = match spec {
                        ArgSpec::MapKey => (key_size, Access::Read),
                        ArgSpec::MapValue => (value_size, Access::Read),
                        _ => (value_size, Access::Write),
                    };
                    let ptr = self.arg_regs().get(reg);
                    self.check_helper_mem(ptr, len, access)?;
                }
                ArgSpec::Mem(access) | ArgSpec::MemOrNull(access) => {
                    let ptr = self.arg_regs().get(reg);
                    let len = match self.arg_regs().get(reg + 1) {
                        RegisterState::Scalar(Scalar::U32(r)) => Some(r.max),
                        RegisterState::Scalar(Scalar::U64(r)) => u32::try_from(r.max).ok(),
                        _ => None,
                    };
                    let len = len
                        .ok_or_else(|| self.err("helper size argument must be a bounded scalar"))?;
                    if matches!(spec, ArgSpec::MemOrNull(_)) && is_null(ptr) {
                        guard!(self, len == 0, "NULL helper memory must have zero size");
                    } else {
                        self.check_helper_mem(ptr, len, access)?;
                    }
                }
            }

            reg += spec.regs();
        }

        Ok(())
    }

    fn map_sizes(&self, map_fd: u16) -> Result<(u32, u32), VerifierError> {
        let sizes = self.verifier().vm.get_map(map_fd).repr.sizes();
        sizes
            .and_then(|(k, v)| Some((u32::try_from(k).ok()?, u32::try_from(v).ok()?)))
            .ok_or_else(|| self.err("helper does not support this map type"))
    }

    /// Checks that `len` bytes from `ptr` can be accessed by a helper.
    fn check_helper_mem(
        &mut self,
        ptr: RegisterState,
        len: u32,
        access: Access,
    ) -> Result<(), VerifierError> {
        match ptr {
            RegisterState::PtrToStack { offset } => {
                let Some(start) = offset.single_val() else {
                    guard!(self, "stack access requires exact pointer offset")
                };
                let end = start
                    .checked_add(len)
                    .filter(|&end| end <= STACK_SIZE as u32)
                    .ok_or_else(|| self.err("helper memory runs past the stack"))?;
                match access {
                    Access::Read => self.check_stack_range_read(start..end),
                    Access::Write => self.mark_stack_range_written(start..end),
                }
            }
            RegisterState::PtrToMapValue { map_fd, offset } => {
                let (_, value_size) = self.map_sizes(map_fd)?;
                guard!(
                    self,
                    offset
                        .max
                        .checked_add(len)
                        .is_some_and(|end| end <= value_size),
                    "helper memory runs past the map value"
                );
                Ok(())
            }
            RegisterState::PtrToPacket {
                offset,
                known_ceiling: Some(ceiling),
                access: allowed,
                ..
            } => {
                let permitted = match access {
                    Access::Read => allowed.allows_read(),
                    Access::Write => allowed.allows_write(),
                };
                guard!(self, permitted, "helper access to packet is not permitted");
                guard!(
                    self,
                    offset
                        .max
                        .checked_add(len)
                        .is_some_and(|end| end <= ceiling.min),
                    "helper memory runs past the checked packet range"
                );
                Ok(())
            }
            _ => guard!(
                self,
                "helper memory argument must point to stack, map value or packet"
            ),
        }
    }

    /// Uninitialized bytes are allowed, as does Linux's privileged
    /// `allow_uninit_stack`. Spilled pointers are not, or a helper like
    /// `map_update_elem` would leak them.
    fn check_stack_range_read(&self, range: Range<u32>) -> Result<(), VerifierError> {
        guard!(
            self,
            self.frame()
                .slots_overlapping(range)
                .all(|(_, slot, _)| !slot.state.is_pointer()),
            "helper would read a spilled pointer"
        );
        Ok(())
    }

    /// Replaces whatever the helper writes over with unknown scalars, so
    /// later loads from the range verify. Scalar slots only partly covered
    /// keep their extent and lose their value.
    fn mark_stack_range_written(&mut self, range: Range<u32>) -> Result<(), VerifierError> {
        let overlapping: Vec<(u32, u32, bool)> = self
            .frame()
            .slots_overlapping(range.clone())
            .map(|(addr, slot, _)| (addr, slot.size.bytes(), slot.state.is_pointer()))
            .collect();

        let (mut fill_start, mut fill_end) = (range.start, range.end);
        for (addr, size, is_pointer) in overlapping {
            let slot_end = addr + size;
            if addr >= range.start && slot_end <= range.end {
                self.stack_mut().remove(&addr);
                continue;
            }

            guard!(
                self,
                !is_pointer,
                "helper write partially overwrites a spilled pointer"
            );
            if let Some(slot) = self.stack_mut().get_mut(&addr) {
                slot.state = RegisterState::Scalar(Scalar::Unknown);
            }
            if addr < range.start {
                fill_start = fill_start.max(slot_end);
            }
            if slot_end > range.end {
                fill_end = fill_end.min(addr);
            }
        }

        let pc = self.this_pc();
        let mut at = fill_start;
        while at < fill_end {
            let size = [MemSize::Dword, MemSize::Word, MemSize::Half]
                .into_iter()
                .find(|s| at.is_multiple_of(s.bytes()) && at + s.bytes() <= fill_end)
                .unwrap_or(MemSize::Byte);
            self.stack_mut().insert(
                at,
                StackSlot {
                    size,
                    state: RegisterState::Scalar(Scalar::Unknown),
                    pc,
                },
            );
            at += size.bytes();
        }

        Ok(())
    }
}
