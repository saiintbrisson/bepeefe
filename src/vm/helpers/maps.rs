use crate::isa::Insn;
use crate::verifier::{RegisterState, Scalar, ScalarRange};
use crate::vm::{Cpu, Vm};

use super::{BpfHelper, map_ops};

pub struct MapLookupElem;
impl MapLookupElem {
    pub const ID: i32 = 1;
}
impl BpfHelper for MapLookupElem {
    fn name(&self) -> &'static str {
        "bpf_map_lookup_elem"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        let map_fd = state.reg(1) as u16;
        let key = state.reg(2);
        let elem = map_ops::lookup_elem(state, map_fd, key).unwrap_or_default();
        state.set_reg(0, elem);
    }

    fn retval(
        &self,
        vm: &Vm,
        regs: &[RegisterState; 11],
        _: Insn,
    ) -> Result<RegisterState, &'static str> {
        let RegisterState::PtrToMap { map_fd } = regs[1] else {
            return Err("map_lookup_elem: R1 must be PtrToMap");
        };
        let map = vm.get_map(map_fd);
        if map.spec.r#type == Some(crate::maps::BPF_MAP_TYPE_ARRAY) {
            Ok(RegisterState::PtrToMapValue {
                map_fd,
                offset: ScalarRange::exact(0),
            })
        } else {
            Ok(RegisterState::PtrToMapValueOrNull { map_fd })
        }
    }

    fn params(&self, _: &Vm, regs: &[RegisterState; 11], _: Insn) -> Result<(), &'static str> {
        if !matches!(regs[1], RegisterState::PtrToMap { .. }) {
            return Err("map_lookup_elem: R1 must be PtrToMap");
        }
        if !regs[2].is_pointer() {
            return Err("map_lookup_elem: R2 must be a valid pointer");
        }
        Ok(())
    }
}

pub struct MapUpdateElem;
impl MapUpdateElem {
    pub const ID: i32 = 2;
}
impl BpfHelper for MapUpdateElem {
    fn name(&self) -> &'static str {
        "bpf_map_update_elem"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        let map_fd = state.reg(1) as u16;
        let key_ptr = state.reg(2);
        let value_ptr = state.reg(3);
        match map_ops::update(state, map_fd, key_ptr, value_ptr) {
            Ok(()) => state.set_reg(0, 0),
            Err(_) => state.set_reg(0, -1i64 as u64),
        }
    }

    fn retval(
        &self,
        _: &Vm,
        _: &[RegisterState; 11],
        _: Insn,
    ) -> Result<RegisterState, &'static str> {
        Ok(RegisterState::Scalar(Scalar::Unknown))
    }

    fn params(&self, _: &Vm, regs: &[RegisterState; 11], _: Insn) -> Result<(), &'static str> {
        if !matches!(regs[1], RegisterState::PtrToMap { .. }) {
            return Err("map_update_elem: R1 must be PtrToMap");
        }
        if !regs[2].is_pointer() {
            return Err("map_update_elem: R2 must be a valid pointer");
        }
        if !regs[3].is_pointer() {
            return Err("map_update_elem: R3 must be a valid pointer");
        }
        if !matches!(regs[4], RegisterState::Scalar(_)) {
            return Err("map_update_elem: R4 must be a scalar");
        }
        Ok(())
    }
}

pub struct MapDeleteElem;
impl MapDeleteElem {
    pub const ID: i32 = 3;
}
impl BpfHelper for MapDeleteElem {
    fn name(&self) -> &'static str {
        "bpf_map_delete_elem"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        let map_fd = state.reg(1) as u16;
        let key_ptr = state.reg(2);
        match map_ops::delete(state, map_fd, key_ptr) {
            Ok(()) => state.set_reg(0, 0),
            Err(_) => state.set_reg(0, -1i64 as u64),
        }
    }

    fn retval(
        &self,
        _: &Vm,
        _: &[RegisterState; 11],
        _: Insn,
    ) -> Result<RegisterState, &'static str> {
        Ok(RegisterState::Scalar(Scalar::Unknown))
    }

    fn params(&self, _: &Vm, regs: &[RegisterState; 11], _: Insn) -> Result<(), &'static str> {
        if !matches!(regs[1], RegisterState::PtrToMap { .. }) {
            return Err("map_delete_elem: R1 must be PtrToMap");
        }
        if !regs[2].is_pointer() {
            return Err("map_delete_elem: R2 must be a valid pointer");
        }
        Ok(())
    }
}

pub struct MapPushElem;
impl MapPushElem {
    pub const ID: i32 = 87;
}
impl BpfHelper for MapPushElem {
    fn name(&self) -> &'static str {
        "bpf_map_push_elem"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        let map_fd = state.reg(1) as u16;
        let value_ptr = state.reg(2);
        match map_ops::push(state, map_fd, value_ptr) {
            Ok(()) => state.set_reg(0, 0),
            Err(_) => state.set_reg(0, -1i64 as u64),
        }
    }

    fn retval(
        &self,
        _: &Vm,
        _: &[RegisterState; 11],
        _: Insn,
    ) -> Result<RegisterState, &'static str> {
        Ok(RegisterState::Scalar(Scalar::Unknown))
    }

    fn params(&self, _: &Vm, regs: &[RegisterState; 11], _: Insn) -> Result<(), &'static str> {
        if !matches!(regs[1], RegisterState::PtrToMap { .. }) {
            return Err("map_push_elem: R1 must be PtrToMap");
        }
        if !regs[2].is_pointer() {
            return Err("map_push_elem: R2 must be a valid pointer");
        }
        Ok(())
    }
}

pub struct MapPopElem;
impl MapPopElem {
    pub const ID: i32 = 88;
}
impl BpfHelper for MapPopElem {
    fn name(&self) -> &'static str {
        "bpf_map_pop_elem"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        let map_fd = state.reg(1) as u16;
        let dest_ptr = state.reg(2);
        match map_ops::pop(state, map_fd, dest_ptr) {
            Ok(()) => state.set_reg(0, 0),
            Err(_) => state.set_reg(0, -1i64 as u64),
        }
    }

    fn retval(
        &self,
        _: &Vm,
        _: &[RegisterState; 11],
        _: Insn,
    ) -> Result<RegisterState, &'static str> {
        Ok(RegisterState::Scalar(Scalar::Unknown))
    }

    fn params(&self, _: &Vm, regs: &[RegisterState; 11], _: Insn) -> Result<(), &'static str> {
        if !matches!(regs[1], RegisterState::PtrToMap { .. }) {
            return Err("map_pop_elem: R1 must be PtrToMap");
        }
        if !regs[2].is_pointer() {
            return Err("map_pop_elem: R2 must be a valid pointer");
        }
        Ok(())
    }
}

pub struct PerfEventOutput;
impl PerfEventOutput {
    pub const ID: i32 = 25;
}
impl BpfHelper for PerfEventOutput {
    fn name(&self) -> &'static str {
        "bpf_perf_event_output"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        let map_fd = state.reg(2) as u16;
        let flags = state.reg(3);
        let data_ptr = state.reg(4);
        let size = state.reg(5) as u32;
        match map_ops::perf_event_output(state, map_fd, flags, data_ptr, size) {
            Ok(()) => state.set_reg(0, 0),
            Err(_) => state.set_reg(0, -1i64 as u64),
        }
    }

    fn retval(
        &self,
        _: &Vm,
        _: &[RegisterState; 11],
        _: Insn,
    ) -> Result<RegisterState, &'static str> {
        Ok(RegisterState::Scalar(Scalar::Unknown))
    }

    fn params(&self, vm: &Vm, regs: &[RegisterState; 11], _: Insn) -> Result<(), &'static str> {
        if !matches!(regs[1], RegisterState::PtrToCtx { .. }) {
            return Err("perf_event_output: R1 must be PtrToCtx");
        }
        let RegisterState::PtrToMap { map_fd } = regs[2] else {
            return Err("perf_event_output: R2 must be PtrToMap");
        };
        let map = vm.get_map(map_fd);
        if map.spec.r#type != Some(crate::maps::BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
            return Err("perf_event_output: R2 map must be BPF_MAP_TYPE_PERF_EVENT_ARRAY");
        }
        if !matches!(regs[3], RegisterState::Scalar(_)) {
            return Err("perf_event_output: R3 must be a scalar");
        }
        if !regs[4].is_pointer() {
            return Err("perf_event_output: R4 must be a valid pointer");
        }
        if !matches!(regs[5], RegisterState::Scalar(_)) {
            return Err("perf_event_output: R5 must be a scalar");
        }
        Ok(())
    }
}

pub struct MapPeekElem;
impl MapPeekElem {
    pub const ID: i32 = 89;
}
impl BpfHelper for MapPeekElem {
    fn name(&self) -> &'static str {
        "bpf_map_peek_elem"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        let map_fd = state.reg(1) as u16;
        let dest_ptr = state.reg(2);
        match map_ops::peek(state, map_fd, dest_ptr) {
            Ok(()) => state.set_reg(0, 0),
            Err(_) => state.set_reg(0, -1i64 as u64),
        }
    }

    fn retval(
        &self,
        _: &Vm,
        _: &[RegisterState; 11],
        _: Insn,
    ) -> Result<RegisterState, &'static str> {
        Ok(RegisterState::Scalar(Scalar::Unknown))
    }

    fn params(&self, _: &Vm, regs: &[RegisterState; 11], _: Insn) -> Result<(), &'static str> {
        if !matches!(regs[1], RegisterState::PtrToMap { .. }) {
            return Err("map_peek_elem: R1 must be PtrToMap");
        }
        if !regs[2].is_pointer() {
            return Err("map_peek_elem: R2 must be a valid pointer");
        }
        Ok(())
    }
}
