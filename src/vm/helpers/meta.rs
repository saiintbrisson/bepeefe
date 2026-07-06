use crate::isa::Insn;
use crate::verifier::{RegisterState, Scalar};
use crate::vm::{Cpu, Vm};

use super::{ArgRegs, BpfHelper};

pub struct KtimeGetNs;
impl KtimeGetNs {
    pub const ID: i32 = 5;
}
impl BpfHelper for KtimeGetNs {
    fn name(&self) -> &'static str {
        "bpf_ktime_get_ns"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        state.set_reg(0, state.ktime_ns());
    }

    fn retval(&self, _: &Vm, _: ArgRegs, _: Insn) -> Result<RegisterState, &'static str> {
        Ok(RegisterState::Scalar(Scalar::Unknown))
    }

    fn params(&self, _: &Vm, _: ArgRegs, _: Insn) -> Result<(), &'static str> {
        Ok(())
    }
}

pub struct GetPrandomU32;
impl GetPrandomU32 {
    pub const ID: i32 = 7;
}
impl BpfHelper for GetPrandomU32 {
    fn name(&self) -> &'static str {
        "bpf_get_prandom_u32"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        state.set_reg(0, state.prandom_u32() as u64);
    }

    fn retval(&self, _: &Vm, _: ArgRegs, _: Insn) -> Result<RegisterState, &'static str> {
        Ok(RegisterState::Scalar(Scalar::Unknown))
    }

    fn params(&self, _: &Vm, _: ArgRegs, _: Insn) -> Result<(), &'static str> {
        Ok(())
    }
}

pub struct GetSmpProcessorId;
impl GetSmpProcessorId {
    pub const ID: i32 = 8;
}
impl BpfHelper for GetSmpProcessorId {
    fn name(&self) -> &'static str {
        "bpf_get_smp_processor_id"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        state.set_reg(0, state.cpu() as u64);
    }

    fn retval(&self, _: &Vm, _: ArgRegs, _: Insn) -> Result<RegisterState, &'static str> {
        Ok(RegisterState::Scalar(Scalar::Unknown))
    }

    fn params(&self, _: &Vm, _: ArgRegs, _: Insn) -> Result<(), &'static str> {
        Ok(())
    }
}

pub struct GetCurrentPidTgid;
impl GetCurrentPidTgid {
    pub const ID: i32 = 14;
}
impl BpfHelper for GetCurrentPidTgid {
    fn name(&self) -> &'static str {
        "bpf_get_current_pid_tgid"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        state.set_reg(0, state.task().pid_tgid());
    }

    fn retval(&self, _: &Vm, _: ArgRegs, _: Insn) -> Result<RegisterState, &'static str> {
        Ok(RegisterState::Scalar(Scalar::Unknown))
    }

    fn params(&self, _: &Vm, _: ArgRegs, _: Insn) -> Result<(), &'static str> {
        Ok(())
    }
}

// TODO: revisit, this is not safe
//
// Writes up to size-1 comm bytes followed by a NUL terminator; unused
// bytes are zeroed. Returns 0 on success, -EINVAL when size is 0.
pub struct GetCurrentComm;
impl GetCurrentComm {
    pub const ID: i32 = 16;
}
impl BpfHelper for GetCurrentComm {
    fn name(&self) -> &'static str {
        "bpf_get_current_comm"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        let buf_ptr = state.reg(1);
        let size = state.reg(2) as u32 as usize;
        if size == 0 {
            state.set_reg(0, -22i64 as u64); // EINVAL
            return;
        }
        let comm = state.task().comm();
        let mut out = Vec::with_capacity(size);
        out.extend(comm.iter().copied().take(size - 1));
        out.resize(size, 0);
        state.write(buf_ptr, &out);
        state.set_reg(0, 0);
    }

    fn retval(&self, _: &Vm, _: ArgRegs, _: Insn) -> Result<RegisterState, &'static str> {
        Ok(RegisterState::Scalar(Scalar::Unknown))
    }

    fn params(&self, _: &Vm, regs: ArgRegs, _: Insn) -> Result<(), &'static str> {
        if !regs.get(1).is_pointer() {
            return Err("get_current_comm: R1 must be a valid pointer");
        }
        if !regs.get(2).is_scalar() {
            return Err("get_current_comm: R2 must be a scalar");
        }
        Ok(())
    }
}
