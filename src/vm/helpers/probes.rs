use crate::isa::Insn;
use crate::verifier::{RegisterState, Scalar};
use crate::vm::ptr::TaggetPtrType;
use crate::vm::{Cpu, Vm};

use super::{BpfHelper, probe_ops};

/// Shared params validator. R3 is `ARG_ANYTHING` in Linux: any source
/// value is accepted, with faults surfaced at runtime as `-EFAULT`.
fn probe_params(regs: &[RegisterState; 11]) -> Result<(), &'static str> {
    if !regs[1].is_pointer() {
        return Err("probe_read: R1 must be a valid pointer");
    }
    if !matches!(regs[2], RegisterState::Scalar(_)) {
        return Err("probe_read: R2 must be a scalar");
    }
    Ok(())
}

fn run_probe_read(state: &mut Cpu, space: TaggetPtrType) {
    let dst = state.reg(1);
    let size = state.reg(2) as u32;
    let src = state.reg(3);
    let r = probe_ops::probe_read(state, space, dst, size, src);
    state.set_reg(0, r as u64);
}

fn run_probe_read_str(state: &mut Cpu, space: TaggetPtrType) {
    let dst = state.reg(1);
    let size = state.reg(2) as u32;
    let src = state.reg(3);
    let r = probe_ops::probe_read_str(state, space, dst, size, src);
    state.set_reg(0, r as u64);
}

pub struct ProbeReadUser;
impl ProbeReadUser {
    pub const ID: i32 = 112;
}
impl BpfHelper for ProbeReadUser {
    fn name(&self) -> &'static str {
        "bpf_probe_read_user"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        run_probe_read(state, TaggetPtrType::User);
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
        probe_params(regs)
    }
}

pub struct ProbeReadKernel;
impl ProbeReadKernel {
    pub const ID: i32 = 113;
}
impl BpfHelper for ProbeReadKernel {
    fn name(&self) -> &'static str {
        "bpf_probe_read_kernel"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        run_probe_read(state, TaggetPtrType::Kernel);
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
        probe_params(regs)
    }
}

pub struct ProbeReadUserStr;
impl ProbeReadUserStr {
    pub const ID: i32 = 114;
}
impl BpfHelper for ProbeReadUserStr {
    fn name(&self) -> &'static str {
        "bpf_probe_read_user_str"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        run_probe_read_str(state, TaggetPtrType::User);
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
        probe_params(regs)
    }
}

pub struct ProbeReadKernelStr;
impl ProbeReadKernelStr {
    pub const ID: i32 = 115;
}
impl BpfHelper for ProbeReadKernelStr {
    fn name(&self) -> &'static str {
        "bpf_probe_read_kernel_str"
    }

    fn exec(&self, state: &mut Cpu, _: Insn) {
        run_probe_read_str(state, TaggetPtrType::Kernel);
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
        probe_params(regs)
    }
}
