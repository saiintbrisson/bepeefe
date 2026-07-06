use std::cell::Cell;

use crate::isa::Insn;
use crate::verifier::{RegMask, RegisterState};

mod map_ops;
mod maps;
mod meta;
mod printk;
mod probe_ops;
mod probes;

pub(crate) use maps::PerfEventOutput;

/// Register view handed to a helper's [`BpfHelper::params`] and
/// [`BpfHelper::retval`]. Every [`get`](ArgRegs::get) marks the register in
/// the verifier's read mask, so the recorded `Insn` event reports exactly the
/// arguments the helper consulted.
#[derive(Clone, Copy)]
pub struct ArgRegs<'a> {
    registers: &'a [RegisterState; 11],
    reads: &'a Cell<RegMask>,
}

impl<'a> ArgRegs<'a> {
    pub(crate) fn new(registers: &'a [RegisterState; 11], reads: &'a Cell<RegMask>) -> Self {
        Self { registers, reads }
    }

    /// # Panics
    ///
    /// Panics if `idx` is out of bounds (>= 11).
    #[expect(
        clippy::indexing_slicing,
        reason = "helpers only read fixed argument registers r1 through r5"
    )]
    pub fn get(&self, idx: u8) -> RegisterState {
        self.reads.set(self.reads.get() | RegMask::single(idx));
        self.registers[idx as usize]
    }
}

/// BPF helper functions and dispatch.
///
/// Each helper is a unit struct implementing [`BpfHelper`]. The
/// verifier validates a call's argument types via `params` and tracks
/// the return type via `retval`; the runtime calls `exec`. [`lookup`]
/// maps a helper id to a `&'static dyn BpfHelper` via a single match,
/// leaving room for a future host-supplied registry to fall through.
pub trait BpfHelper {
    fn name(&self) -> &'static str;

    fn exec(&self, state: &mut crate::vm::Cpu, insn: Insn);

    fn retval(
        &self,
        vm: &crate::vm::Vm,
        regs: ArgRegs,
        insn: Insn,
    ) -> Result<RegisterState, &'static str>;

    fn params(&self, vm: &crate::vm::Vm, regs: ArgRegs, insn: Insn) -> Result<(), &'static str>;
}

pub fn lookup(id: i32) -> Option<&'static dyn BpfHelper> {
    fn dyn_ref<H: BpfHelper + 'static>(h: &'static H) -> &'static dyn BpfHelper {
        h
    }

    use maps::*;
    use meta::*;
    use printk::*;
    use probes::*;

    match id {
        MapLookupElem::ID => Some(dyn_ref(&MapLookupElem)),
        MapUpdateElem::ID => Some(dyn_ref(&MapUpdateElem)),
        MapDeleteElem::ID => Some(dyn_ref(&MapDeleteElem)),
        MapPushElem::ID => Some(dyn_ref(&MapPushElem)),
        MapPopElem::ID => Some(dyn_ref(&MapPopElem)),
        MapPeekElem::ID => Some(dyn_ref(&MapPeekElem)),
        PerfEventOutput::ID => Some(dyn_ref(&PerfEventOutput)),

        TracePrintk::ID => Some(dyn_ref(&TracePrintk)),

        KtimeGetNs::ID => Some(dyn_ref(&KtimeGetNs)),
        GetPrandomU32::ID => Some(dyn_ref(&GetPrandomU32)),
        GetSmpProcessorId::ID => Some(dyn_ref(&GetSmpProcessorId)),
        GetCurrentPidTgid::ID => Some(dyn_ref(&GetCurrentPidTgid)),
        GetCurrentComm::ID => Some(dyn_ref(&GetCurrentComm)),

        ProbeReadUser::ID => Some(dyn_ref(&ProbeReadUser)),
        ProbeReadKernel::ID => Some(dyn_ref(&ProbeReadKernel)),
        ProbeReadUserStr::ID => Some(dyn_ref(&ProbeReadUserStr)),
        ProbeReadKernelStr::ID => Some(dyn_ref(&ProbeReadKernelStr)),

        _ => None,
    }
}
