use std::cell::Cell;

use crate::verifier::{RegMask, RegisterState, Scalar};
use crate::vm::{Cpu, Vm};

pub use args::{Access, ArgSpec};
use args::{ArgList, Call};

mod args;
mod map_ops;
mod maps;
mod meta;
mod printk;
mod probe_ops;
mod probes;

pub(crate) use maps::PerfEventOutput;

/// Register view handed to a helper's [`BpfHelper::retval`]. Every
/// [`get`](ArgRegs::get) marks the register in the verifier's read mask, so
/// the recorded `Insn` event reports exactly the arguments the call consulted.
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
/// Each helper is a unit struct implementing [`BpfHelper`]. Its `Args` tuple
/// is both what the verifier checks the argument registers against and what
/// `exec` receives, so the memory a helper touches is the memory that was
/// checked. [`lookup`] maps a helper id to a `&'static dyn Helper` via a
/// single match, leaving room for a future host-supplied registry to fall
/// through.
pub trait BpfHelper: Sync + 'static {
    type Args: ArgList;

    fn name(&self) -> &'static str;

    /// Runs after the arguments were checked against `Args`. Helpers whose
    /// return type depends on their arguments, or that constrain them further
    /// than a signature can say, override this.
    fn retval(&self, _: &Vm, _: ArgRegs) -> Result<RegisterState, &'static str> {
        Ok(RegisterState::Scalar(Scalar::Unknown))
    }

    /// Returns the value for r0.
    fn exec(&self, cx: &mut Call<'_>, args: Self::Args) -> u64;
}

/// Object safe face of [`BpfHelper`].
pub trait Helper {
    fn name(&self) -> &'static str;
    fn sig(&self) -> &'static [ArgSpec];
    fn retval(&self, vm: &Vm, regs: ArgRegs) -> Result<RegisterState, &'static str>;
    fn exec(&self, cpu: &mut Cpu);
}

impl<H: BpfHelper> Helper for H {
    fn name(&self) -> &'static str {
        BpfHelper::name(self)
    }

    fn sig(&self) -> &'static [ArgSpec] {
        H::Args::SIG
    }

    fn retval(&self, vm: &Vm, regs: ArgRegs) -> Result<RegisterState, &'static str> {
        BpfHelper::retval(self, vm, regs)
    }

    fn exec(&self, cpu: &mut Cpu) {
        let args = H::Args::decode(cpu);
        let r0 = BpfHelper::exec(self, &mut Call::new(cpu), args);
        cpu.set_reg(0, r0);
    }
}

pub fn lookup(id: i32) -> Option<&'static dyn Helper> {
    fn dyn_ref<H: BpfHelper>(h: &'static H) -> &'static dyn Helper {
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
