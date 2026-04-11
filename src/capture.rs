use std::borrow::Cow;

use crate::verifier::RegisterState;

#[derive(serde::Serialize)]
pub enum Event<'a> {
    Print(Cow<'a, str>),
    Verifier(VerifierEvent<'a>),
    /// Emitted by `bpf_perf_event_output`. `fd` is the value the BPF
    /// program had previously stored at the slot resolved from `flags`
    /// (typically a perf event fd), and `data` is the payload copied
    /// out of the program's memory.
    PerfEventOutput {
        fd: u32,
        data: Cow<'a, [u8]>,
    },
}

#[derive(serde::Serialize)]
pub enum VerifierEvent<'a> {
    Insn {
        depth: usize,
        pc: usize,
        #[serde(skip)]
        registers: &'a [RegisterState; 11],
    },
    BranchEnter {
        depth: usize,
        target_pc: usize,
    },
    BranchExit {
        depth: usize,
    },
    Warning {
        pc: usize,
        message: Cow<'a, str>,
    },
}

pub trait Capture {
    fn record(&self, event: Event<'_>);
}

pub type NoopCapture = ();

impl Capture for NoopCapture {
    fn record(&self, _: Event<'_>) {}
}
