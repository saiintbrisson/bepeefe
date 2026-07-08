use std::borrow::Cow;

use crate::verifier::VerifierEvent;

#[derive(serde::Serialize)]
pub enum Event<'a> {
    Print(Cow<'a, str>),
    Verifier(VerifierEvent<'a>),
    /// Emitted by `bpf_perf_event_output`. `fd` is the value the BPF
    /// program had previously stored at the slot resolved from `flags`
    /// (typically a perf event fd), and `data` is the payload copied
    /// out of the program's memory.
    PerfEventOutput {
        /// pc of the emitting call instruction. Joins the payload to the
        /// [`VerifierEvent::PerfEventLayout`] recorded for the same call
        /// site.
        pc: usize,
        fd: u32,
        data: Cow<'a, [u8]>,
    },
}

pub trait Capture {
    fn record(&self, event: Event<'_>);
}

pub type NoopCapture = ();

impl Capture for NoopCapture {
    fn record(&self, _: Event<'_>) {}
}
