use std::borrow::Cow;

use crate::{
    btf::BtfTypeId,
    verifier::{BranchDecision, RegMask, RegisterState},
};

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

#[derive(serde::Serialize)]
pub enum VerifierEvent<'a> {
    Insn {
        depth: usize,
        pc: usize,
        /// Registers whose state the check consulted. Helper calls report the
        /// exact arguments the helper read, subprogram calls report r1 through
        /// the callee's last declared parameter.
        read: RegMask,
        /// Registers the instruction wrote, paired with their new state.
        /// Walk-spawning jumps record before their check runs and write
        /// nothing here, refinements arrive on the arms' [`BranchEnter`]
        /// events instead.
        ///
        /// [`BranchEnter`]: VerifierEvent::BranchEnter
        written: &'a [(u8, RegisterState)],
    },
    BranchEnter {
        depth: usize,
        target_pc: usize,
        /// Verdict reached for the jump that spawned this arm. `Both` means
        /// a sibling arm is also walked, the skip variants mean this arm is
        /// the only one.
        decision: BranchDecision,
        /// Register the comparison refined on this arm, with its new state.
        /// The rest of the arm's registers match the parent walk.
        refined: Option<(u8, RegisterState)>,
    },
    BranchExit {
        depth: usize,
    },
    CallEnter {
        depth: usize,
        target_pc: usize,
        /// Name of the called subprogram, empty when unknown.
        name: Cow<'a, str>,
        /// BTF id of the subprogram's `Func` type, when the object carries
        /// func_info for it. Resolvable to the full signature through BTF.
        btf_id: Option<BtfTypeId>,
        /// Callee register state on entry, r1 onwards carry the arguments.
        registers: &'a [RegisterState; 11],
    },
    CallExit {
        depth: usize,
        /// State the call returns in r0. The caller's r1 through r5 always
        /// become uninit after a call, that is left implicit.
        r0: RegisterState,
    },

    /// The verifier's static view of a `bpf_perf_event_output` payload.
    ///
    /// Only describes the stack boundaries known to the verifier, not types.
    ///
    /// [`Insn`]: VerifierEvent::Insn
    PerfEventLayout {
        depth: usize,
        /// pc of the emitting call. Joins this layout to the runtime
        /// [`Event::PerfEventOutput`] payloads and the call's `Insn` event.
        pc: usize,
        map_fd: u16,
        /// Payload byte length when known at verification time.
        size: Option<u32>,
        /// Slots fully inside the payload region. Bytes covered by no slot
        /// were never written on this path. Empty when the data pointer is
        /// not an exact stack pointer or the length is unknown.
        slots: &'a [PayloadSlot],
    },
    Warning {
        pc: usize,
        message: Cow<'a, str>,
    },
}

/// A stack slot inside a perf event payload, as the verifier saw it
/// written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct PayloadSlot {
    /// Byte offset within the payload.
    pub offset: u32,
    pub size: u32,
    pub state: RegisterState,
    /// pc of the store that wrote this slot. Joins to `line_info` for the
    /// source location that produced the value.
    pub pc: usize,
}

pub trait Capture {
    fn record(&self, event: Event<'_>);
}

pub type NoopCapture = ();

impl Capture for NoopCapture {
    fn record(&self, _: Event<'_>) {}
}
