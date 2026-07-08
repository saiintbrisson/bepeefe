use std::borrow::Cow;

use crate::btf::BtfTypeId;

use super::{PruneSite, RegMask, RegisterState, WalkOrigin};

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
        /// Stable id of this walk. [`StatePruned`] events reference it through
        /// their `matched` field.
        ///
        /// [`StatePruned`]: VerifierEvent::StatePruned
        id: usize,
        target_pc: usize,
        /// Which arm this is, carrying the `fork_pc` of the jump that spawned
        /// it. Every arm of one branch, live or [`BranchDead`], shares that
        /// `fork_pc`, and a [`StatePruned`] landing on that jump carries the
        /// same `fork_pc`, which is how it joins to the arms.
        ///
        /// [`BranchDead`]: VerifierEvent::BranchDead
        /// [`StatePruned`]: VerifierEvent::StatePruned
        kind: WalkOrigin,
    },
    /// An arm the comparison ruled out. It never entered, so it has no id and
    /// no body. A leaf sibling of the arms that did enter.
    BranchDead {
        depth: usize,
        target_pc: usize,
        /// Which side was ruled out, carrying the same `fork_pc` as its live
        /// siblings' [`BranchEnter`].
        ///
        /// [`BranchEnter`]: VerifierEvent::BranchEnter
        kind: WalkOrigin,
    },
    /// This walk stopped because walker `matched` already covered every state
    /// reachable from `fork_pc`. Not an arm. The continuation is whatever
    /// walker `matched` explored from `fork_pc`, which may be a whole subtree.
    /// `site` says how to reach it without resolving `matched` first.
    StatePruned {
        depth: usize,
        /// pc where the walk's state was already covered. When `site` is
        /// [`PruneSite::Jump`] this is a jump, and the arms it spawned carry it
        /// as their `fork_pc`.
        fork_pc: usize,
        /// Walk that recorded the covering snapshot.
        matched: usize,
        site: PruneSite,
    },
    BranchExit {
        depth: usize,
    },
    CallEnter {
        depth: usize,
        /// Stable id of this walk. [`StatePruned`] events reference it through
        /// their `matched` field.
        ///
        /// [`StatePruned`]: VerifierEvent::StatePruned
        id: usize,
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

/// A stack slot inside a perf event payload, as the verifier saw it written.
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
