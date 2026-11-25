//! Rendering verifier events, and cutting a failed run down to the path that
//! reached the failure.

use std::{collections::BTreeSet, sync::Mutex};

use bepeefe::{
    PrepareError,
    capture::{Capture, Event},
    verifier::{RegMask, VerifierError, VerifierEvent, WalkOrigin},
};

/// Prints each verifier event on its own line, nested by walk depth so the
/// branch tree reads top to bottom.
pub struct EventLines;

impl Capture for EventLines {
    fn record(&self, event: Event<'_>) {
        let Event::Verifier(event) = event else {
            return;
        };
        let indent = event.depth().unwrap_or(0);
        println!("{}", event_line(&event, indent));
    }
}

/// Holds every verifier event so a failed run can be filtered afterwards.
#[derive(Default)]
pub struct TraceBuffer(Mutex<Vec<VerifierEvent<'static>>>);

impl Capture for TraceBuffer {
    fn record(&self, event: Event<'_>) {
        let Event::Verifier(event) = event else {
            return;
        };
        if let Ok(mut events) = self.0.lock() {
            events.push(event.into_owned());
        }
    }
}

/// Events selected for a failure report, and how many were recorded overall.
pub struct FailureTrace {
    pub label: &'static str,
    pub events: Vec<VerifierEvent<'static>>,
    pub recorded: usize,
}

impl TraceBuffer {
    /// Picks out the events worth showing for a failure.
    ///
    /// [`TraceMode::Path`] keeps every event on the failing walk and its
    /// ancestors. [`TraceMode::Slice`] narrows that to the ones that produced
    /// the registers the failing check was reading. The other modes print no
    /// trace at all.
    pub fn failure_trace(&self, err: &PrepareError, mode: TraceMode) -> Option<FailureTrace> {
        if matches!(mode, TraceMode::None | TraceMode::All) {
            return None;
        }

        let events = self.0.lock().ok()?;
        let path = failing_path(&events);
        if path.is_empty() {
            return None;
        }

        let (label, shown) = match (mode, failure_seed(err)) {
            (TraceMode::Slice, Some(seed)) => ("slice", slice(&path, seed)),
            _ => ("path", path),
        };

        Some(FailureTrace {
            label,
            events: shown.into_iter().cloned().collect(),
            recorded: events.len(),
        })
    }
}

/// What to print when verification fails.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum TraceMode {
    /// Nothing beyond the error report.
    None,
    /// Only what produced the registers the failing check read.
    Slice,
    /// Every event on the failing walk and its ancestors.
    Path,
    /// Every event, streamed as it happens.
    All,
}

/// Registers the failing check was reading, the roots of the slice.
fn failure_seed(err: &PrepareError) -> Option<RegMask> {
    let PrepareError::Verifier {
        source: VerifierError::Other { read, .. },
        ..
    } = err
    else {
        return None;
    };
    Some(*read)
}

/// The events leading to wherever the stream stopped, with every walk that
/// isn't an ancestor of it dropped.
///
/// The stream is a preorder traversal of the walk tree and a failure truncates
/// it, so the last event sits inside the failing walk. Scanning backwards,
/// anything deeper than the walk currently being followed belongs to a sibling
/// that already finished, and reaching a walk's own enter steps out into its
/// parent. What survives is the failing walk plus each ancestor's events from
/// before it forked.
fn failing_path<'e>(events: &'e [VerifierEvent<'static>]) -> Vec<&'e VerifierEvent<'static>> {
    let Some(mut cursor) = events.last().and_then(|event| event.depth()) else {
        return Vec::new();
    };

    let mut path = Vec::new();
    for event in events.iter().rev() {
        let Some(depth) = event.depth() else {
            // Warnings belong to no walk, so they can't move the cursor. Keep
            // them, they are cheap and usually worth reading.
            path.push(event);
            continue;
        };

        if depth > cursor {
            continue;
        }
        cursor = depth;
        path.push(event);

        if event.is_walk_enter() {
            match cursor.checked_sub(1) {
                Some(parent) => cursor = parent,
                None => break,
            }
        }
    }

    path.reverse();
    path
}

/// Backward slice of a path: the events that produced the registers in `seed`,
/// the ones that produced *those*, and so on back to the entry.
///
/// Walking the path in reverse with a set of registers we still owe an
/// explanation for: an instruction that writes one of them is kept, and its own
/// reads join the set. A branch that refined one is kept too, along with the
/// jump it forked at, since the refinement is often the whole story.
fn slice<'e>(
    path: &[&'e VerifierEvent<'static>],
    seed: RegMask,
) -> Vec<&'e VerifierEvent<'static>> {
    let mut wanted = seed;
    let mut wanted_pcs = BTreeSet::new();
    let mut kept = Vec::new();

    for event in path.iter().rev() {
        match event {
            VerifierEvent::Insn {
                pc, read, written, ..
            } => {
                let writes = written.iter().fold(RegMask::empty(), |mask, (reg, _)| {
                    mask | RegMask::single(*reg)
                });

                if !wanted.intersects(writes) && !wanted_pcs.remove(pc) {
                    continue;
                }

                wanted = (wanted - writes) | *read;
                kept.push(*event);
            }

            // A call's own instruction records no writes, so pull the callee's
            // arguments in when the returned r0 is still owed an explanation.
            VerifierEvent::CallExit { r0: _, .. } => {
                if wanted.contains(RegMask::R0) {
                    wanted |= ARG_REGS;
                }
                kept.push(*event);
            }
            VerifierEvent::CallEnter { .. } => kept.push(*event),

            VerifierEvent::BranchEnter { kind, .. } => {
                let (WalkOrigin::Branch { refined, fork_pc }
                | WalkOrigin::Fallthrough { refined, fork_pc }) = kind
                else {
                    continue;
                };
                let Some((reg, _)) = refined else { continue };
                if !wanted.contains(RegMask::single(*reg)) {
                    continue;
                }
                wanted_pcs.insert(*fork_pc);
                kept.push(*event);
            }

            _ => {}
        }
    }

    kept.reverse();
    kept
}

/// r1 through r5, the registers a call passes its arguments in.
const ARG_REGS: RegMask = RegMask::R1
    .union(RegMask::R2)
    .union(RegMask::R3)
    .union(RegMask::R4)
    .union(RegMask::R5);

pub fn event_line(event: &VerifierEvent<'_>, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    match event {
        VerifierEvent::Insn {
            pc, read, written, ..
        } => {
            let writes = written
                .iter()
                .map(|(reg, state)| format!("r{reg}={state:?}"))
                .collect::<Vec<_>>()
                .join(" ");
            format!("{pad}insn pc={pc} read={read:?} write=[{writes}]")
        }
        VerifierEvent::BranchEnter {
            id,
            target_pc,
            kind,
            ..
        } => format!("{pad}branch-enter id={id} target={target_pc} kind={kind:?}"),
        VerifierEvent::BranchDead {
            target_pc, kind, ..
        } => format!("{pad}branch-dead target={target_pc} kind={kind:?}"),
        VerifierEvent::StatePruned {
            fork_pc,
            matched,
            site,
            ..
        } => format!("{pad}state-pruned fork={fork_pc} matched={matched} site={site:?}"),
        VerifierEvent::BranchExit { .. } => format!("{pad}branch-exit"),
        VerifierEvent::CallEnter {
            id,
            target_pc,
            name,
            btf_id,
            ..
        } => format!("{pad}call-enter id={id} target={target_pc} name={name:?} btf={btf_id:?}"),
        VerifierEvent::CallExit { r0, .. } => format!("{pad}call-exit r0={r0:?}"),
        VerifierEvent::PerfEventLayout {
            pc, map_fd, size, ..
        } => format!("{pad}perf-layout pc={pc} map_fd={map_fd} size={size:?}"),
        VerifierEvent::Warning { pc, message } => format!("{pad}warning pc={pc} {message}"),
    }
}
