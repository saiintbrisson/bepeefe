//! Rendering a verifier failure as a source-annotated snippet.

use std::{borrow::Cow, collections::BTreeSet};

use bepeefe::{
    PrepareError,
    object::LineEntry,
    verifier::{Diagnostic, VerifierEvent, WalkOrigin},
};

use crate::trace::FailureTrace;

/// Instructions to show on either side of the failing one.
const RADIUS: usize = 3;

pub fn render(err: &PrepareError) -> String {
    let Some(diag) = err.diagnostic() else {
        return format!("error: {err}\n");
    };

    let insns = diag.prog.insns();
    let start = diag.pc.saturating_sub(RADIUS);
    let end = (diag.pc + RADIUS + 1).min(insns.len());
    let pc_width = end.saturating_sub(1).to_string().len().max(2);
    let gutter = " ".repeat(pc_width + 4);

    let mut out = format!("error: {}\n  --> pc {}\n\n", diag.message, diag.pc);

    let mut prev_line_off = None;
    for pc in start..end {
        let Some(insn) = insns.get(pc) else {
            break;
        };
        let next = insns.get(pc + 1).copied();

        // Source lines repeat across the instructions they compiled to, so
        // only annotate the first instruction of each one.
        let line = source_at(&diag, pc);
        let annotation = match &line {
            Some((entry, _)) if prev_line_off == Some(entry.line_off) => String::new(),
            Some((entry, text)) => format!("    ; @{:<3}  {}", entry.line_no, text.trim()),
            None => String::new(),
        };
        if let Some((entry, _)) = &line {
            prev_line_off = Some(entry.line_off);
        }

        let marker = if pc == diag.pc { '>' } else { ' ' };
        let disasm = bepeefe::isa::dump::disasm(*insn, next);
        out.push_str(&format!(
            " {marker} {pc:>pc_width$} | {disasm}{annotation}\n"
        ));

        if pc == diag.pc {
            out.push_str(&format!("{gutter}|   {}\n", registers(&diag)));
        }
    }

    out
}

/// Column the register states line up in, wide enough for most disassembly.
const STATE_COLUMN: usize = 34;

/// Renders the events that led to the failure as instructions rather than as
/// an event dump: same pc gutter and source annotations as the report above it,
/// with the state each instruction produced alongside.
pub fn render_trace(diag: &Diagnostic<'_>, trace: &FailureTrace) -> String {
    if trace.events.is_empty() {
        return String::new();
    }

    let insns = diag.prog.insns();
    let pc_width = diag.pc.to_string().len().max(2);
    let mut out = format!(
        "\n{}: {} of {} events\n\n",
        trace.label,
        trace.events.len(),
        trace.recorded
    );

    // A slice jumps around the program and often revisits a line, e.g. once per
    // loop iteration. Announcing each one only the first time keeps the
    // instructions readable, the pc column is enough to find your way back.
    let mut announced = BTreeSet::new();
    for event in &trace.events {
        match event {
            VerifierEvent::Insn { pc, written, .. } => {
                if let Some((entry, text)) = source_at(diag, *pc)
                    && announced.insert(entry.line_off)
                {
                    out.push_str(&format!(
                        "{:w$}   ; @{:<3} {}\n",
                        "",
                        entry.line_no,
                        text.trim(),
                        w = pc_width
                    ));
                }

                let Some(insn) = insns.get(*pc) else { continue };
                let disasm = bepeefe::isa::dump::disasm(*insn, insns.get(pc + 1).copied());
                let writes = written
                    .iter()
                    .map(|(reg, state)| format!("r{reg} = {state:?}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push_str(&format!(
                    " {pc:>pc_width$} | {disasm:<STATE_COLUMN$} {writes}\n"
                ));
            }

            VerifierEvent::BranchEnter {
                target_pc, kind, ..
            } => {
                let (arm, refined) = match kind {
                    WalkOrigin::Branch { refined, .. } => ("branch", refined),
                    WalkOrigin::Fallthrough { refined, .. } => ("fallthrough", refined),
                    WalkOrigin::Call => continue,
                };
                let refinement = match refined {
                    Some((reg, state)) => format!("r{reg} = {state:?}"),
                    None => String::new(),
                };
                let arm = format!("{arm} to {target_pc}");
                out.push_str(&format!(
                    "{:w$} + {arm:<STATE_COLUMN$} {refinement}\n",
                    "",
                    w = pc_width
                ));
            }

            VerifierEvent::CallEnter {
                target_pc, name, ..
            } => out.push_str(&format!(" {target_pc:>pc_width$} | {name}:\n")),
            VerifierEvent::CallExit { r0, .. } => out.push_str(&format!(
                "{:w$} + {:<STATE_COLUMN$} r0 = {r0:?}\n",
                "",
                "returns",
                w = pc_width
            )),

            _ => {}
        }
    }

    out
}

/// The source line covering `pc`, when the object carries one.
///
/// Records are sparse: one marks the first instruction a line compiled to and
/// covers everything up to the next record, so the nearest one at or before
/// `pc` is the one that owns it.
fn source_at<'a>(diag: &'a Diagnostic<'a>, pc: usize) -> Option<(&'a LineEntry, Cow<'a, str>)> {
    let (_, entry) = diag.prog.line_info().range(..=pc).next_back()?;
    let text = diag.prog.btf().string(entry.line_off)?;
    (!text.trim().is_empty()).then_some((entry, text))
}

/// The registers the failing check read, in the state it read them.
///
/// Falls back to the instruction's own register fields when the check rejected
/// the instruction before consulting anything, so the line is never empty.
fn registers(diag: &Diagnostic<'_>) -> String {
    let mut regs: Vec<u8> = diag
        .read
        .iter()
        .map(|flag| flag.bits().trailing_zeros() as u8)
        .collect();

    if regs.is_empty() {
        regs.push(diag.insn.dst_reg());
        if diag.insn.src_reg() != diag.insn.dst_reg() {
            regs.push(diag.insn.src_reg());
        }
    }

    regs.iter()
        .map(|&idx| {
            // These are 4-bit instruction fields, so the failing instruction
            // may name a register that doesn't exist. That can be exactly why
            // it failed, so degrade instead of panicking.
            match diag.registers.get(idx as usize) {
                Some(state) => format!("r{idx} = {state:?}"),
                None => format!("r{idx} = <invalid register>"),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
