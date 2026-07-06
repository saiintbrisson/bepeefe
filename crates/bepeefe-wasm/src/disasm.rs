use bepeefe::{
    isa::dump::{self, InsnKind},
    object::EbpfProgram,
};
use wasm_bindgen::JsError;

use crate::js_err;

#[derive(serde::Serialize)]
struct Row {
    pc: usize,
    insn: Option<String>,
    source: Option<Source>,
}

#[derive(serde::Serialize)]
struct Source {
    line: u32,
    col: u32,
    source: String,
}

/// Disassemble a program to a JSON array of rows, one per instruction.
/// The second word of a `LdImm64` is emitted as an empty row so program
/// counters stay aligned with the instruction stream.
pub fn to_json(prog: &EbpfProgram) -> Result<String, JsError> {
    let btf = prog.btf();
    let insns = prog.insns();
    let mut rows = Vec::with_capacity(insns.len());
    let mut skip_next = false;

    for (pc, insn) in insns.iter().enumerate() {
        if skip_next {
            skip_next = false;
            rows.push(Row {
                pc,
                insn: None,
                source: None,
            });
            continue;
        }

        let next = insns.get(pc + 1).copied();
        let text = dump::disasm(*insn, next);
        let source = prog.line_info().get(&pc).and_then(|entry| {
            let src = btf.string(entry.line_off)?;
            Some(Source {
                line: entry.line_no,
                col: entry.column_no,
                source: src.to_string(),
            })
        });

        if matches!(dump::describe(insn.opcode()), InsnKind::LdImm64) {
            skip_next = true;
        }

        rows.push(Row {
            pc,
            insn: Some(text),
            source,
        });
    }

    serde_json::to_string(&rows).map_err(js_err)
}
