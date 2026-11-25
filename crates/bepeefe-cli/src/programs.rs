//! The `programs` subcommand. Listing, inspecting, and disassembling.

use std::sync::Arc;

use bepeefe::{
    EbpfObject,
    btf::Btf,
    capture::Capture,
    hook::{Attach, Hook},
    isa::Insn,
    object::FunctionSignature,
    verifier::VerifierConfig,
    vm::{MapReuseStrategy, Vm},
};
use tabled::Tabled;

use crate::{
    render::{render_decl, render_type},
    report, table,
    trace::{EventLines, TraceBuffer, TraceMode},
};

#[derive(Tabled)]
struct ProgRow {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "TYPE")]
    ty: String,
    #[tabled(rename = "TARGET")]
    target: String,
    #[tabled(rename = "SECTION")]
    section: String,
}

pub fn list(obj: &EbpfObject) {
    let rows: Vec<ProgRow> = obj
        .programs()
        .map(|p| {
            let sec = obj.section_name(p.section_idx).unwrap_or("?");
            let hook = Hook::parse(sec);
            ProgRow {
                name: p.name.clone(),
                ty: hook
                    .as_ref()
                    .map(|h| format!("{:?}", h.prog_type))
                    .unwrap_or_else(|| "-".into()),
                target: hook
                    .as_ref()
                    .and_then(|h| h.target.clone())
                    .unwrap_or_else(|| "-".into()),
                section: sec.into(),
            }
        })
        .collect();

    if rows.is_empty() {
        println!("(no global programs)");
        return;
    }
    println!("{}", table(rows));
    crate::hint(
        "next:  programs <name>        inspect one\n\
         \x20      programs <name> dump   disassemble (--src for source)",
    );
}

pub fn show(obj: &EbpfObject, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let prog = obj
        .functions()
        .iter()
        .find(|f| f.is_global && f.name == name)
        .ok_or_else(|| format!("program {name:?} not found"))?;
    print_function(obj.btf(), prog);
    let sec = obj.section_name(prog.section_idx).unwrap_or("?");
    println!("section:   {sec}");
    if let Some(h) = Hook::parse(sec) {
        println!("type:      {:?}", h.prog_type);
        if !matches!(h.attach, Attach::None) {
            println!("attach:    {:?}", h.attach);
        }
        if let Some(t) = &h.target {
            println!("target:    {t}");
        }
        if h.sleepable {
            println!("sleepable: true");
        }
        if h.frags {
            println!("frags:     true");
        }
    } else {
        println!("type:      (unparseable section)");
    }
    println!(
        "insns:     {} (section offset {})",
        prog.size / Insn::BYTES,
        prog.section_offset
    );
    crate::hint(&format!(
        "next:  programs {name} dump     disassemble (--src for source)\n\
         \x20      programs {name} verify   stream verifier events"
    ));
    Ok(())
}

pub fn disasm(obj: &EbpfObject, name: &str, src: bool) -> Result<(), Box<dyn std::error::Error>> {
    let prog = obj.load_prog(name)?;
    let insns = prog.insns();
    let subprogs = prog.subprogs();
    let lines = prog.line_info();

    let mut pc = 0;
    let mut last_line = None;
    while pc < insns.len() {
        if let Some(sp) = subprogs.get(&pc) {
            if pc > 0 {
                println!();
            }
            println!("{}:", sp.name);
        }
        if src
            && let Some(entry) = lines.get(&pc)
            && last_line.replace((entry.line_no, entry.line_off))
                != Some((entry.line_no, entry.line_off))
            && let Some(text) = obj.btf().string(entry.line_off)
            && !text.trim().is_empty()
        {
            println!("         ; {}: {}", entry.line_no, text.trim());
        }
        let insn = insns[pc];
        let next = insns.get(pc + 1).copied();
        let line = bepeefe::isa::dump::disasm(insn, next);
        println!("  {pc:5}:  {line}");
        pc += if insn.is_ld_imm64() { 2 } else { 1 };
    }
    Ok(())
}

pub fn verify(
    obj: &EbpfObject,
    name: &str,
    mode: TraceMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let prog = obj.load_prog(name)?;
    let vm = Vm::new();
    // Every mode but `all` buffers the stream instead of printing it, so a
    // failure can report only the part that led to it.
    let buffer = Arc::new(TraceBuffer::default());
    let capture: Arc<dyn Capture> = match mode {
        TraceMode::All => Arc::new(EventLines),
        _ => buffer.clone(),
    };
    let config = VerifierConfig {
        capture: Some(capture),
        ..Default::default()
    };
    if let Err(e) = vm.prepare(prog, MapReuseStrategy::None, &config) {
        eprint!("{}", report::render(&e));
        if let Some(diag) = e.diagnostic()
            && let Some(trace) = buffer.failure_trace(&e, mode)
        {
            eprint!("{}", report::render_trace(&diag, &trace));
        }
        std::process::exit(1);
    }
    Ok(())
}

fn print_function(btf: &Btf, f: &FunctionSignature) {
    let ret = match f.return_type {
        Some(id) => render_type(btf, id),
        None => "void".into(),
    };
    let params = if f.params_types.is_empty() {
        "void".into()
    } else {
        f.params_types
            .iter()
            .map(|(name, id)| {
                let (l, r) = render_decl(btf, *id);
                if name.is_empty() {
                    format!("{l}{r}")
                } else {
                    format!("{l} {name}{r}")
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let kind = if f.is_global { "global" } else { "static" };
    println!("{kind} {ret} {}({params});", f.name);
}
