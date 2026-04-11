//! BPF/BTF inspector.

use std::{path::PathBuf, process::ExitCode};

use bepeefe::{
    EbpfObject,
    btf::{Btf, BtfKind, BtfType, BtfTypeId},
    hook::{Attach, Hook},
    isa::Insn,
    maps::*,
    object::FunctionSignature,
};
use clap::{Parser, Subcommand};

/// Inspect an eBPF object file.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Path to the eBPF .o file.
    file: PathBuf,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// List or inspect global programs.
    Programs {
        name: Option<String>,
        #[command(subcommand)]
        action: Option<ProgAction>,
    },
    /// List or inspect maps.
    Maps { name: Option<String> },
    /// List or inspect BTF types.
    Btf {
        /// Type name or numeric id.
        query: Option<String>,
        /// Expand nested structs/unions/enums. Pointers are not followed.
        #[arg(short, long)]
        expand: bool,
        /// When listing, include every type.
        #[arg(short, long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum ProgAction {
    /// Disassemble the program's instructions.
    Dump,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(&cli.file)?;
    let obj = EbpfObject::from_elf(&bytes)?;

    match cli.command {
        None => overview(&obj),
        Some(Cmd::Programs { name: None, .. }) => list_programs(&obj),
        Some(Cmd::Programs {
            name: Some(n),
            action: None,
        }) => show_program(&obj, &n)?,
        Some(Cmd::Programs {
            name: Some(n),
            action: Some(ProgAction::Dump),
        }) => show_disasm(&obj, &n)?,
        Some(Cmd::Maps { name: None }) => list_maps(&obj),
        Some(Cmd::Maps { name: Some(n) }) => show_map(&obj, &n)?,
        Some(Cmd::Btf {
            query: None, all, ..
        }) => list_btf(obj.btf(), all),
        Some(Cmd::Btf {
            query: Some(q),
            expand,
            ..
        }) => show_btf(obj.btf(), &q, expand)?,
    }
    Ok(())
}

fn overview(obj: &EbpfObject) {
    println!("license:   {}", obj.license().unwrap_or("?"));
    println!("programs:  {}", obj.programs().count());
    println!("functions: {}", obj.functions().len());
    println!("maps:      {}", obj.maps().len());
    println!("btf types: {}", obj.btf().types.len());
}

fn list_programs(obj: &EbpfObject) {
    let progs: Vec<_> = obj.programs().collect();
    if progs.is_empty() {
        println!("(no global programs)");
        return;
    }
    let rows: Vec<_> = progs
        .iter()
        .map(|p| {
            let sec = obj.section_name(p.section_idx).unwrap_or("?");
            let hook = Hook::parse(sec);
            let ty = hook
                .as_ref()
                .map(|h| format!("{:?}", h.prog_type))
                .unwrap_or_else(|| "-".into());
            let target = hook
                .as_ref()
                .and_then(|h| h.target.clone())
                .unwrap_or_else(|| "-".into());
            (p.name.clone(), ty, target, sec)
        })
        .collect();

    let name_w = rows.iter().map(|r| r.0.len()).max().unwrap_or(0).max(4);
    let ty_w = rows.iter().map(|r| r.1.len()).max().unwrap_or(0).max(4);
    let target_w = rows.iter().map(|r| r.2.len()).max().unwrap_or(0).max(6);

    println!(
        "{:name_w$}  {:ty_w$}  {:target_w$}  SECTION",
        "NAME", "TYPE", "TARGET"
    );
    for (n, t, target, sec) in rows {
        println!("{n:name_w$}  {t:ty_w$}  {target:target_w$}  {sec}");
    }
}

fn show_program(obj: &EbpfObject, name: &str) -> Result<(), Box<dyn std::error::Error>> {
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
        prog.size / Insn::WIDTH,
        prog.section_offset
    );
    Ok(())
}

fn show_disasm(obj: &EbpfObject, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let prog = obj.load_prog(name)?;
    let insns = prog.insns();
    let subprogs = prog.subprogs();

    let mut pc = 0;
    while pc < insns.len() {
        if let Some(sp) = subprogs.get(&pc) {
            if pc > 0 {
                println!();
            }
            println!("{}:", sp.name);
        }
        let insn = insns[pc];
        let next = insns.get(pc + 1).copied();
        let line = bepeefe::isa::dump::disasm(insn, next);
        println!("  {pc:5}:  {line}");
        pc += if insn.is_ld_imm64() { 2 } else { 1 };
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

fn list_maps(obj: &EbpfObject) {
    let maps = obj.maps();
    if maps.is_empty() {
        println!("(no maps)");
        return;
    }
    let name_w = maps.iter().map(|m| m.name.len()).max().unwrap_or(0).max(4);
    let type_w = 24usize;
    println!(
        "{:name_w$}  {:type_w$}  ENTRIES  KEY -> VALUE",
        "NAME", "TYPE"
    );
    for m in maps {
        let ty = m.r#type.map(map_type_name).unwrap_or("UNKNOWN");
        let entries = m
            .max_entries
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".into());
        let key = m.key.map(|k| render_type(obj.btf(), k)).unwrap_or_else(|| {
            m.key_size
                .map(|s| format!("[{s} bytes]"))
                .unwrap_or_else(|| "?".into())
        });
        let val = m
            .value
            .map(|v| render_type(obj.btf(), v))
            .unwrap_or_else(|| {
                m.value_size
                    .map(|s| format!("[{s} bytes]"))
                    .unwrap_or_else(|| "?".into())
            });
        let key_id = m
            .key
            .map(|k| format!("#{}", k.0))
            .unwrap_or_else(|| "?".into());
        let val_id = m
            .value
            .map(|v| format!("#{}", v.0))
            .unwrap_or_else(|| "?".into());
        println!(
            "{:name_w$}  {ty:type_w$}  {entries:>7}  {key} -> {val}  /* {key_id} -> {val_id} */",
            m.name
        );
    }
}

fn show_map(obj: &EbpfObject, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let map = obj
        .maps()
        .iter()
        .find(|m| m.name == name)
        .ok_or_else(|| format!("map {name:?} not found"))?;

    println!("name:        {}", map.name);
    println!(
        "type:        {}",
        map.r#type.map(map_type_name).unwrap_or("UNKNOWN")
    );
    if let Some(n) = map.max_entries {
        println!("max_entries: {n}");
    }
    if let Some(s) = map.key_size {
        println!("key_size:    {s}");
    }
    if let Some(s) = map.value_size {
        println!("value_size:  {s}");
    }
    if let Some(id) = map.key {
        println!("key:         {}  (#{})", render_type(obj.btf(), id), id.0);
    }
    if let Some(id) = map.value {
        println!("value:       {}  (#{})", render_type(obj.btf(), id), id.0);
    }
    if matches!(map.pinning, bepeefe::maps::MapPinning::ByName) {
        println!("pinning:     by_name");
    }
    if let Some(data) = &map.initial_data {
        println!("initial:     {} bytes", data.len());
    }
    Ok(())
}

fn list_btf(btf: &Btf, all: bool) {
    let mut rows: Vec<(BtfTypeId, &'static str, String)> = Vec::new();
    for (id, ty) in &btf.types {
        let name = btf.string(ty.name_off).unwrap_or_default();
        let kind = if all {
            kind_label(&ty.kind)
        } else {
            match &ty.kind {
                BtfKind::Struct(_) => "struct",
                BtfKind::Union(_) => "union",
                BtfKind::Enum(_) | BtfKind::Enum64(_) => "enum",
                BtfKind::Typedef(_) => "typedef",
                BtfKind::Func(_) => "func",
                _ => continue,
            }
        };
        if !all && name.is_empty() {
            continue;
        }
        let display = if matches!(ty.kind, BtfKind::Func(_)) {
            render_type(btf, *id)
        } else if name.is_empty() {
            "(anon)".into()
        } else {
            name.into_owned()
        };
        rows.push((*id, kind, display));
    }
    if rows.is_empty() {
        println!("(no types)");
        return;
    }
    if all {
        rows.sort_by_key(|r| r.0.0);
    } else {
        rows.sort_by(|a, b| a.2.cmp(&b.2));
    }
    let kind_w = rows.iter().map(|(_, k, _)| k.len()).max().unwrap_or(0);
    let shown = rows.len();
    println!("{:>5}  {:kind_w$}  NAME", "ID", "KIND");
    for (id, kind, name) in rows {
        println!("{:>5}  {kind:kind_w$}  {name}", id.0);
    }
    let hidden = btf.types.len().saturating_sub(shown);
    if !all && hidden > 0 {
        println!("\n... {hidden} more types hidden, run with --all to see them");
    }
}

fn show_btf(btf: &Btf, query: &str, expand: bool) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(n) = query.parse::<u32>() {
        let id = BtfTypeId(n);
        if let Some(ty) = btf.types.get(&id) {
            print_btf_type(btf, id, ty, expand);
            return Ok(());
        }
        return Err(format!("no BTF type with id {n}").into());
    }

    let matches: Vec<_> = btf
        .types
        .iter()
        .filter(|(_, ty)| btf.string(ty.name_off).is_some_and(|n| n == query))
        .collect();

    match matches.len() {
        0 => Err(format!("no BTF type named {query:?}").into()),
        1 => {
            print_btf_type(btf, *matches[0].0, matches[0].1, expand);
            Ok(())
        }
        _ => {
            println!("{} types named {query:?}:", matches.len());
            for (id, ty) in &matches {
                println!("  #{}  {}", id.0, kind_label(&ty.kind));
            }
            println!("disambiguate with: cli <file> btf <id>");
            Ok(())
        }
    }
}

fn print_btf_type(btf: &Btf, id: BtfTypeId, ty: &BtfType, expand: bool) {
    let name = btf.string(ty.name_off).unwrap_or_default();
    println!("#{}", id.0);
    let mut in_stack = vec![id];
    match &ty.kind {
        BtfKind::Struct(s) => {
            let n = if name.is_empty() {
                "(anon)".into()
            } else {
                name
            };
            println!("struct {n} {{ /* size {} */", s.size);
            print_members(btf, &s.members, 4, expand, &mut in_stack);
            println!("}};");
        }
        BtfKind::Union(u) => {
            let n = if name.is_empty() {
                "(anon)".into()
            } else {
                name
            };
            println!("union {n} {{ /* size {} */", u.size);
            print_members(btf, &u.members, 4, expand, &mut in_stack);
            println!("}};");
        }
        BtfKind::Enum(e) => {
            let n = if name.is_empty() {
                "(anon)".into()
            } else {
                name
            };
            let sign = if e.signed { "signed" } else { "unsigned" };
            println!("enum {n} {{ /* size {}, {sign} */", e.size);
            for v in &e.values {
                let vn = btf.string(v.name_off).unwrap_or_default();
                println!("    {vn} = {},", v.val);
            }
            println!("}};");
        }
        BtfKind::Enum64(e) => {
            let n = if name.is_empty() {
                "(anon)".into()
            } else {
                name
            };
            let sign = if e.signed { "signed" } else { "unsigned" };
            println!("enum {n} {{ /* size {}, {sign}, 64-bit */", e.size);
            for v in &e.values {
                let vn = btf.string(v.name_off).unwrap_or_default();
                let val = ((v.val_hi32 as u64) << 32) | v.val_lo32 as u64;
                println!("    {vn} = {val},");
            }
            println!("}};");
        }
        BtfKind::Typedef(target) => {
            let target_str = render_type(btf, *target);
            println!("typedef {target_str} {name};  /* -> #{} */", target.0);
        }
        BtfKind::Func(f) => {
            if let Some(p) = btf.types.get(&f.func_proto)
                && let BtfKind::FuncProto(fp) = &p.kind
            {
                let ret = render_type(btf, fp.return_type);
                let params = if fp.params.is_empty() {
                    "void".into()
                } else {
                    fp.params
                        .iter()
                        .map(|p| {
                            let (l, r) = render_decl(btf, p.r#type);
                            let pn = btf.string(p.name_off).unwrap_or_default();
                            if pn.is_empty() {
                                format!("{l}{r}")
                            } else {
                                format!("{l} {pn}{r}")
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                println!("{ret} {name}({params});");
            } else {
                println!("func {name};  /* unresolved proto */");
            }
        }
        _ => {
            let decl = render_type(btf, id);
            let label = kind_label(&ty.kind);
            let target = target_id(&ty.kind)
                .map(|t| format!("  /* -> #{} */", t.0))
                .unwrap_or_default();
            if name.is_empty() {
                println!("{label}: {decl}{target}");
            } else {
                println!("{label} {name}: {decl}{target}");
            }
        }
    }
}

fn print_members(
    btf: &Btf,
    members: &[bepeefe::btf::StructMember],
    indent: usize,
    expand: bool,
    in_stack: &mut Vec<BtfTypeId>,
) {
    for m in members {
        print_member(btf, m, indent, expand, in_stack);
    }
}

fn print_member(
    btf: &Btf,
    m: &bepeefe::btf::StructMember,
    indent: usize,
    expand: bool,
    in_stack: &mut Vec<BtfTypeId>,
) {
    let mname = btf.string(m.name_off).unwrap_or_default();
    let pad = " ".repeat(indent);
    let bit_off = m.offset;
    let byte_off = bit_off / 8;
    let bit_in_byte = bit_off % 8;
    let bf = match m.bitfield_size {
        Some(n) if n > 0 => format!(" : {n}"),
        _ => String::new(),
    };
    let off_str = if bit_in_byte == 0 {
        format!("offset {byte_off}")
    } else {
        format!("offset {byte_off}+{bit_in_byte}b")
    };
    let size = btf.type_size(m.r#type);
    let suffix = format!("{bf};  /* {off_str}, size {size}, type #{} */", m.r#type.0);

    if expand
        && let Some(ty) = btf.get_type(m.r#type)
        && !in_stack.contains(&ty.btf_id)
    {
        let tn = btf.string(ty.name_off).unwrap_or_default();
        let tn_str = if tn.is_empty() { "(anon)" } else { tn.as_ref() };
        let name_part = if mname.is_empty() {
            String::new()
        } else {
            format!(" {mname}")
        };
        match &ty.kind {
            BtfKind::Struct(s) => {
                println!("{pad}struct {tn_str} {{ /* size {} */", s.size);
                in_stack.push(ty.btf_id);
                print_members(btf, &s.members, indent + 4, expand, in_stack);
                in_stack.pop();
                println!("{pad}}}{name_part}{suffix}");
                return;
            }
            BtfKind::Union(u) => {
                println!("{pad}union {tn_str} {{ /* size {} */", u.size);
                in_stack.push(ty.btf_id);
                print_members(btf, &u.members, indent + 4, expand, in_stack);
                in_stack.pop();
                println!("{pad}}}{name_part}{suffix}");
                return;
            }
            BtfKind::Enum(e) => {
                let sign = if e.signed { "signed" } else { "unsigned" };
                println!("{pad}enum {tn_str} {{ /* size {}, {sign} */", e.size);
                for v in &e.values {
                    let vn = btf.string(v.name_off).unwrap_or_default();
                    println!("{pad}    {vn} = {},", v.val);
                }
                println!("{pad}}}{name_part}{suffix}");
                return;
            }
            BtfKind::Enum64(e) => {
                let sign = if e.signed { "signed" } else { "unsigned" };
                println!(
                    "{pad}enum {tn_str} {{ /* size {}, {sign}, 64-bit */",
                    e.size
                );
                for v in &e.values {
                    let vn = btf.string(v.name_off).unwrap_or_default();
                    let val = ((v.val_hi32 as u64) << 32) | v.val_lo32 as u64;
                    println!("{pad}    {vn} = {val},");
                }
                println!("{pad}}}{name_part}{suffix}");
                return;
            }
            _ => {}
        }
    }

    let (l, r) = render_decl(btf, m.r#type);
    if mname.is_empty() {
        println!("{pad}{l}{r}{suffix}");
    } else {
        println!("{pad}{l} {mname}{r}{suffix}");
    }
}

fn render_type(btf: &Btf, id: BtfTypeId) -> String {
    let (l, r) = render_decl(btf, id);
    if r.is_empty() { l } else { format!("{l}{r}") }
}

fn render_decl(btf: &Btf, id: BtfTypeId) -> (String, String) {
    let mut left = String::new();
    let mut right = String::new();
    write_decl(btf, id, &mut left, &mut right);
    (left, right)
}

fn write_decl(btf: &Btf, id: BtfTypeId, left: &mut String, right: &mut String) {
    if id.0 == 0 {
        left.push_str("void");
        return;
    }
    let Some(ty) = btf.types.get(&id) else {
        left.push_str(&format!("<unknown #{}>", id.0));
        return;
    };
    let name = btf.string(ty.name_off).unwrap_or_default();
    match &ty.kind {
        BtfKind::Int(_) | BtfKind::Float(_) | BtfKind::Typedef(_) => left.push_str(&name),
        BtfKind::Struct(_) => {
            left.push_str("struct ");
            left.push_str(if name.is_empty() {
                "(anon)"
            } else {
                name.as_ref()
            });
        }
        BtfKind::Union(_) => {
            left.push_str("union ");
            left.push_str(if name.is_empty() {
                "(anon)"
            } else {
                name.as_ref()
            });
        }
        BtfKind::Enum(_) | BtfKind::Enum64(_) => {
            left.push_str("enum ");
            left.push_str(if name.is_empty() {
                "(anon)"
            } else {
                name.as_ref()
            });
        }
        BtfKind::Fwd(fwd) => {
            left.push_str(if fwd.kind_flag { "union " } else { "struct " });
            left.push_str(&name);
        }
        BtfKind::Const(t) => {
            write_decl(btf, *t, left, right);
            left.insert_str(0, "const ");
        }
        BtfKind::Volatile(t) => {
            write_decl(btf, *t, left, right);
            left.insert_str(0, "volatile ");
        }
        BtfKind::Restrict(t) => {
            write_decl(btf, *t, left, right);
            left.insert_str(0, "restrict ");
        }
        BtfKind::TypeTag(t) => write_decl(btf, *t, left, right),
        BtfKind::Ptr(t) => {
            write_decl(btf, *t, left, right);
            let pointee_needs_parens = matches!(
                btf.types.get(t).map(|x| &x.kind),
                Some(BtfKind::Array(_) | BtfKind::FuncProto(_))
            );
            if pointee_needs_parens {
                left.push_str(" (*");
                right.insert(0, ')');
            } else {
                left.push_str(" *");
            }
        }
        BtfKind::Array(arr) => {
            write_decl(btf, arr.r#type, left, right);
            right.insert_str(0, &format!("[{}]", arr.no_elems));
        }
        BtfKind::FuncProto(p) => {
            write_decl(btf, p.return_type, left, right);
            let params = if p.params.is_empty() {
                "void".into()
            } else {
                p.params
                    .iter()
                    .map(|param| {
                        let (l2, r2) = render_decl(btf, param.r#type);
                        let pn = btf.string(param.name_off).unwrap_or_default();
                        if pn.is_empty() {
                            format!("{l2}{r2}")
                        } else {
                            format!("{l2} {pn}{r2}")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            right.insert_str(0, &format!("({params})"));
        }
        BtfKind::Func(f) => {
            write_decl(btf, f.func_proto, left, right);
            if !name.is_empty() {
                left.push(' ');
                left.push_str(&name);
            }
        }
        BtfKind::Var(v) => {
            write_decl(btf, v.ty, left, right);
            if !name.is_empty() {
                left.push(' ');
                left.push_str(&name);
            }
        }
        BtfKind::Datasec(_) => {
            left.push_str("datasec ");
            left.push_str(&name);
        }
        BtfKind::DeclTag => left.push_str("<decl_tag>"),
    }
}

fn target_id(k: &BtfKind) -> Option<BtfTypeId> {
    match k {
        BtfKind::Ptr(id)
        | BtfKind::Volatile(id)
        | BtfKind::Const(id)
        | BtfKind::Restrict(id)
        | BtfKind::TypeTag(id)
        | BtfKind::Typedef(id) => Some(*id),
        BtfKind::Var(v) => Some(v.ty),
        BtfKind::Array(a) => Some(a.r#type),
        BtfKind::Func(f) => Some(f.func_proto),
        _ => None,
    }
}

fn kind_label(k: &BtfKind) -> &'static str {
    match k {
        BtfKind::Int(_) => "int",
        BtfKind::Ptr(_) => "ptr",
        BtfKind::Array(_) => "array",
        BtfKind::Struct(_) => "struct",
        BtfKind::Union(_) => "union",
        BtfKind::Enum(_) => "enum",
        BtfKind::Fwd(_) => "fwd",
        BtfKind::Typedef(_) => "typedef",
        BtfKind::Volatile(_) => "volatile",
        BtfKind::Const(_) => "const",
        BtfKind::Restrict(_) => "restrict",
        BtfKind::Func(_) => "func",
        BtfKind::FuncProto(_) => "func_proto",
        BtfKind::Var(_) => "var",
        BtfKind::Datasec(_) => "datasec",
        BtfKind::Float(_) => "float",
        BtfKind::DeclTag => "decl_tag",
        BtfKind::TypeTag(_) => "type_tag",
        BtfKind::Enum64(_) => "enum64",
    }
}

fn map_type_name(t: u32) -> &'static str {
    match t {
        BPF_MAP_TYPE_UNSPEC => "UNSPEC",
        BPF_MAP_TYPE_HASH => "HASH",
        BPF_MAP_TYPE_ARRAY => "ARRAY",
        BPF_MAP_TYPE_PROG_ARRAY => "PROG_ARRAY",
        BPF_MAP_TYPE_PERF_EVENT_ARRAY => "PERF_EVENT_ARRAY",
        BPF_MAP_TYPE_PERCPU_HASH => "PERCPU_HASH",
        BPF_MAP_TYPE_PERCPU_ARRAY => "PERCPU_ARRAY",
        BPF_MAP_TYPE_STACK_TRACE => "STACK_TRACE",
        BPF_MAP_TYPE_CGROUP_ARRAY => "CGROUP_ARRAY",
        BPF_MAP_TYPE_LRU_HASH => "LRU_HASH",
        BPF_MAP_TYPE_LRU_PERCPU_HASH => "LRU_PERCPU_HASH",
        BPF_MAP_TYPE_LPM_TRIE => "LPM_TRIE",
        BPF_MAP_TYPE_ARRAY_OF_MAPS => "ARRAY_OF_MAPS",
        BPF_MAP_TYPE_HASH_OF_MAPS => "HASH_OF_MAPS",
        BPF_MAP_TYPE_DEVMAP => "DEVMAP",
        BPF_MAP_TYPE_SOCKMAP => "SOCKMAP",
        BPF_MAP_TYPE_CPUMAP => "CPUMAP",
        BPF_MAP_TYPE_XSKMAP => "XSKMAP",
        BPF_MAP_TYPE_SOCKHASH => "SOCKHASH",
        BPF_MAP_TYPE_CGROUP_STORAGE => "CGROUP_STORAGE",
        BPF_MAP_TYPE_REUSEPORT_SOCKARRAY => "REUSEPORT_SOCKARRAY",
        BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE => "PERCPU_CGROUP_STORAGE",
        BPF_MAP_TYPE_QUEUE => "QUEUE",
        BPF_MAP_TYPE_STACK => "STACK",
        BPF_MAP_TYPE_SK_STORAGE => "SK_STORAGE",
        BPF_MAP_TYPE_DEVMAP_HASH => "DEVMAP_HASH",
        BPF_MAP_TYPE_STRUCT_OPS => "STRUCT_OPS",
        BPF_MAP_TYPE_RINGBUF => "RINGBUF",
        BPF_MAP_TYPE_INODE_STORAGE => "INODE_STORAGE",
        BPF_MAP_TYPE_TASK_STORAGE => "TASK_STORAGE",
        BPF_MAP_TYPE_BLOOM_FILTER => "BLOOM_FILTER",
        BPF_MAP_TYPE_USER_RINGBUF => "USER_RINGBUF",
        BPF_MAP_TYPE_CGRP_STORAGE => "CGRP_STORAGE",
        _ => "UNKNOWN",
    }
}
