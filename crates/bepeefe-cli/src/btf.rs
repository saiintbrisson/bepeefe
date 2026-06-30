//! The `btf` subcommand. Listing and inspecting BTF types.

use bepeefe::btf::{Btf, BtfKind, BtfType, BtfTypeId, StructMember};
use tabled::{
    Tabled,
    settings::{Alignment, Modify, object::Columns},
};

use crate::{
    render::{kind_label, render_type, target_id},
    table,
};

#[derive(Tabled)]
struct TypeRow {
    #[tabled(rename = "ID")]
    id: u32,
    #[tabled(rename = "KIND")]
    kind: &'static str,
    #[tabled(rename = "SIZE")]
    size: String,
    #[tabled(rename = "NAME")]
    name: String,
}

pub fn list(btf: &Btf, all: bool) {
    let mut rows: Vec<(BtfTypeId, TypeRow)> = Vec::new();
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
        let size = match btf.type_size(*id) {
            0 => String::new(),
            n => n.to_string(),
        };
        rows.push((
            *id,
            TypeRow {
                id: id.0,
                kind,
                size,
                name: display,
            },
        ));
    }
    if rows.is_empty() {
        println!("(no types)");
        return;
    }
    if all {
        rows.sort_by_key(|(id, _)| id.0);
    } else {
        rows.sort_by(|a, b| a.1.name.cmp(&b.1.name));
    }
    let shown = rows.len();

    let mut t = table(rows.into_iter().map(|(_, row)| row));
    t.with(Modify::new(Columns::one(0)).with(Alignment::right()));
    t.with(Modify::new(Columns::one(2)).with(Alignment::right()));
    println!("{t}");

    let mut body = String::from(
        "next:  btf <name|id>   inspect a type (--expand to expand members)\n\
         \x20      btf core        list CO-RE relocations",
    );
    let hidden = btf.types.len().saturating_sub(shown);
    if !all && hidden > 0 {
        body.push_str(&format!(
            "\n\n{hidden} more types hidden, run with --all to see them"
        ));
    }
    crate::hint(&body);
}

pub fn show(btf: &Btf, query: &str, expand: bool) -> Result<(), Box<dyn std::error::Error>> {
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
                            let (l, r) = crate::render::render_decl(btf, p.r#type);
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
    members: &[StructMember],
    indent: usize,
    expand: bool,
    in_stack: &mut Vec<BtfTypeId>,
) {
    for (idx, m) in members.iter().enumerate() {
        print_member(btf, m, idx, indent, expand, in_stack);
    }
}

fn print_member(
    btf: &Btf,
    m: &StructMember,
    idx: usize,
    indent: usize,
    expand: bool,
    in_stack: &mut Vec<BtfTypeId>,
) {
    let mname = btf.member_name(m, idx);
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
        let name_part = format!(" {mname}");
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

    let (l, r) = crate::render::render_decl(btf, m.r#type);
    println!("{pad}{l} {mname}{r}{suffix}");
}
