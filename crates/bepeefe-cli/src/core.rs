//! Listing CO-RE relocations from `.BTF.ext`.

use bepeefe::btf::{Btf, BtfTypeId, ext::CoreRelo};
use tabled::{
    Tabled,
    settings::{Alignment, Modify, object::Columns},
};

use crate::{render::render_type, table};

#[derive(Tabled)]
struct CoreReloRow {
    #[tabled(rename = "INSN")]
    insn: u32,
    #[tabled(rename = "KIND")]
    kind: &'static str,
    #[tabled(rename = "ACCESS")]
    access: String,
    #[tabled(rename = "TYPE")]
    ty: String,
}

pub fn list(btf: &Btf) {
    let sections: Vec<_> = btf
        .ext
        .core_relo
        .iter()
        .filter(|s| !s.data.is_empty())
        .collect();
    let total: usize = sections.iter().map(|s| s.data.len()).sum();
    if total == 0 {
        println!("(no CO-RE relocations)");
        return;
    }

    println!("{total} CO-RE relocations");
    for sec in sections {
        let name = btf.string(sec.sec_name_off).unwrap_or_default();
        let name = if name.is_empty() {
            "(anon)".into()
        } else {
            name
        };
        println!("\n{name}");

        let rows: Vec<CoreReloRow> = sec.data.iter().map(|r| core_relo_row(btf, r)).collect();
        let mut t = table(rows);
        t.with(Modify::new(Columns::one(0)).with(Alignment::right()));
        println!("{t}");
    }
}

fn core_relo_row(btf: &Btf, relo: &CoreRelo) -> CoreReloRow {
    let path = core_relo_path(btf, relo).unwrap_or_default();
    let path = if path.is_empty() {
        String::new()
    } else {
        format!("  {path}")
    };
    CoreReloRow {
        insn: relo.insn_off,
        kind: relo.kind.label(),
        access: btf
            .string(relo.access_str_off)
            .unwrap_or_default()
            .into_owned(),
        ty: format!(
            "{} (#{}){path}",
            render_type(btf, BtfTypeId(relo.type_id)),
            relo.type_id
        ),
    }
}

/// Human-readable target of a relocation: `.field.subfield`. For field access,
/// `::VARIANT` for an enum value, or empty for whole type relocations.
fn core_relo_path(btf: &Btf, relo: &CoreRelo) -> Option<String> {
    let access = btf.string(relo.access_str_off)?;
    let root = BtfTypeId(relo.type_id);
    if relo.kind.is_enum() {
        let idx: usize = access.split(':').next()?.parse().ok()?;
        return btf.enum_variant_name(root, idx).map(|v| format!("::{v}"));
    }
    if !relo.kind.is_field() {
        return None;
    }
    let access = btf.parse_access(root, &access).ok()?;
    (!access.is_empty()).then(|| access.to_string())
}
