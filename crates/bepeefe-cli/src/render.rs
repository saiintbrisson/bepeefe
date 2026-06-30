//! Rendering BTF types back into C declaration syntax.

use bepeefe::btf::{Btf, BtfKind, BtfTypeId};

pub fn render_type(btf: &Btf, id: BtfTypeId) -> String {
    let (l, r) = render_decl(btf, id);
    if r.is_empty() { l } else { format!("{l}{r}") }
}

pub fn render_decl(btf: &Btf, id: BtfTypeId) -> (String, String) {
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

pub fn target_id(k: &BtfKind) -> Option<BtfTypeId> {
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

pub fn kind_label(k: &BtfKind) -> &'static str {
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
