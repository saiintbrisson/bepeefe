use std::collections::HashSet;

use bepeefe::btf::{Btf, BtfKind, BtfTypeId, StructMember};
use indexmap::IndexMap;

const BTF_INT_SIGNED: u8 = 1 << 0;
const BTF_INT_CHAR: u8 = 1 << 1;
const BTF_INT_BOOL: u8 = 1 << 2;

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct JsonSchema {
    /// BTF id of the type this node describes, after stripping pointers and
    /// typedefs. Consumers link recursive stubs and shared types back to their
    /// definition through this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_id: Option<u32>,

    /// JSON Schema type of the value, absent on enum variant stubs.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub schema_type: Option<JsonSchemaType>,

    /// Human readable name, usually the type or typedef name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Short note on the underlying representation, such as `u32` or `char`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Smallest value the integer can hold, set for widths up to 32 bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,

    /// Largest value the integer can hold, set for widths up to 32 bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<f64>,

    /// Enum values or union variants, each as a `const` or nested schema.
    #[serde(rename = "oneOf", skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<JsonSchemaVariant>>,

    /// Struct members keyed by field name, in declaration order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<IndexMap<String, JsonSchema>>,

    /// Names of properties that must be present, always every struct member.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,

    /// Schema for each element of an array type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<JsonSchema>>,

    /// Fixed length of the array, equal to `max_items`.
    #[serde(rename = "minItems", skip_serializing_if = "Option::is_none")]
    pub min_items: Option<u32>,

    /// Fixed length of the array, equal to `min_items`.
    #[serde(rename = "maxItems", skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u32>,

    /// Number of pointer indirections stripped to reach this type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<u32>,

    /// Set when the object is a union rather than a struct.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub union: Option<bool>,

    /// Name of the union member this variant came from, if it had one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,

    /// Bit offset of this member from the start of its parent struct or union.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_offset: Option<u32>,

    /// Width in bits of a bitfield member. Absent on plain members.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u32>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JsonSchemaType {
    Boolean,
    Integer,
    Number,
    Object,
    Array,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct JsonSchemaVariant {
    #[serde(rename = "const", skip_serializing_if = "Option::is_none")]
    pub const_value: Option<i64>,
    pub title: String,
    #[serde(flatten)]
    pub schema: JsonSchema,
}

pub fn type_to_schema(type_id: BtfTypeId, btf: &Btf) -> JsonSchema {
    let mut seen = HashSet::new();
    walk(type_id, btf, &mut seen)
}

fn walk(type_id: BtfTypeId, btf: &Btf, seen: &mut HashSet<BtfTypeId>) -> JsonSchema {
    let mut ptr_depth: u32 = 0;
    let mut walk_id = type_id;
    let mut typedef_name: Option<String> = None;
    while let Some(ty) = btf.types.get(&walk_id) {
        match &ty.kind {
            BtfKind::Ptr(inner) => {
                ptr_depth += 1;
                walk_id = *inner;
            }
            BtfKind::Typedef(inner) => {
                typedef_name = typedef_name.or_else(|| named(btf, ty.name_off));
                walk_id = *inner;
            }
            BtfKind::Const(inner)
            | BtfKind::Volatile(inner)
            | BtfKind::Restrict(inner)
            | BtfKind::TypeTag(inner) => {
                walk_id = *inner;
            }
            _ => break,
        }
    }

    let resolved = btf.types.get(&walk_id);
    let has_type = resolved.is_some();
    let node_title = typedef_name.or_else(|| resolved.and_then(|t| named(btf, t.name_off)));
    let finish = |mut s: JsonSchema| -> JsonSchema {
        if ptr_depth > 0 {
            s.pointer = Some(ptr_depth);
        }
        if has_type {
            s.type_id = Some(walk_id.0);
        }
        if s.title.is_none() {
            s.title = node_title.clone();
        }
        s
    };

    let Some(ty) = resolved else {
        return finish(JsonSchema {
            schema_type: Some(JsonSchemaType::Integer),
            description: Some("void".into()),
            ..Default::default()
        });
    };

    let schema = match &ty.kind {
        BtfKind::DeclTag => JsonSchema {
            schema_type: Some(JsonSchemaType::Integer),
            ..Default::default()
        },

        BtfKind::Int(int) => int_schema(int.encoding, int.bits),

        BtfKind::Float(f) => JsonSchema {
            schema_type: Some(JsonSchemaType::Number),
            description: Some(format!("f{}", f.size * 8)),
            ..Default::default()
        },

        BtfKind::Enum(e) => {
            let variants = e.values.iter().map(|v| (v.name_off, i64::from(v.val)));
            enum_schema(variants, btf)
        }

        BtfKind::Enum64(e) => {
            let variants = e.values.iter().map(|v| {
                let val = ((u64::from(v.val_hi32) << 32) | u64::from(v.val_lo32)) as i64;
                (v.name_off, val)
            });
            enum_schema(variants, btf)
        }

        BtfKind::Struct(_) if seen.contains(&walk_id) => recursive_stub(false),

        BtfKind::Struct(s) => {
            seen.insert(walk_id);
            let properties: IndexMap<String, JsonSchema> = s
                .members
                .iter()
                .enumerate()
                .map(|(idx, member)| {
                    let key = btf.member_name(member, idx).into_owned();
                    (key, member_schema(member, btf, seen))
                })
                .collect();
            seen.remove(&walk_id);

            let required = properties.keys().cloned().collect();
            JsonSchema {
                schema_type: Some(JsonSchemaType::Object),
                properties: Some(properties),
                required: Some(required),
                ..Default::default()
            }
        }

        BtfKind::Union(_) if seen.contains(&walk_id) => recursive_stub(true),

        BtfKind::Union(u) => {
            seen.insert(walk_id);
            let variants = u
                .members
                .iter()
                .enumerate()
                .map(|(idx, member)| {
                    let mut sub = member_schema(member, btf, seen);
                    let title = match named(btf, member.name_off) {
                        Some(name) => {
                            sub.member = Some(name.clone());
                            name
                        }
                        None => anon_variant_label(&sub, idx),
                    };
                    JsonSchemaVariant {
                        const_value: None,
                        title,
                        schema: sub,
                    }
                })
                .collect();
            seen.remove(&walk_id);

            JsonSchema {
                schema_type: Some(JsonSchemaType::Object),
                union: Some(true),
                one_of: Some(variants),
                ..Default::default()
            }
        }

        BtfKind::Array(a) => JsonSchema {
            schema_type: Some(JsonSchemaType::Array),
            items: Some(Box::new(walk(a.r#type, btf, seen))),
            min_items: Some(a.no_elems),
            max_items: Some(a.no_elems),
            ..Default::default()
        },

        _ => JsonSchema {
            schema_type: Some(JsonSchemaType::Integer),
            ..Default::default()
        },
    };

    finish(schema)
}

fn int_schema(encoding: u8, bits: u8) -> JsonSchema {
    if encoding & BTF_INT_BOOL != 0 {
        return JsonSchema {
            schema_type: Some(JsonSchemaType::Boolean),
            description: Some("bool".into()),
            ..Default::default()
        };
    }

    let signed = (encoding & BTF_INT_SIGNED) != 0;
    let bits = u32::from(bits);
    let mut schema = JsonSchema {
        schema_type: Some(JsonSchemaType::Integer),
        ..Default::default()
    };
    if encoding & BTF_INT_CHAR != 0 {
        schema.description = Some("char".into());
    } else if bits.is_multiple_of(8) && (8..=64).contains(&bits) {
        schema.description = Some(format!("{}{bits}", if signed { 'i' } else { 'u' }));
    } else if let Some((min, max)) = int_bounds(signed, bits) {
        schema.description = Some(format!("< {min}, {max} >"));
    }
    if bits <= 32
        && let Some((min, max)) = int_bounds(signed, bits)
    {
        schema.minimum = Some(min as f64);
        schema.maximum = Some(max as f64);
    }
    schema
}

/// Resolves a BTF string offset, treating the empty string as absent.
fn named(btf: &Btf, off: u32) -> Option<String> {
    btf.string(off)
        .map(|c| c.into_owned())
        .filter(|s| !s.is_empty())
}

/// Placeholder for a struct or union already on the walk stack, breaking the
/// cycle. The link to the full definition survives through `type_id`.
fn recursive_stub(union: bool) -> JsonSchema {
    if union {
        JsonSchema {
            schema_type: Some(JsonSchemaType::Object),
            union: Some(true),
            ..Default::default()
        }
    } else {
        JsonSchema {
            schema_type: Some(JsonSchemaType::Object),
            properties: Some(IndexMap::new()),
            required: Some(Vec::new()),
            ..Default::default()
        }
    }
}

fn member_schema(member: &StructMember, btf: &Btf, seen: &mut HashSet<BtfTypeId>) -> JsonSchema {
    let mut sub = walk(member.r#type, btf, seen);
    sub.bit_offset = Some(member.offset);
    sub.bits = bitfield_width(member.bitfield_size);
    sub
}

fn enum_schema(variants: impl Iterator<Item = (u32, i64)>, btf: &Btf) -> JsonSchema {
    JsonSchema {
        schema_type: Some(JsonSchemaType::Integer),
        one_of: Some(
            variants
                .map(|(name_off, val)| JsonSchemaVariant {
                    const_value: Some(val),
                    title: named(btf, name_off).unwrap_or_default(),
                    schema: JsonSchema::default(),
                })
                .collect(),
        ),
        ..Default::default()
    }
}

/// A `Some(width)` only when the member is an actual bitfield. Plain members
/// leave `bitfield_size` as `None` or zero.
fn bitfield_width(bitfield_size: Option<u32>) -> Option<u32> {
    bitfield_size.filter(|&b| b > 0)
}

fn int_bounds(signed: bool, bits: u32) -> Option<(i64, i64)> {
    if !(1..=63).contains(&bits) {
        return None;
    }
    if signed {
        let half = 1_i64 << (bits - 1);
        Some((-half, half - 1))
    } else {
        Some((0, (1_i64 << bits) - 1))
    }
}

fn anon_variant_label(schema: &JsonSchema, idx: usize) -> String {
    if let Some(t) = &schema.title {
        return t.clone();
    }
    if let Some(props) = &schema.properties
        && let Some(first) = props.keys().next()
    {
        return format!("via {first}");
    }
    format!("_{idx}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bepeefe::btf::BtfBuilder;
    use serde_json::json;

    fn schema_json(id: BtfTypeId, btf: &Btf) -> serde_json::Value {
        serde_json::to_value(type_to_schema(id, btf)).unwrap()
    }

    #[test]
    fn typedef_alias_wins_over_underlying_name() {
        let mut b = BtfBuilder::default();
        let int = b.add_int("int", 4, BTF_INT_SIGNED);
        let pid_t = b.add_typedef("pid_t", int);
        let btf = b.build();

        let v = schema_json(pid_t, &btf);
        assert_eq!(v["title"], "pid_t");
        assert_eq!(v["description"], "i32");
        assert_eq!(v["type"], "integer");
        assert_eq!(v["minimum"].as_f64(), Some(i32::MIN as f64));
        assert_eq!(v["type_id"], json!(int.0));
    }

    #[test]
    fn named_primitives_ship_their_title() {
        let mut b = BtfBuilder::default();
        let u32t = b.add_int("u32", 4, 0);
        let double = b.add_float("double", 8);
        let btf = b.build();

        assert_eq!(schema_json(u32t, &btf)["title"], "u32");
        assert_eq!(schema_json(double, &btf)["title"], "double");
    }

    #[test]
    fn bool_and_char_encodings() {
        let mut b = BtfBuilder::default();
        let boolt = b.add_int("_Bool", 1, BTF_INT_BOOL);
        let chart = b.add_int("char", 1, BTF_INT_CHAR);
        let btf = b.build();

        let bv = schema_json(boolt, &btf);
        assert_eq!(bv["type"], "boolean");
        assert_eq!(bv["description"], "bool");

        let cv = schema_json(chart, &btf);
        assert_eq!(cv["type"], "integer");
        assert_eq!(cv["description"], "char");
    }

    #[test]
    fn enum_ships_name_and_variants() {
        let mut b = BtfBuilder::default();
        let e = b.make_enum("tcp_state", 4, false, |e| {
            e.value("Established", 1).value("Close", 7);
        });
        let btf = b.build();

        let v = schema_json(e, &btf);
        assert_eq!(v["title"], "tcp_state");
        assert_eq!(v["type"], "integer");
        assert_eq!(v["oneOf"][0]["const"], json!(1));
        assert_eq!(v["oneOf"][0]["title"], "Established");
        assert_eq!(v["oneOf"][1]["const"], json!(7));
    }

    #[test]
    fn enum64_keeps_high_bits() {
        let big = 1_i64 << 33;
        let mut b = BtfBuilder::default();
        let e = b.make_enum64("big", 8, false, |e| {
            e.value("Huge", big);
        });
        let btf = b.build();

        let v = schema_json(e, &btf);
        assert_eq!(v["oneOf"][0]["const"].as_i64(), Some(big));
    }

    #[test]
    fn bitfield_members_carry_width() {
        let mut b = BtfBuilder::default();
        let u8t = b.add_int("u8", 1, 0);
        let s = b.make_struct("flags", 4, |s| {
            s.field("a", u8t, 0);
        });
        let mut btf = b.build();
        if let Some(t) = btf.types.get_mut(&s)
            && let BtfKind::Struct(st) = &mut t.kind
        {
            st.members[0].bitfield_size = Some(4);
        }

        let v = schema_json(s, &btf);
        assert_eq!(v["properties"]["a"]["bits"], json!(4));
        assert_eq!(v["properties"]["a"]["bit_offset"], json!(0));
        assert_eq!(v["required"][0], "a");
    }
}
