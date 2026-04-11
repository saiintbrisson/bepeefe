use std::collections::HashSet;

use bepeefe::btf::{Btf, BtfKind, BtfTypeId};
use indexmap::IndexMap;

const BTF_INT_SIGNED: u8 = 1;

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct JsonSchema {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub schema_type: Option<JsonSchemaType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<f64>,

    #[serde(rename = "oneOf", skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<JsonSchemaVariant>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<IndexMap<String, JsonSchema>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<JsonSchema>>,

    #[serde(rename = "minItems", skip_serializing_if = "Option::is_none")]
    pub min_items: Option<u32>,

    #[serde(rename = "maxItems", skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub union: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JsonSchemaType {
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
    while let Some(ty) = btf.types.get(&walk_id) {
        match &ty.kind {
            BtfKind::Ptr(inner) => {
                ptr_depth += 1;
                walk_id = *inner;
            }
            BtfKind::Typedef(inner)
            | BtfKind::Const(inner)
            | BtfKind::Volatile(inner)
            | BtfKind::Restrict(inner)
            | BtfKind::TypeTag(inner) => {
                walk_id = *inner;
            }
            _ => break,
        }
    }

    let with_ptr = |mut s: JsonSchema| -> JsonSchema {
        if ptr_depth > 0 {
            s.pointer = Some(ptr_depth);
        }
        s
    };

    let Some(ty) = btf.types.get(&walk_id) else {
        return with_ptr(JsonSchema {
            schema_type: Some(JsonSchemaType::Integer),
            description: Some("void".into()),
            ..Default::default()
        });
    };

    let title_of = |off: u32| -> Option<String> {
        let s = btf.string(off)?;
        if s.is_empty() {
            None
        } else {
            Some(s.into_owned())
        }
    };

    match &ty.kind {
        BtfKind::DeclTag => with_ptr(JsonSchema {
            schema_type: Some(JsonSchemaType::Integer),
            ..Default::default()
        }),

        BtfKind::Int(int) => with_ptr(int_schema(int.encoding, int.bits)),

        BtfKind::Float(f) => with_ptr(JsonSchema {
            schema_type: Some(JsonSchemaType::Number),
            description: Some(format!("f{}", f.size * 8)),
            ..Default::default()
        }),

        BtfKind::Enum(e) => with_ptr(JsonSchema {
            description: Some("enum".into()),
            one_of: Some(
                e.values
                    .iter()
                    .map(|v| JsonSchemaVariant {
                        const_value: Some(i64::from(v.val)),
                        title: btf
                            .string(v.name_off)
                            .map(|c| c.into_owned())
                            .unwrap_or_default(),
                        schema: JsonSchema::default(),
                    })
                    .collect(),
            ),
            ..Default::default()
        }),

        BtfKind::Enum64(e) => with_ptr(JsonSchema {
            description: Some("enum".into()),
            one_of: Some(
                e.values
                    .iter()
                    .map(|v| JsonSchemaVariant {
                        const_value: Some(i64::from(v.val_lo32)),
                        title: btf
                            .string(v.name_off)
                            .map(|c| c.into_owned())
                            .unwrap_or_default(),
                        schema: JsonSchema::default(),
                    })
                    .collect(),
            ),
            ..Default::default()
        }),

        BtfKind::Struct(s) => {
            let title = title_of(ty.name_off);

            if seen.contains(&walk_id) {
                let mut result = JsonSchema {
                    schema_type: Some(JsonSchemaType::Object),
                    properties: Some(IndexMap::new()),
                    required: Some(Vec::new()),
                    ..Default::default()
                };
                if let Some(name) = title {
                    result.title = Some(name);
                }
                return with_ptr(result);
            }

            seen.insert(walk_id);
            let mut properties: IndexMap<String, JsonSchema> = IndexMap::new();
            let mut required: Vec<String> = Vec::new();
            for (idx, member) in s.members.iter().enumerate() {
                // A zero size covers plain members too, since kind_flag
                // off leaves the upper byte clear, so only skip Some(>0)
                if member.bitfield_size.unwrap_or(0) > 0 {
                    continue;
                }
                let name = btf
                    .string(member.name_off)
                    .map(|c| c.into_owned())
                    .unwrap_or_default();
                let sub = walk(member.r#type, btf, seen);
                let key = if name.is_empty() {
                    format!("_anon_{idx}")
                } else {
                    name
                };
                properties.insert(key.clone(), sub);
                required.push(key);
            }
            seen.remove(&walk_id);

            let mut result = JsonSchema {
                schema_type: Some(JsonSchemaType::Object),
                properties: Some(properties),
                required: Some(required),
                ..Default::default()
            };
            if let Some(name) = title {
                result.title = Some(name);
            }
            with_ptr(result)
        }

        BtfKind::Union(u) => {
            let title = title_of(ty.name_off);

            if seen.contains(&walk_id) {
                let mut result = JsonSchema {
                    schema_type: Some(JsonSchemaType::Object),
                    union: Some(true),
                    ..Default::default()
                };
                if let Some(name) = title {
                    result.title = Some(name);
                }
                return with_ptr(result);
            }

            seen.insert(walk_id);
            let mut variants: Vec<JsonSchemaVariant> = Vec::new();
            for (idx, member) in u.members.iter().enumerate() {
                if member.bitfield_size.unwrap_or(0) > 0 {
                    continue;
                }
                let member_name = btf
                    .string(member.name_off)
                    .map(|c| c.into_owned())
                    .unwrap_or_default();
                let mut sub = walk(member.r#type, btf, seen);
                let title = if member_name.is_empty() {
                    anon_variant_label(&sub, idx)
                } else {
                    sub.member = Some(member_name.clone());
                    member_name
                };
                variants.push(JsonSchemaVariant {
                    const_value: None,
                    title,
                    schema: sub,
                });
            }
            seen.remove(&walk_id);

            let mut result = JsonSchema {
                schema_type: Some(JsonSchemaType::Object),
                union: Some(true),
                one_of: Some(variants),
                ..Default::default()
            };
            if let Some(name) = title {
                result.title = Some(name);
            }
            with_ptr(result)
        }

        BtfKind::Array(a) => with_ptr(JsonSchema {
            schema_type: Some(JsonSchemaType::Array),
            items: Some(Box::new(walk(a.r#type, btf, seen))),
            min_items: Some(a.no_elems),
            max_items: Some(a.no_elems),
            ..Default::default()
        }),

        _ => with_ptr(JsonSchema {
            schema_type: Some(JsonSchemaType::Integer),
            ..Default::default()
        }),
    }
}

fn int_schema(encoding: u8, bits: u8) -> JsonSchema {
    let signed = (encoding & BTF_INT_SIGNED) != 0;
    let bits = u32::from(bits);
    let mut schema = JsonSchema {
        schema_type: Some(JsonSchemaType::Integer),
        ..Default::default()
    };
    if bits.is_multiple_of(8) && (8..=64).contains(&bits) {
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
