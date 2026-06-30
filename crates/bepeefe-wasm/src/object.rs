use std::{collections::BTreeMap, sync::Arc};

use wasm_bindgen::prelude::*;

use bepeefe::{
    EbpfObject,
    btf::{Btf, BtfKind, BtfType, BtfTypeId, Hop, ext::CoreRelo, value::Value},
    hook::Hook,
    object::{EbpfProgram, FunctionSignature},
};

use crate::{
    disasm, js_err,
    schema::{self, JsonSchema},
    to_js,
};

#[wasm_bindgen]
pub struct WasmObject {
    programs: BTreeMap<String, EbpfProgram>,
    signatures: Vec<FunctionSignature>,
    sections: BTreeMap<String, String>,
    btf: Arc<Btf>,
}

#[wasm_bindgen]
impl WasmObject {
    pub fn parse(elf: &[u8]) -> Result<WasmObject, JsError> {
        let obj = EbpfObject::from_elf(elf).map_err(js_err)?;
        let btf = obj.btf().clone();
        let signatures: Vec<_> = obj.programs().cloned().collect();

        let mut programs = BTreeMap::new();
        let mut sections = BTreeMap::new();
        for sig in &signatures {
            let prog = obj.load_prog(&sig.name).map_err(js_err)?;
            programs.insert(sig.name.clone(), prog);
            if let Some(sec) = obj.section_name(sig.section_idx) {
                sections.insert(sig.name.clone(), sec.to_string());
            }
        }

        Ok(WasmObject {
            programs,
            signatures,
            sections,
            btf,
        })
    }

    pub fn disasm(&self, prog_name: &str) -> Result<String, JsError> {
        disasm::to_json(self.lookup(prog_name)?)
    }

    pub fn type_size(&self, type_id: u32) -> u32 {
        self.btf.type_size(BtfTypeId(type_id))
    }

    /// Type labels, e.g. "struct sock", "u32", etc.
    ///
    /// Returns null when the type has no name or doesn't resolve.
    #[wasm_bindgen(unchecked_return_type = "string | null")]
    pub fn type_label(&self, type_id: u32) -> Option<String> {
        let ty = self.btf.types.get(&BtfTypeId(type_id))?;
        type_label(&self.btf, ty)
    }

    /// Named struct, union, enum, and int types in this object, sorted
    /// by label.
    #[wasm_bindgen(unchecked_return_type = "BrowseEntry[]")]
    pub fn browseable_types(&self) -> Result<JsValue, JsError> {
        let mut out: Vec<BrowseEntry> = Vec::new();
        for (id, ty) in &self.btf.types {
            let kind = match &ty.kind {
                BtfKind::Struct(_) => "struct",
                BtfKind::Union(_) => "union",
                BtfKind::Enum(_) | BtfKind::Enum64(_) => "enum",
                BtfKind::Int(_) => "int",
                _ => continue,
            };
            let Some(label) = type_label(&self.btf, ty) else {
                continue;
            };
            out.push(BrowseEntry {
                type_id: id.0,
                label,
                kind: kind.into(),
                size: ty.kind.size(&self.btf),
            });
        }
        out.sort_by(|a, b| a.label.cmp(&b.label));
        to_js(&out)
    }

    /// Encode a JSON `Value` to bytes laid out per the given BTF type, matching
    /// what the engine writes for that type at runtime.
    pub fn value_to_bytes(&self, type_id: u32, value_json: &str) -> Result<Vec<u8>, JsError> {
        let ty = self
            .btf
            .resolve(BtfTypeId(type_id))
            .ok_or_else(|| JsError::new(&format!("unknown type id {type_id}")))?;
        let value: Value = serde_json::from_str(value_json).map_err(js_err)?;
        value.to_bytes(ty).map_err(js_err)
    }

    /// Inverse of `value_to_bytes`. Decode bytes into a `Value` shaped
    /// by the given BTF type.
    pub fn value_from_bytes(&self, type_id: u32, bytes: &[u8]) -> Result<String, JsError> {
        let ty = self
            .btf
            .resolve(BtfTypeId(type_id))
            .ok_or_else(|| JsError::new(&format!("unknown type id {type_id}")))?;
        let value = Value::from_bytes(ty, bytes).map_err(js_err)?;
        serde_json::to_string(&value).map_err(js_err)
    }

    /// Programs in this object and their schemas.
    #[wasm_bindgen(unchecked_return_type = "ProgramSchema[]")]
    pub fn program_schemas(&self) -> Result<JsValue, JsError> {
        let out: Vec<ProgramSchema> = self
            .signatures
            .iter()
            .map(|sig| {
                let section = self.sections.get(&sig.name).cloned();
                let hook = section
                    .as_deref()
                    .and_then(Hook::parse)
                    .map(|h| HookInfo { raw: h.raw });
                ProgramSchema {
                    name: sig.name.clone(),
                    section,
                    hook,
                    params: sig
                        .params_types
                        .iter()
                        .map(|(name, tid)| ParamSchema {
                            name: name.clone(),
                            type_id: tid.0,
                            schema: schema::type_to_schema(*tid, &self.btf),
                        })
                        .collect(),
                }
            })
            .collect();
        to_js(&out)
    }

    /// Map specs for a program with key/value and their schemas.
    #[wasm_bindgen(unchecked_return_type = "MapSchema[]")]
    pub fn map_schemas(&self, prog_name: &str) -> Result<JsValue, JsError> {
        let out: Vec<MapSchema> = self
            .lookup(prog_name)?
            .maps()
            .iter()
            .filter(|m| m.initial_data.is_none())
            .map(|m| MapSchema {
                name: m.name.clone(),
                map_type: m.r#type,
                max_entries: m.max_entries,
                key_size: m.key_size,
                value_size: m.value_size,
                key_type_id: m.key.map(|t| t.0),
                value_type_id: m.value.map(|t| t.0),
                key: m.key.map(|t| schema::type_to_schema(t, &self.btf)),
                value: m.value.map(|t| schema::type_to_schema(t, &self.btf)),
            })
            .collect();
        to_js(&out)
    }

    /// Single-type schema lookup for an BTF id.
    #[wasm_bindgen(unchecked_return_type = "JsonSchema")]
    pub fn type_schema(&self, type_id: u32) -> Result<JsValue, JsError> {
        to_js(&schema::type_to_schema(BtfTypeId(type_id), &self.btf))
    }

    /// CO-RE relocations from .BTF.ext, each with its access path resolved
    /// against the BTF type graph.
    #[wasm_bindgen(unchecked_return_type = "CoreRelo[]")]
    pub fn core_relos(&self) -> Result<JsValue, JsError> {
        let out: Vec<CoreReloEntry> = self
            .btf
            .ext
            .core_relo
            .iter()
            .flat_map(|sec| {
                let section = self
                    .btf
                    .string(sec.sec_name_off)
                    .unwrap_or_default()
                    .into_owned();
                sec.data
                    .iter()
                    .map(move |relo| core_relo_entry(&self.btf, &section, relo))
            })
            .collect();
        to_js(&out)
    }
}

impl WasmObject {
    pub(crate) fn program(&self, name: &str) -> Option<&EbpfProgram> {
        self.programs.get(name)
    }

    fn lookup(&self, name: &str) -> Result<&EbpfProgram, JsError> {
        self.program(name)
            .ok_or_else(|| JsError::new(&format!("program '{name}' not found")))
    }
}

/// Resolves one CO-RE relocation into its JS-facing shape, following the
/// access spec through the BTF graph for field relocations and naming the
/// selected variant for enum relocations.
fn core_relo_entry(btf: &Btf, section: &str, relo: &CoreRelo) -> CoreReloEntry {
    let root = BtfTypeId(relo.type_id);
    let access = btf
        .string(relo.access_str_off)
        .unwrap_or_default()
        .into_owned();

    let mut entry = CoreReloEntry {
        section: section.to_owned(),
        insn: relo.insn_off,
        kind: relo.kind.label(),
        type_id: relo.type_id,
        type_label: btf.get_type(root).and_then(|ty| type_label(btf, ty)),
        access: access.clone(),
        path: None,
        hops: None,
        byte_offset: None,
        variant: None,
    };

    if relo.kind.is_enum() {
        if let Some(idx) = access
            .split(':')
            .next()
            .and_then(|s| s.parse::<usize>().ok())
        {
            entry.variant = btf.enum_variant_name(root, idx).map(|v| v.into_owned());
            entry.path = entry.variant.as_ref().map(|v| format!("::{v}"));
        }
    } else if relo.kind.is_field()
        && let Ok(path) = btf.parse_access(root, &access)
    {
        entry.byte_offset = Some(path.byte_offset());
        entry.path = (!path.is_empty()).then(|| path.to_string());
        entry.hops = Some(
            path.hops()
                .iter()
                .map(|hop| CoreReloHop {
                    name: hop_name(hop),
                    type_id: hop.type_id().0,
                })
                .collect(),
        );
    }

    entry
}

fn hop_name(hop: &Hop<'_>) -> String {
    match hop {
        Hop::Member { name, .. } => name.to_string(),
        Hop::Element { index, .. } => format!("[{index}]"),
    }
}

/// C-style label for a named type, or the bare name for kinds that don't take a
/// prefix.
fn type_label(btf: &Btf, ty: &BtfType) -> Option<String> {
    let name = btf.string(ty.name_off)?;
    if name.is_empty() {
        return None;
    }
    Some(match &ty.kind {
        BtfKind::Struct(_) => format!("struct {name}"),
        BtfKind::Union(_) => format!("union {name}"),
        BtfKind::Enum(_) | BtfKind::Enum64(_) => format!("enum {name}"),
        _ => name.into_owned(),
    })
}

#[derive(serde::Serialize)]
struct ProgramSchema {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    section: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hook: Option<HookInfo>,
    params: Vec<ParamSchema>,
}

#[derive(serde::Serialize)]
struct ParamSchema {
    name: String,
    type_id: u32,
    schema: JsonSchema,
}

#[derive(serde::Serialize)]
struct HookInfo {
    raw: String,
}

#[derive(serde::Serialize)]
struct BrowseEntry {
    type_id: u32,
    label: String,
    kind: String,
    size: u32,
}

#[derive(serde::Serialize)]
struct CoreReloEntry {
    section: String,
    insn: u32,
    kind: &'static str,
    type_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    type_label: Option<String>,
    access: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hops: Option<Vec<CoreReloHop>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    byte_offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    variant: Option<String>,
}

#[derive(serde::Serialize)]
struct CoreReloHop {
    name: String,
    type_id: u32,
}

#[derive(serde::Serialize)]
struct MapSchema {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    map_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_entries: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_type_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_type_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<JsonSchema>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<JsonSchema>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bepeefe::btf::{BtfBuilder, ext::CoreReloKind};

    fn push_string(btf: &mut Btf, s: &str) -> u32 {
        let off = btf.strings.len() as u32;
        btf.strings.extend_from_slice(s.as_bytes());
        btf.strings.push(0);
        off
    }

    #[test]
    fn field_relocation_resolves_hops_and_offset() {
        let mut b = BtfBuilder::default();
        let u32t = b.add_int("u32", 4, 0);
        let sk = b.make_struct("sk", 8, |s| {
            s.field("family", u32t, 0);
            s.field("mark", u32t, 32);
        });
        let mut btf = b.build();
        let access_str_off = push_string(&mut btf, "0:1");
        let relo = CoreRelo {
            insn_off: 3,
            type_id: sk.0,
            access_str_off,
            kind: CoreReloKind::FieldByteOffset,
        };

        let v = serde_json::to_value(core_relo_entry(&btf, ".text", &relo)).unwrap();
        assert_eq!(v["kind"], "field_byte_offset");
        assert_eq!(v["type_label"], "struct sk");
        assert_eq!(v["access"], "0:1");
        assert_eq!(v["path"], ".mark");
        assert_eq!(v["byte_offset"], 4);
        assert_eq!(v["hops"][0]["name"], "mark");
        assert_eq!(v["hops"][0]["type_id"], u32t.0);
    }

    #[test]
    fn enum_relocation_names_variant_without_hops() {
        let mut b = BtfBuilder::default();
        let st = b.make_enum("st", 4, false, |e| {
            e.value("A", 1);
            e.value("B", 7);
        });
        let mut btf = b.build();
        let access_str_off = push_string(&mut btf, "1");
        let relo = CoreRelo {
            insn_off: 0,
            type_id: st.0,
            access_str_off,
            kind: CoreReloKind::EnumvalValue,
        };

        let v = serde_json::to_value(core_relo_entry(&btf, ".text", &relo)).unwrap();
        assert_eq!(v["kind"], "enumval_value");
        assert_eq!(v["variant"], "B");
        assert_eq!(v["path"], "::B");
        assert!(v.get("hops").is_none());
    }

    #[test]
    fn whole_type_relocation_has_no_path() {
        let mut b = BtfBuilder::default();
        let sk = b.make_struct("sk", 8, |_| {});
        let mut btf = b.build();
        let access_str_off = push_string(&mut btf, "0");
        let relo = CoreRelo {
            insn_off: 0,
            type_id: sk.0,
            access_str_off,
            kind: CoreReloKind::TypeSize,
        };

        let v = serde_json::to_value(core_relo_entry(&btf, ".text", &relo)).unwrap();
        assert_eq!(v["kind"], "type_size");
        assert_eq!(v["type_label"], "struct sk");
        assert!(v.get("path").is_none());
        assert!(v.get("hops").is_none());
    }
}
