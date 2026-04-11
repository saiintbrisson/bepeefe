use std::{collections::BTreeMap, sync::Arc};

use wasm_bindgen::prelude::*;

use bepeefe::{
    EbpfObject,
    btf::{Btf, BtfKind, BtfType, BtfTypeId, value::Value},
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
