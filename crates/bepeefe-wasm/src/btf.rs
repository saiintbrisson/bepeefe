use std::sync::Arc;

use wasm_bindgen::prelude::*;

use bepeefe::btf::{Btf, BtfKind, BtfRef, BtfType, BtfTypeId, value::Value};

use crate::{js_err, schema, to_js};

/// A BTF type graph, either parsed from a raw blob like
/// `/sys/kernel/btf/vmlinux` or taken from an object's `.BTF` section.
#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmBtf {
    inner: Arc<Btf>,
}

impl WasmBtf {
    pub(crate) fn new(inner: Arc<Btf>) -> Self {
        Self { inner }
    }

    pub(crate) fn inner(&self) -> &Btf {
        &self.inner
    }
}

#[wasm_bindgen]
impl WasmBtf {
    /// Parses a raw BTF blob and rejects it if any type points at one that
    /// doesn't exist, since every other method assumes the graph is whole.
    pub fn parse(bytes: &[u8]) -> Result<WasmBtf, JsError> {
        let btf = Btf::from_bytes(bytes).map_err(js_err)?;
        btf.validate().map_err(js_err)?;
        Ok(Self::new(Arc::new(btf)))
    }

    pub fn type_count(&self) -> usize {
        self.inner.types.len()
    }

    pub fn type_size(&self, type_id: u32) -> u32 {
        self.inner.type_size(BtfTypeId(type_id))
    }

    /// Type labels, e.g. "struct sock", "u32", etc.
    ///
    /// Returns null when the type has no name or doesn't resolve.
    #[wasm_bindgen(unchecked_return_type = "string | null")]
    pub fn type_label(&self, type_id: u32) -> Option<String> {
        let ty = self.inner.types.get(&BtfTypeId(type_id))?;
        type_label(&self.inner, ty)
    }

    /// Named struct, union, enum, and int types, sorted by label.
    #[wasm_bindgen(unchecked_return_type = "BrowseEntry[]")]
    pub fn browseable_types(&self) -> Result<JsValue, JsError> {
        let mut out: Vec<BrowseEntry> = Vec::new();
        for (id, ty) in &self.inner.types {
            let kind = match &ty.kind {
                BtfKind::Struct(_) => "struct",
                BtfKind::Union(_) => "union",
                BtfKind::Enum(_) | BtfKind::Enum64(_) => "enum",
                BtfKind::Int(_) => "int",
                _ => continue,
            };
            let Some(label) = type_label(&self.inner, ty) else {
                continue;
            };
            out.push(BrowseEntry {
                type_id: id.0,
                label,
                kind,
                size: ty.kind.size(&self.inner),
            });
        }
        out.sort_by(|a, b| a.label.cmp(&b.label));
        to_js(&out)
    }

    /// Encode a JSON `Value` to bytes laid out per the given BTF type, matching
    /// what the engine writes for that type at runtime.
    pub fn value_to_bytes(&self, type_id: u32, value_json: &str) -> Result<Vec<u8>, JsError> {
        let ty = self.resolve(type_id)?;
        let value: Value = serde_json::from_str(value_json).map_err(js_err)?;
        value.to_bytes(ty).map_err(js_err)
    }

    /// Inverse of `value_to_bytes`. Decode bytes into a `Value` shaped
    /// by the given BTF type.
    pub fn value_from_bytes(&self, type_id: u32, bytes: &[u8]) -> Result<String, JsError> {
        let ty = self.resolve(type_id)?;
        let value = Value::from_bytes(ty, bytes).map_err(js_err)?;
        serde_json::to_string(&value).map_err(js_err)
    }

    #[wasm_bindgen(unchecked_return_type = "JsonSchema")]
    pub fn type_schema(&self, type_id: u32) -> Result<JsValue, JsError> {
        to_js(&schema::type_to_schema(BtfTypeId(type_id), &self.inner))
    }
}

impl WasmBtf {
    fn resolve(&self, type_id: u32) -> Result<BtfRef<'_>, JsError> {
        self.inner
            .resolve(BtfTypeId(type_id))
            .ok_or_else(|| JsError::new(&format!("unknown type id {type_id}")))
    }
}

/// C-style label for a named type, or the bare name for kinds that don't take a
/// prefix.
pub(crate) fn type_label(btf: &Btf, ty: &BtfType) -> Option<String> {
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
struct BrowseEntry {
    type_id: u32,
    label: String,
    kind: &'static str,
    size: u32,
}
