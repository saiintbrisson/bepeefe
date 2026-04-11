use wasm_bindgen::prelude::*;

mod capture;
mod disasm;
mod object;
mod schema;
mod vm;

pub use capture::WasmCapture;
pub use object::WasmObject;
pub use vm::{WasmProgram, WasmSession, WasmVm};

/// Serialize with BTF maps rendered as plain objects instead of ES
/// `Map`s.
pub(crate) fn to_js<T: serde::Serialize>(value: &T) -> Result<JsValue, JsError> {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    value
        .serialize(&serializer)
        .map_err(|e| JsError::new(&e.to_string()))
}

pub(crate) fn js_err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

/// Hand-written TS declarations for the structs these methods return,
/// concatenated into the generated `bepeefe.d.ts` by wasm-bindgen.
#[wasm_bindgen(typescript_custom_section)]
const TS_DEFS: &'static str = include_str!("./types.ts");
