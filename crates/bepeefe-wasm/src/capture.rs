use std::sync::Arc;

use wasm_bindgen::prelude::*;

use bepeefe::capture::{Capture, Event};

struct JsCapture {
    callback: js_sys::Function,
}

impl Capture for JsCapture {
    fn record(&self, event: Event<'_>) {
        if let Ok(json) = serde_json::to_string(&event) {
            let _ = self
                .callback
                .call1(&JsValue::NULL, &JsValue::from_str(&json));
        }
    }
}

/// Wraps a JS callback so the engine can stream capture events to it as
/// JSON strings. Each string parses into the `CaptureEvent` shape declared
/// in types.ts.
#[wasm_bindgen]
pub struct WasmCapture {
    pub(crate) inner: Arc<dyn Capture>,
}

#[wasm_bindgen]
impl WasmCapture {
    #[wasm_bindgen(constructor)]
    pub fn new(callback: js_sys::Function) -> Self {
        Self {
            inner: Arc::new(JsCapture { callback }),
        }
    }
}
