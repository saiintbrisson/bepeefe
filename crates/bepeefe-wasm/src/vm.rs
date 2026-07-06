use std::sync::Arc;

use wasm_bindgen::prelude::*;

use bepeefe::{
    btf::value::Value,
    verifier::VerifierConfig,
    vm::{Cpu, CtxImage, MapHandle, MapReuseStrategy, PreparedProgram, Task, Vm, World},
};

use crate::{capture::WasmCapture, disasm, js_err, object::WasmObject};

#[wasm_bindgen]
pub struct WasmVm {
    inner: Arc<Vm>,
}

#[wasm_bindgen]
impl WasmVm {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> WasmVm {
        WasmVm { inner: Vm::new() }
    }

    /// Replaces the shared world (clock, probe memory, CPU, RNG seed).
    /// Call between runs to advance the emulated machine.
    pub fn set_world(&self, world_json: &str) -> Result<(), JsError> {
        let world: World = serde_json::from_str(world_json).map_err(js_err)?;
        *self.inner.world() = world;
        Ok(())
    }

    pub fn load(
        &self,
        obj: &WasmObject,
        prog_name: &str,
        capture: Option<WasmCapture>,
    ) -> Result<WasmProgram, JsError> {
        let prog = obj
            .program(prog_name)
            .ok_or_else(|| JsError::new(&format!("program '{prog_name}' not found")))?
            .clone();
        let verifier_config = VerifierConfig {
            capture: capture.map(|c| c.inner),
            ..Default::default()
        };
        let prepared = self
            .inner
            .prepare(prog, MapReuseStrategy::None, &verifier_config)
            .map_err(|e| JsError::new(&e.report()))?;
        Ok(WasmProgram { prepared })
    }

    pub fn map_pop(&self, name: &str) -> Result<JsValue, JsError> {
        let Some(mut handle) = self.inner.map(name) else {
            return Ok(JsValue::NULL);
        };
        match handle.pop_value().map_err(js_err)? {
            Some(pv) => to_json_value(&pv),
            None => Ok(JsValue::NULL),
        }
    }

    pub fn map_lookup(&self, name: &str, key_json: &str) -> Result<JsValue, JsError> {
        let Some(handle) = self.inner.map(name) else {
            return Ok(JsValue::NULL);
        };
        let key: Value = serde_json::from_str(key_json).map_err(js_err)?;
        match handle.lookup_value(&key).map_err(js_err)? {
            Some(pv) => to_json_value(&pv),
            None => Ok(JsValue::NULL),
        }
    }

    pub fn dump_maps(&self) -> Result<String, JsError> {
        #[derive(serde::Serialize)]
        struct MapDump {
            name: String,
            map_type: Option<u32>,
            key_type_id: u32,
            value_type_id: u32,
            entries: Vec<(Value, Value)>,
        }
        let dumps: Vec<MapDump> = self
            .inner
            .maps()
            .iter()
            .map(|h| {
                Ok(MapDump {
                    name: h.name().to_string(),
                    map_type: h.map_type(),
                    key_type_id: h.key_type().0,
                    value_type_id: h.value_type().0,
                    entries: h.entries_filtered(|_, v| v.iter().any(|b| *b != 0))?,
                })
            })
            .collect::<Result<_, bepeefe::RuntimeError>>()
            .map_err(js_err)?;
        serde_json::to_string(&dumps).map_err(js_err)
    }

    pub fn map_update(&self, name: &str, key_json: &str, val_json: &str) -> Result<(), JsError> {
        let handle = self.typed_map(name)?;
        let key: Value = serde_json::from_str(key_json).map_err(js_err)?;
        let val: Value = serde_json::from_str(val_json).map_err(js_err)?;
        handle.update(&key, &val).map_err(js_err)
    }

    pub fn map_delete(&self, name: &str, key_json: &str) -> Result<(), JsError> {
        let handle = self.typed_map(name)?;
        let key: Value = serde_json::from_str(key_json).map_err(js_err)?;
        handle.delete(&key).map_err(js_err)
    }

    pub fn map_clear(&self, name: &str) -> Result<(), JsError> {
        if let Some(mut handle) = self.inner.map(name) {
            handle.clear();
        }
        Ok(())
    }
}

impl WasmVm {
    fn typed_map(&self, name: &str) -> Result<MapHandle, JsError> {
        self.inner
            .map(name)
            .ok_or_else(|| JsError::new(&format!("map {name:?} is not typed")))
    }
}

#[wasm_bindgen]
pub struct WasmProgram {
    prepared: Arc<PreparedProgram>,
}

#[wasm_bindgen]
impl WasmProgram {
    pub fn start(
        &self,
        ctx_json: &str,
        task_json: &str,
        capture: Option<WasmCapture>,
    ) -> Result<WasmSession, JsError> {
        let image = self
            .build_image(ctx_json)?
            .from_task(parse_task(task_json)?);
        let inner = self.prepared.start(image, capture.map(|c| c.inner));
        Ok(WasmSession { inner })
    }

    pub fn run(
        &self,
        ctx_json: &str,
        task_json: &str,
        capture: Option<WasmCapture>,
    ) -> Result<u64, JsError> {
        let image = self
            .build_image(ctx_json)?
            .from_task(parse_task(task_json)?);
        Ok(self.prepared.run(image, capture.map(|c| c.inner)))
    }

    #[wasm_bindgen(unchecked_return_type = "DisasmRow[]")]
    pub fn disasm(&self) -> Result<String, JsError> {
        disasm::to_json(&self.prepared)
    }
}

impl WasmProgram {
    fn build_image(&self, ctx_json: &str) -> Result<CtxImage, JsError> {
        let params: Vec<Value> = serde_json::from_str(ctx_json).map_err(js_err)?;
        self.prepared.build_image(&params).map_err(js_err)
    }
}

#[wasm_bindgen]
pub struct WasmSession {
    inner: Cpu,
}

#[wasm_bindgen]
impl WasmSession {
    pub fn step(&mut self) -> bool {
        self.inner.step()
    }

    pub fn done(&self) -> bool {
        self.inner.done()
    }

    pub fn pc(&self) -> usize {
        self.inner.pc()
    }

    pub fn registers(&self) -> Vec<u64> {
        self.inner.regs().to_vec()
    }

    pub fn buf(&self) -> Vec<u8> {
        self.inner.buf().to_vec()
    }

    pub fn return_val(&self) -> u64 {
        self.inner.return_val()
    }
}

fn parse_task(task_json: &str) -> Result<Task, JsError> {
    let trimmed = task_json.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Task::default());
    }
    serde_json::from_str(trimmed).map_err(js_err)
}

fn to_json_value<T: serde::Serialize>(value: &T) -> Result<JsValue, JsError> {
    let json = serde_json::to_string(value).map_err(js_err)?;
    Ok(JsValue::from_str(&json))
}
