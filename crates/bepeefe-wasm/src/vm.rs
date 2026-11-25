use std::{collections::BTreeMap, sync::Arc};

use wasm_bindgen::prelude::*;

use bepeefe::{
    btf::{BtfTypeId, value::Value},
    verifier::{FieldRule, VerifierConfig},
    vm::{Cpu, CtxImage, MapReuseStrategy as MapReuse, PreparedProgram, Task, Vm, World},
};

use crate::{capture::WasmCapture, disasm, js_err, object::WasmObject};

/// How `load` treats a program's unpinned maps. Mirrors the engine's
/// `MapReuseStrategy`.
#[wasm_bindgen]
#[derive(Clone, Copy, Default)]
pub enum MapReuseStrategy {
    /// Only maps pinned by name are shared, the rest are private to the load.
    #[default]
    None,
    /// Every map is pinned by name, so it shares state with a compatible map
    /// of the same name from an earlier load.
    MatchByName,
}

impl From<MapReuseStrategy> for MapReuse {
    fn from(strategy: MapReuseStrategy) -> Self {
        match strategy {
            MapReuseStrategy::None => MapReuse::None,
            MapReuseStrategy::MatchByName => MapReuse::MatchByName,
        }
    }
}

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

    /// `datasecs_json` sets data section variables before the program is
    /// verified. It's a `Value` map from
    /// section name to a map of the variables to change, and anything it
    /// leaves out keeps the compiled-in value.
    pub fn load(
        &self,
        obj: &WasmObject,
        prog_name: &str,
        capture: Option<WasmCapture>,
        map_reuse: Option<MapReuseStrategy>,
        datasecs_json: Option<String>,
    ) -> Result<WasmProgram, JsError> {
        let mut prog = obj
            .program(prog_name)
            .ok_or_else(|| JsError::new(&format!("program '{prog_name}' not found")))?
            .clone();
        if let Some(json) = datasecs_json {
            for (section, vars) in parse_map(&json)? {
                let Value::Map(vars) = vars else {
                    return Err(JsError::new(&format!(
                        "variables for {section:?} must be a Map value"
                    )));
                };
                prog.set_datasec_vars(&section, &vars).map_err(js_err)?;
            }
        }
        let verifier_config = VerifierConfig {
            capture: capture.map(|c| c.inner),
            ..Default::default()
        };
        let prepared = self
            .inner
            .prepare(prog, map_reuse.unwrap_or_default().into(), &verifier_config)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(WasmProgram { prepared })
    }

    /// Maps pinned by name, shared by every program that pins them. A
    /// program's own maps go through [`WasmProgram`] instead.
    pub fn pinned_map_pop(&self, name: &str) -> Result<JsValue, JsError> {
        map_ops::pop(self.inner.pinned_map(name))
    }

    pub fn pinned_map_lookup(&self, name: &str, key_json: &str) -> Result<JsValue, JsError> {
        map_ops::lookup(self.inner.pinned_map(name), key_json)
    }

    pub fn pinned_map_update(
        &self,
        name: &str,
        key_json: &str,
        val_json: &str,
    ) -> Result<(), JsError> {
        map_ops::update(self.inner.pinned_map(name), name, key_json, val_json)
    }

    pub fn pinned_map_delete(&self, name: &str, key_json: &str) -> Result<(), JsError> {
        map_ops::delete(self.inner.pinned_map(name), name, key_json)
    }

    pub fn pinned_map_clear(&self, name: &str) {
        map_ops::clear(self.inner.pinned_map(name));
    }

    pub fn dump_pinned_maps(&self) -> Result<String, JsError> {
        map_ops::dump(self.inner.pinned_maps())
    }

    /// Returns whether `name` was pinned. Programs already bound to the map
    /// keep it, the next load declaring `name` creates a new one.
    pub fn unpin(&self, name: &str) -> bool {
        self.inner.unpin(name)
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

    /// This load's copy of a data section as a `Value` JSON string, or null
    /// when the program has no such section.
    #[wasm_bindgen(unchecked_return_type = "string | null")]
    pub fn datasec_read(&self, name: &str) -> Result<Option<String>, JsError> {
        let Some(sec) = self.prepared.datasec(name) else {
            return Ok(None);
        };
        let value = sec.read().map_err(js_err)?;
        serde_json::to_string(&value).map(Some).map_err(js_err)
    }

    /// Changes the variables `vars_json`, a `Value` map, names. Works on
    /// `.rodata` too, since only the program is bound by its `const`.
    pub fn datasec_write(&self, name: &str, vars_json: &str) -> Result<(), JsError> {
        let sec = self
            .prepared
            .datasec(name)
            .ok_or_else(|| JsError::new(&format!("program has no data section {name:?}")))?;
        sec.write(&parse_map(vars_json)?).map_err(js_err)
    }

    /// Every map this program declares, pinned or not.
    pub fn map_pop(&self, name: &str) -> Result<JsValue, JsError> {
        map_ops::pop(self.prepared.map(name))
    }

    pub fn map_lookup(&self, name: &str, key_json: &str) -> Result<JsValue, JsError> {
        map_ops::lookup(self.prepared.map(name), key_json)
    }

    pub fn map_update(&self, name: &str, key_json: &str, val_json: &str) -> Result<(), JsError> {
        map_ops::update(self.prepared.map(name), name, key_json, val_json)
    }

    pub fn map_delete(&self, name: &str, key_json: &str) -> Result<(), JsError> {
        map_ops::delete(self.prepared.map(name), name, key_json)
    }

    pub fn map_clear(&self, name: &str) {
        map_ops::clear(self.prepared.map(name));
    }

    pub fn dump_maps(&self) -> Result<String, JsError> {
        map_ops::dump(self.prepared.maps())
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

fn parse_map(json: &str) -> Result<BTreeMap<String, Value>, JsError> {
    match serde_json::from_str(json).map_err(js_err)? {
        Value::Map(map) => Ok(map),
        _ => Err(JsError::new("expected a Map value")),
    }
}

fn to_json_value<T: serde::Serialize>(value: &T) -> Result<JsValue, JsError> {
    let json = serde_json::to_string(value).map_err(js_err)?;
    Ok(JsValue::from_str(&json))
}

/// The map calls `WasmVm` and `WasmProgram` share, each over the handle its
/// own lookup found.
mod map_ops {
    use bepeefe::{
        btf::value::Value,
        maps::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY},
        vm::MapHandle,
    };
    use wasm_bindgen::prelude::*;

    use super::to_json_value;
    use crate::js_err;

    fn typed(handle: Option<MapHandle>, name: &str) -> Result<MapHandle, JsError> {
        handle.ok_or_else(|| JsError::new(&format!("map {name:?} is not typed")))
    }

    pub fn pop(handle: Option<MapHandle>) -> Result<JsValue, JsError> {
        let Some(mut handle) = handle else {
            return Ok(JsValue::NULL);
        };
        match handle.pop_value().map_err(js_err)? {
            Some(pv) => to_json_value(&pv),
            None => Ok(JsValue::NULL),
        }
    }

    pub fn lookup(handle: Option<MapHandle>, key_json: &str) -> Result<JsValue, JsError> {
        let Some(handle) = handle else {
            return Ok(JsValue::NULL);
        };
        let key: Value = serde_json::from_str(key_json).map_err(js_err)?;
        match handle.lookup_value(&key).map_err(js_err)? {
            Some(pv) => to_json_value(&pv),
            None => Ok(JsValue::NULL),
        }
    }

    pub fn update(
        handle: Option<MapHandle>,
        name: &str,
        key_json: &str,
        val_json: &str,
    ) -> Result<(), JsError> {
        let handle = typed(handle, name)?;
        let key: Value = serde_json::from_str(key_json).map_err(js_err)?;
        let val: Value = serde_json::from_str(val_json).map_err(js_err)?;
        handle.update(&key, &val).map_err(js_err)
    }

    pub fn delete(handle: Option<MapHandle>, name: &str, key_json: &str) -> Result<(), JsError> {
        let handle = typed(handle, name)?;
        let key: Value = serde_json::from_str(key_json).map_err(js_err)?;
        handle.delete(&key).map_err(js_err)
    }

    pub fn clear(handle: Option<MapHandle>) {
        if let Some(mut handle) = handle {
            handle.clear();
        }
    }

    pub fn dump(handles: Vec<MapHandle>) -> Result<String, JsError> {
        #[derive(serde::Serialize)]
        struct MapDump {
            name: String,
            map_type: Option<u32>,
            key_type_id: u32,
            value_type_id: u32,
            entries: Vec<(Value, Value)>,
        }
        let dumps: Vec<MapDump> = handles
            .iter()
            .map(|h| {
                let is_array = matches!(
                    h.map_type(),
                    Some(BPF_MAP_TYPE_ARRAY | BPF_MAP_TYPE_PERCPU_ARRAY)
                );
                Ok(MapDump {
                    name: h.name().to_string(),
                    map_type: h.map_type(),
                    key_type_id: h.key_type().0,
                    value_type_id: h.value_type().0,
                    entries: h.entries_filtered(|_, v| !is_array || v.iter().any(|b| *b != 0))?,
                })
            })
            .collect::<Result<_, bepeefe::RuntimeError>>()
            .map_err(js_err)?;
        serde_json::to_string(&dumps).map_err(js_err)
    }
}
