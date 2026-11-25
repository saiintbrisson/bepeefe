use std::{collections::BTreeMap, sync::Arc};

use crate::{
    btf::{BtfRef, BtfTypeId, value::Value},
    error::RuntimeError,
    maps::BpfMap,
};

/// One program load's copy of a data section.
pub struct DatasecHandle {
    map: Arc<BpfMap>,
    name: String,
    value_id: BtfTypeId,
}

impl DatasecHandle {
    pub(super) fn new(map: Arc<BpfMap>, name: String) -> Option<Self> {
        let value_id = map.spec.value?;
        Some(Self {
            map,
            name,
            value_id,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the program sees the section as `const`. It only binds the
    /// program, since [`DatasecHandle::write`] changes `.rodata` too.
    pub fn readonly(&self) -> bool {
        is_readonly(&self.name)
    }

    pub fn value_type(&self) -> BtfTypeId {
        self.value_id
    }

    fn ty(&self) -> BtfRef<'_> {
        self.map.btf.resolve_must(self.value_id)
    }

    fn bytes(&self) -> Option<Vec<u8>> {
        let addr = self.map.repr.lookup(&0u32.to_ne_bytes())?;
        self.map.repr.read_bytes(addr, self.map.repr.value_size())
    }

    pub fn read(&self) -> Result<Value, RuntimeError> {
        let bytes = self.bytes().ok_or(RuntimeError::MapKeyNotFound)?;
        Ok(Value::from_bytes(self.ty(), &bytes)?)
    }

    pub fn write(&self, vars: &BTreeMap<String, Value>) -> Result<(), RuntimeError> {
        let mut bytes = self.bytes().ok_or(RuntimeError::MapKeyNotFound)?;
        Value::patch_datasec(self.ty(), &mut bytes, vars)?;
        self.map.repr.update(&0u32.to_ne_bytes(), &bytes)
    }
}

pub(crate) fn is_readonly(name: &str) -> bool {
    name.starts_with(".rodata")
}
