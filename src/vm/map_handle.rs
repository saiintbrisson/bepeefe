use std::sync::Arc;

use crate::error::RuntimeError;
use crate::{
    btf::{
        BtfBuilder, BtfRef, BtfType, BtfTypeId,
        value::{Value, from_value, to_value},
    },
    maps::BpfMap,
};

pub struct MapHandle {
    map: Arc<BpfMap>,
    key_btf: Arc<crate::btf::Btf>,
    key_id: BtfTypeId,
    value_id: BtfTypeId,
}

impl MapHandle {
    /// Constructs a handle, refusing untyped data maps (no value BTF).
    pub(super) fn new(map: Arc<BpfMap>) -> Option<Self> {
        if map.spec.initial_data.is_some() {
            return None;
        }

        let value_id = map.spec.value?;
        let (key_btf, key_id) = match map.spec.key {
            Some(id) => (map.btf.clone(), id),
            None => {
                let mut b = BtfBuilder::default();
                let u8_id = b.add_int("u8", 1, 0);
                let id = b.add_array("key", u8_id, u8_id, map.repr.key_size() as u32);
                (Arc::new(b.build()), id)
            }
        };
        Some(Self {
            map,
            key_btf,
            key_id,
            value_id,
        })
    }

    fn key_ty(&self) -> BtfRef<'_> {
        self.key_btf.resolve_must(self.key_id)
    }

    fn value_ty(&self) -> BtfRef<'_> {
        self.map.btf.resolve_must(self.value_id)
    }

    pub fn update(
        &self,
        key: &(impl serde::Serialize + ?Sized),
        val: &(impl serde::Serialize + ?Sized),
    ) -> Result<(), RuntimeError> {
        let key = to_value(key)?.to_bytes(self.key_ty())?;
        let val = to_value(val)?.to_bytes(self.value_ty())?;
        self.map.repr.update(&key, &val)?;
        Ok(())
    }

    pub fn push(&mut self, val: &(impl serde::Serialize + ?Sized)) -> Result<(), RuntimeError> {
        let val = to_value(val)?.to_bytes(self.value_ty())?;
        self.map.repr.push(&val)?;
        Ok(())
    }

    pub fn pop<T: for<'de> serde::Deserialize<'de>>(&mut self) -> Result<Option<T>, RuntimeError> {
        let Some(pv) = self.pop_value()? else {
            return Ok(None);
        };
        Ok(Some(from_value(pv)?))
    }

    pub fn pop_value(&mut self) -> Result<Option<Value>, RuntimeError> {
        let val_ty = self.value_ty();
        let Some(addr) = self.map.repr.pop() else {
            return Ok(None);
        };
        let Some(bytes) = self.map.repr.read_bytes(addr, self.map.repr.value_size()) else {
            return Ok(None);
        };
        Ok(Some(Value::from_bytes(val_ty, &bytes)?))
    }

    pub fn lookup<T: for<'de> serde::Deserialize<'de>>(
        &self,
        key: &(impl serde::Serialize + ?Sized),
    ) -> Result<Option<T>, RuntimeError> {
        let key = to_value(key)?;
        let Some(pv) = self.lookup_value(&key)? else {
            return Ok(None);
        };
        Ok(Some(from_value(pv)?))
    }

    pub fn lookup_value(&self, key: &Value) -> Result<Option<Value>, RuntimeError> {
        let key_bytes = key.to_bytes(self.key_ty())?;
        let val_ty = self.value_ty();
        let Some(addr) = self.map.repr.lookup(&key_bytes) else {
            return Ok(None);
        };
        let Some(bytes) = self.map.repr.read_bytes(addr, self.map.repr.value_size()) else {
            return Ok(None);
        };
        Ok(Some(Value::from_bytes(val_ty, &bytes)?))
    }

    pub fn delete(&self, key: &(impl serde::Serialize + ?Sized)) -> Result<(), RuntimeError> {
        let key = to_value(key)?.to_bytes(self.key_ty())?;
        self.map.repr.delete(&key)?;
        Ok(())
    }

    pub fn clear(&mut self) {
        self.map.repr.clear();
    }

    pub fn btf(&self) -> &crate::btf::Btf {
        &self.map.btf
    }

    pub fn btf_val_type(&self) -> &BtfType {
        self.value_ty().ty()
    }

    pub fn name(&self) -> &str {
        &self.map.spec.name
    }

    pub fn map_type(&self) -> Option<u32> {
        self.map.spec.r#type
    }

    pub fn key_type(&self) -> BtfTypeId {
        self.key_id
    }

    pub fn value_type(&self) -> BtfTypeId {
        self.value_id
    }

    /// Visits each entry, calling `filter` on the raw key/value bytes.
    /// Returns deserialized `(key, value)` pairs only for entries where
    /// `filter` returns `true`. No intermediate byte buffers are
    /// allocated for skipped entries.
    pub fn entries_filtered<F>(&self, mut filter: F) -> Result<Vec<(Value, Value)>, RuntimeError>
    where
        F: FnMut(&[u8], &[u8]) -> bool,
    {
        let key_ty = self.key_ty();
        let val_ty = self.value_ty();
        let mut out: Result<Vec<(Value, Value)>, RuntimeError> = Ok(Vec::new());
        self.map.repr.for_each_entry(|k, v| {
            let Ok(acc) = out.as_mut() else {
                return;
            };
            if !filter(k, v) {
                return;
            }
            match (Value::from_bytes(key_ty, k), Value::from_bytes(val_ty, v)) {
                (Ok(key), Ok(value)) => acc.push((key, value)),
                (Err(e), _) | (_, Err(e)) => out = Err(e.into()),
            }
        });
        out
    }
}
