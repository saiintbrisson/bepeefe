use std::{
    alloc::Layout,
    io::{ErrorKind, Result},
    ptr::NonNull,
};

#[derive(Debug)]
pub struct Array {
    data: Option<NonNull<u8>>,

    max_entries: usize,

    element_layout: Layout,
    /// Number of bytes in-between elements. This is essentially element size +
    /// alignment.
    element_stride: usize,
}

impl Array {
    pub fn new(max_entries: u32, value_size: u32) -> Self {
        let max_entries = max_entries as usize;
        let value_size = value_size as usize;

        let element_layout = Layout::from_size_align(value_size, 8).expect("invalid value size");
        let element_stride = element_layout.pad_to_align().size();

        Self {
            data: None,
            max_entries,
            element_layout,
            element_stride,
        }
    }

    pub fn key_size(&self) -> usize {
        u32::BITS as usize / 8
    }

    pub fn init(&mut self, mem: &mut crate::vm::mem::VmMem) {
        let (map_layout, _) = self
            .element_layout
            .repeat(self.max_entries)
            .expect("invalid map config");

        self.data = Some(mem.alloc_layout(map_layout).expect("vm mem oom").as_ptr());
    }

    pub fn lookup_elem(&self, key: &[u8]) -> Option<*const u8> {
        let key = key.try_into().unwrap();
        let key = u32::from_ne_bytes(key) as usize;
        if key > self.max_entries {
            return None;
        }

        let idx = self.element_stride * key;
        let ptr = self.data.expect("map not initialized").as_ptr() as usize;
        Some(ptr.checked_add(idx)? as *const u8)
    }

    pub fn update_elem(&mut self, key: &[u8], value: *const u8) -> Result<()> {
        let key = key.try_into().unwrap();
        let key = u32::from_ne_bytes(key) as usize;
        if key <= self.max_entries {
            return Err(ErrorKind::InvalidInput.into());
        }

        let idx = self.element_stride * key;
        let ptr = self.data.expect("map not initialized").as_ptr() as usize;
        let ptr = ptr.checked_add(idx).ok_or(ErrorKind::InvalidInput)? as *mut u8;

        unsafe {
            ptr.copy_from(value, self.element_layout.size());
        }

        Ok(())
    }
}
