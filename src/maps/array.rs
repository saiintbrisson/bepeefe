use std::{
    alloc::Layout,
    io::{ErrorKind, Result},
    ptr::NonNull,
};

#[derive(Debug)]
pub struct Array {
    data: Option<NonNull<u8>>,

    max_entries: usize,

    /// The resulting value layout, without padidng. Its size is provided by the map configuration.
    element_layout: Layout,
    /// The padded array element layout. Its size is padded to align, representing the element stride.
    stride_layout: Layout,
}

impl Array {
    pub fn new(max_entries: u32, value_size: u32) -> Self {
        assert!(max_entries > 0, "max entries must be greater than 0");
        assert!(value_size > 0, "value size must be greater than 0");

        let max_entries = max_entries as usize;
        let value_size = value_size as usize;

        // The kernel aligns array elements to 8 bytes
        // https://github.com/torvalds/linux/blob/8765f467912ff0d4832eeaf26ae573792da877e7/kernel/bpf/arraymap.c#L93
        let element_layout = Layout::from_size_align(value_size, 8).expect("invalid value size");
        let stride_layout = element_layout.pad_to_align();

        Self {
            data: None,
            max_entries,
            element_layout,
            stride_layout,
        }
    }

    pub fn key_size(&self) -> usize {
        u32::BITS as usize / 8
    }

    pub fn value_size(&self) -> usize {
        self.element_layout.size()
    }

    pub fn init(&mut self, mem: &mut crate::vm::mem::VmMem) {
        let map_layout = Layout::from_size_align(
            self.stride_layout.size() * self.max_entries,
            self.stride_layout.align(),
        )
        .expect("invalid map config");

        self.data = Some(mem.alloc_layout(map_layout).expect("vm mem oom").as_ptr());
    }

    pub fn lookup_elem(&self, key: &[u8]) -> Option<*const u8> {
        let key = key.try_into().unwrap();
        let key = u32::from_ne_bytes(key) as usize;
        if key > self.max_entries {
            return None;
        }

        let idx = self.stride_layout.size() * key;
        let ptr = self.data.expect("map not initialized").as_ptr() as usize;
        Some(ptr.checked_add(idx)? as *const u8)
    }

    pub fn update_elem(&mut self, key: &[u8], value: *const u8) -> Result<()> {
        let key = key.try_into().unwrap();
        let key = u32::from_ne_bytes(key) as usize;
        if key > self.max_entries {
            return Err(ErrorKind::InvalidInput.into());
        }

        let idx = self.stride_layout.size() * key;
        let ptr = self.data.expect("map not initialized").as_ptr() as usize;
        let ptr = ptr.checked_add(idx).ok_or(ErrorKind::InvalidInput)? as *mut u8;

        unsafe {
            ptr.copy_from(value, self.element_layout.size());
        }

        Ok(())
    }
}
