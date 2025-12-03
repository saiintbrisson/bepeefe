use std::{
    alloc::Layout,
    io::{ErrorKind, Result},
};

use crate::vm::mem::Region;

#[derive(Debug)]
pub struct Array {
    region: Option<Region>,

    max_entries: usize,

    /// The resulting value layout, without padding. Its size is provided by the map configuration.
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
            region: None,
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

    pub fn init(&mut self, mem: &mut crate::vm::mem::Memory) {
        let map_layout = Layout::from_size_align(
            self.stride_layout.size() * self.max_entries,
            self.stride_layout.align(),
        )
        .expect("invalid map config");

        self.region = Some(mem.alloc_layout(map_layout).expect("vm mem oom"));
    }

    pub fn lookup(&self, _: &crate::vm::mem::Memory, key: &[u8]) -> Option<usize> {
        let key: [u8; 4] = key.try_into().ok()?;
        let key = u32::from_ne_bytes(key) as usize;

        if key >= self.max_entries {
            return None;
        }

        let start = self.region.as_ref()?.start();
        Some(start + self.stride_layout.size() * key)
    }

    pub fn update(
        &mut self,
        mem: &mut crate::vm::mem::Memory,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        if value.len() != self.element_layout.size() {
            return Err(ErrorKind::InvalidInput.into());
        }

        let key: [u8; 4] = key.try_into().map_err(|_| ErrorKind::InvalidInput)?;
        let key = u32::from_ne_bytes(key) as usize;
        if key >= self.max_entries {
            return Err(ErrorKind::InvalidInput.into());
        }

        let start = self.region.as_ref().ok_or(ErrorKind::NotFound)?.start();
        let addr = start + self.stride_layout.size() * key;
        mem.write_slice(addr, value)
    }

    pub(crate) fn update_from_guest(
        &mut self,
        mem: &mut crate::vm::mem::Memory,
        key_addr: usize,
        value_addr: usize,
    ) -> Result<()> {
        let key = u32::from_ne_bytes(mem.read_as(key_addr).ok_or(ErrorKind::InvalidInput)?);

        if key as usize >= self.max_entries {
            return Err(ErrorKind::InvalidInput.into());
        }

        let start = self.region.as_ref().ok_or(ErrorKind::NotFound)?.start();
        let dest = start + key as usize * self.stride_layout.size();
        mem.copy_within(value_addr, dest, self.element_layout.size())
    }
}
