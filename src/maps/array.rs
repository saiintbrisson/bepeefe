use std::{
    alloc::Layout,
    io::{ErrorKind, Result},
    sync::Mutex,
};

#[derive(Debug)]
pub struct Array {
    region: Mutex<Vec<u8>>,

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

        let total = stride_layout.size() * max_entries;

        Self {
            region: Mutex::new(vec![0u8; total]),
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

    pub fn lookup(&self, key: &[u8]) -> Option<usize> {
        let key: [u8; 4] = key.try_into().ok()?;
        let key = u32::from_ne_bytes(key) as usize;

        if key >= self.max_entries {
            return None;
        }

        Some(self.stride_layout.size() * key)
    }

    pub fn update(&self, key: &[u8], value: &[u8]) -> Result<()> {
        if value.len() != self.element_layout.size() {
            return Err(ErrorKind::InvalidInput.into());
        }

        let offset = self.lookup(key).ok_or(ErrorKind::InvalidInput)?;
        let mut data = self.region.lock().unwrap();
        data[offset..offset + value.len()].copy_from_slice(value);
        Ok(())
    }

    pub fn clear(&self) {
        self.region.lock().unwrap().fill(0);
    }

    /// Reads N bytes from the map storage at the given offset,
    /// ensuring the read stays within a single element's value bounds.
    pub fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        self.check_bounds(offset, N)?;
        let data = self.region.lock().unwrap();
        Some(data[offset..offset + N].try_into().unwrap())
    }

    /// Writes bytes to the map storage at the given offset,
    /// ensuring the write stays within a single element's value bounds.
    pub fn write(&self, offset: usize, src: &[u8]) -> Result<()> {
        self.check_bounds(offset, src.len())
            .ok_or(ErrorKind::InvalidInput)?;
        let mut data = self.region.lock().unwrap();
        data[offset..offset + src.len()].copy_from_slice(src);
        Ok(())
    }

    pub fn read_bytes(&self, offset: usize, len: usize) -> Option<Vec<u8>> {
        self.check_bounds(offset, len)?;
        let data = self.region.lock().unwrap();
        Some(data[offset..offset + len].to_vec())
    }

    /// Ensures an access at `offset` of `len` bytes stays within
    /// a single element's value region, never overflowing into
    /// stride padding or adjacent entries.
    fn check_bounds(&self, offset: usize, len: usize) -> Option<()> {
        let stride = self.stride_layout.size();
        let value_size = self.element_layout.size();

        if offset + len > stride * self.max_entries {
            return None;
        }
        if offset % stride + len > value_size {
            return None;
        }
        Some(())
    }
}
