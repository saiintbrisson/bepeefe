use std::{alloc::Layout, io::Result};

pub struct Memory {
    buf: Vec<u8>,
    tail: usize,
}

#[derive(Debug)]
pub struct Region {
    start: usize,
    end: usize,
}

impl Region {
    pub fn start(&self) -> usize {
        self.start
    }

    pub fn end(&self) -> usize {
        self.end
    }
}

impl Memory {
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(
            capacity > 0 && capacity.is_power_of_two(),
            "memory capacity must be a non-zero power of two"
        );
        let buf = vec![0; capacity];
        Self { buf, tail: 0 }
    }

    /// Allocates a new memory region with the size and alignment of the given
    /// layout. The returned region contains a well-aligned pointer to the
    /// allocated region.
    pub fn alloc_layout(&mut self, layout: Layout) -> Option<Region> {
        let tail_ptr = self.buf.as_ptr().wrapping_add(self.tail);
        let offset = tail_ptr.align_offset(layout.align());
        let new_tail = self.tail + offset + layout.size();

        if new_tail > self.buf.len() {
            return None;
        }

        let current_tail = self.tail;
        self.tail = new_tail;

        Some(Region {
            start: current_tail + offset,
            end: new_tail,
        })
    }

    /// Reclaims the space of the tail region by moving our
    /// tail to the start of the region.
    ///
    /// Returns true if the region is indeed the last one.
    pub fn reclaim_region(&mut self, region: Region) -> bool {
        if region.end != self.tail {
            return false;
        }
        self.tail = region.start;
        true
    }
}

impl Memory {
    pub fn push_bytes(&mut self, buf: &[u8], align: Option<usize>) -> Region {
        let reg = self
            .alloc_layout(Layout::from_size_align(buf.len(), align.unwrap_or(8)).unwrap())
            .unwrap();
        self.buf[reg.start..reg.end].copy_from_slice(buf);
        reg
    }

    pub(crate) fn read_as<const N: usize>(&self, addr: usize) -> Option<[u8; N]> {
        if addr + N > self.tail {
            return None;
        }
        Some(self.buf[addr..addr + N].try_into().unwrap())
    }

    pub(crate) fn slice(&self, addr: usize, len: usize) -> Option<&[u8]> {
        if addr + len > self.tail {
            return None;
        }
        Some(&self.buf[addr..addr + len])
    }

    pub(crate) fn write_slice(&mut self, addr: usize, data: &[u8]) -> Result<()> {
        if addr + data.len() > self.tail {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        self.buf[addr..addr + data.len()].copy_from_slice(data);
        Ok(())
    }

    pub(crate) fn copy_within(&mut self, src: usize, dst: usize, len: usize) -> Result<()> {
        if src + len > self.tail || dst + len > self.tail {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        self.buf.copy_within(src..src + len, dst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_allocation_up_to_limit() {
        let mut mem = Memory::with_capacity(128);
        assert_eq!(mem.tail, 0);

        let first = mem
            .alloc_layout(Layout::new::<[u8; 64]>())
            .expect("failed to create region");
        assert_eq!(first.start, 0);
        assert_eq!(first.end, 64);
        assert_eq!(mem.tail, 64);

        let second = mem
            .alloc_layout(Layout::new::<[u8; 64]>())
            .expect("failed to create region");
        assert_eq!(second.start, first.end);
        assert_eq!(second.end, 128);
        assert_eq!(mem.tail, 128);

        assert!(mem.alloc_layout(Layout::new::<u8>()).is_none());
    }

    #[test]
    fn alloc_respects_layout_alignment() {
        let mut mem = Memory::with_capacity(128);

        let first = mem
            .alloc_layout(Layout::from_size_align(4, 4).unwrap())
            .expect("failed to create region");
        let first_ptr = mem.buf.as_ptr().wrapping_add(first.start);
        assert_eq!(first_ptr.align_offset(4), 0);
        assert_eq!(first.end - first.start, 4);

        let second = mem
            .alloc_layout(Layout::from_size_align(4, 8).unwrap())
            .expect("failed to create region");
        let second_ptr = mem.buf.as_ptr().wrapping_add(second.start);
        assert_eq!(second_ptr.align_offset(8), 0);
        assert_eq!(second.end - second.start, 4);
        assert_eq!(second.start, 8);
    }
}
