use std::{
    alloc::Layout,
    io::{ErrorKind, Result},
    ptr::NonNull,
};

macro_rules! check_bounds {
    ($ty:ty, $ptr:expr, $start:expr, $end:expr) => {
        ($ptr as usize) >= ($start as usize)
            && ($ptr as usize + size_of::<$ty>()) <= ($end as usize)
    };
}

/// This is a very simple memory arena. The goal is to pass virtual memory
/// addresses to the VM and allow it to read everything it is allowed to, such
/// as the stack or map values.
pub struct VmMem {
    base_ptr: *const u8,
    tail_ptr: *mut u8,
    end_ptr: *const u8,
}

impl VmMem {
    /// Creates and allocated a new memory arena.
    ///
    /// # Panics
    ///
    /// If the capacity is not a multiple of two.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity.is_power_of_two());

        let mem_layout = Layout::from_size_align(capacity, size_of::<usize>()).unwrap();
        let data = unsafe { std::alloc::alloc_zeroed(mem_layout) };

        Self {
            base_ptr: data,
            tail_ptr: data,
            end_ptr: data.wrapping_byte_add(mem_layout.pad_to_align().size()),
        }
    }

    /// Allocates a new memory region with the size and alignment of the given
    /// layout. The returned region contains a well-aligned pointer to the
    /// allocated region.
    pub fn alloc_layout(&mut self, layout: Layout) -> Option<VmMemRegion> {
        let current_tail = self.tail_ptr;

        let align_offset = current_tail.align_offset(layout.align());
        let size = layout.pad_to_align().size() + align_offset;
        let new_tail = (current_tail as usize).checked_add(size)? as *mut u8;

        if new_tail as *const u8 > self.end_ptr {
            return None;
        }

        self.tail_ptr = new_tail;

        Some(VmMemRegion {
            base_ptr: self.base_ptr,
            start_ptr: current_tail.map_addr(|tail| tail + align_offset),
            end_ptr: new_tail,
        })
    }

    pub fn read_as<T>(&self, addr: GuestAddr) -> Option<T> {
        self.read_ptr(addr, size_of::<T>())
            .map(|ptr| unsafe { (ptr as *const T).read() })
    }

    pub fn read(&self, addr: GuestAddr, len: usize) -> Option<&[u8]> {
        self.read_ptr(addr, len)
            .map(|ptr| unsafe { std::slice::from_raw_parts(ptr as *const u8, len) })
    }

    #[inline(always)]
    fn read_ptr(&self, GuestAddr(addr): GuestAddr, len: usize) -> Option<*const u8> {
        let ptr = (self.base_ptr as usize).checked_add(addr)?;
        if ptr + len < self.end_ptr as usize {
            Some(ptr as *const u8)
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn write(&mut self, addr: GuestAddr, val: &[u8]) -> Result<()> {
        self.copy_from(addr, val.as_ptr(), val.len())
    }

    pub fn copy_from(
        &mut self,
        GuestAddr(addr): GuestAddr,
        from_ptr: *const u8,
        len: usize,
    ) -> Result<()> {
        let Some(ptr) = (self.base_ptr as usize)
            .checked_add(addr)
            .filter(|ptr| ptr + len <= self.end_ptr as usize)
        else {
            return Err(ErrorKind::InvalidInput.into());
        };

        unsafe {
            (ptr as *mut u8).copy_from(from_ptr, len);
        }

        Ok(())
    }

    pub fn into_guest_addr(&self, ptr: *const u8) -> Option<GuestAddr> {
        if check_bounds!((), ptr, self.base_ptr, self.end_ptr) {
            (ptr as usize)
                .checked_sub(self.base_ptr as usize)
                .map(GuestAddr)
        } else {
            None
        }
    }
}

pub struct VmMemRegion {
    base_ptr: *const u8,
    start_ptr: *mut u8,
    end_ptr: *const u8,
}

impl VmMemRegion {
    pub fn as_ptr(&self) -> NonNull<u8> {
        NonNull::new(self.start_ptr).expect("invalid region")
    }

    pub fn read_at_offset<T>(&self, offset: usize) -> Option<T> {
        let start = self.start_ptr as usize;
        let ptr = start.checked_add(offset)?;
        if check_bounds!(T, ptr, self.start_ptr, self.end_ptr) {
            Some(unsafe { (ptr as *const T).read() })
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn guest_addr(&self) -> GuestAddr {
        GuestAddr(
            (self.start_ptr as usize)
                .checked_sub(self.base_ptr as usize)
                .unwrap(),
        )
    }

    pub fn guest_end_addr(&self) -> GuestAddr {
        GuestAddr(
            (self.end_ptr as usize)
                .checked_sub(self.base_ptr as usize)
                .unwrap(),
        )
    }
}

#[derive(Default)]
pub struct GuestAddr(pub usize);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_allocation_up_to_limit() {
        type AllocType = [u8; 64];

        let mut vm = VmMem::new(128);
        assert_eq!(vm.base_ptr, vm.tail_ptr);

        let first_region = vm
            .alloc_layout(Layout::new::<AllocType>())
            .expect("failed to create region");
        assert_eq!(first_region.base_ptr, vm.base_ptr);
        assert_eq!(first_region.start_ptr, vm.base_ptr as *mut u8);
        assert_eq!(first_region.end_ptr, vm.tail_ptr);

        assert_eq!(first_region.base_ptr, first_region.start_ptr);

        assert_eq!(
            first_region.end_ptr,
            first_region
                .start_ptr
                .wrapping_byte_add(size_of::<AllocType>())
        );

        let second_region = vm
            .alloc_layout(Layout::new::<[u8; 64]>())
            .expect("failed to create region");
        assert_eq!(second_region.base_ptr, vm.base_ptr);
        assert_eq!(second_region.start_ptr, first_region.end_ptr as *mut u8);
        assert_eq!(second_region.end_ptr, vm.tail_ptr);

        assert_eq!(
            second_region.end_ptr,
            second_region
                .start_ptr
                .wrapping_byte_add(size_of::<AllocType>())
        );
    }

    #[test]
    fn alloc_respects_layout_alignment() {
        let mut vm = VmMem::new(128);
        assert_eq!(vm.base_ptr, vm.tail_ptr);

        let first_region = vm
            .alloc_layout(Layout::from_size_align(4, 4).unwrap())
            .expect("failed to create region");
        assert_eq!(first_region.start_ptr.align_offset(4), 0);
        assert_eq!(first_region.start_ptr, vm.tail_ptr.wrapping_sub(4));
        assert_eq!(first_region.end_ptr, vm.tail_ptr);

        let second_region = vm
            .alloc_layout(Layout::from_size_align(4, 8).unwrap())
            .expect("failed to create region");
        assert_eq!(second_region.start_ptr.align_offset(8), 0);
        assert_eq!(
            second_region.start_ptr as *const u8,
            first_region.end_ptr.wrapping_add(4)
        );
        assert_eq!(second_region.end_ptr, vm.tail_ptr);
    }
}
