use std::{
    alloc::Layout,
    io::{ErrorKind, Result},
    ptr::NonNull,
};

pub struct VmMem {
    base_ptr: *const u8,
    tail_ptr: *mut u8,
    end_ptr: *const u8,
}

impl VmMem {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity.is_power_of_two());

        let mem_layout = Layout::new::<u8>().repeat_packed(capacity).unwrap();
        let data = unsafe { std::alloc::alloc_zeroed(mem_layout) };

        Self {
            base_ptr: data,
            tail_ptr: data,
            end_ptr: data.wrapping_byte_add(mem_layout.pad_to_align().size()),
        }
    }

    pub fn alloc_layout(&mut self, layout: Layout) -> Option<VmMemRegion> {
        let size = layout.pad_to_align().size();
        let current_tail = self.tail_ptr;
        let new_tail = (current_tail as usize).checked_add(size)? as *mut u8;

        if new_tail as *const u8 > self.end_ptr {
            return None;
        }

        self.tail_ptr = new_tail;

        Some(VmMemRegion {
            base_ptr: current_tail,
            start_ptr: current_tail,
            end_ptr: new_tail,
        })
    }

    pub fn read_as<T>(&self, GuestAddr(addr): GuestAddr) -> Option<T> {
        let ptr = (self.base_ptr as usize).checked_add(addr)?;
        if ptr + size_of::<T>() <= self.end_ptr as usize {
            Some(unsafe { (ptr as *const T).read() })
        } else {
            None
        }
    }

    pub fn read(&self, GuestAddr(addr): GuestAddr, len: usize) -> Option<&[u8]> {
        let ptr = (self.base_ptr as usize).checked_add(addr)?;
        if ptr + len <= self.end_ptr as usize {
            Some(unsafe { std::slice::from_raw_parts(ptr as *const u8, len) })
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
        if ptr <= self.end_ptr {
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
    pub fn into_ptr(self) -> NonNull<u8> {
        NonNull::new(self.start_ptr).expect("invalid region")
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

        vm.alloc_layout(Layout::new::<[u8; 64]>());
    }
}
