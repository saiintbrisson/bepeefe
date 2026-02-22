use std::borrow::Cow;

use crate::PreparedProgram;

const PTR_OFFSET_MASK: u64 = u32::MAX as u64;
const TAG_MAP_FD_MASK: u64 = (u16::MAX as u64) << 40;

#[repr(u64)]
pub(super) enum PtrTag {
    Map = 1 << 56,
    Local = 2 << 56,
}

// #[derive(Default)]
// struct StackFrame {
//     ret_addr: usize,
//     registers: [u64; 4],
// }

pub struct State {
    pub(crate) prog: PreparedProgram,
    pub(crate) buf: Vec<u8>,
    pub(crate) pc: usize,
    pub(crate) registers: [u64; 11],
    pub(crate) exit: bool,
}

impl State {
    pub fn read<const SIZE: usize>(&self, ptr: u64) -> [u8; SIZE] {
        let offset = (ptr & PTR_OFFSET_MASK) as usize;

        if ptr & PtrTag::Map as u64 != 0 {
            let map_fd = (ptr & TAG_MAP_FD_MASK) >> TAG_MAP_FD_MASK.trailing_zeros();
            let map = self.prog.vm.find_map(map_fd as u16).unwrap();
            map.repr.read(offset).unwrap()
        } else if ptr & PtrTag::Local as u64 != 0 {
            self.buf[offset..offset + SIZE].try_into().unwrap()
        } else {
            panic!("illegal pointer tag for {ptr:X}")
        }
    }

    pub fn write(&mut self, ptr: u64, src: &[u8]) {
        let offset = (ptr & PTR_OFFSET_MASK) as usize;

        if ptr & PtrTag::Map as u64 != 0 {
            let map_fd = (ptr & TAG_MAP_FD_MASK) >> TAG_MAP_FD_MASK.trailing_zeros();
            let map = self.prog.vm.find_map(map_fd as u16).unwrap();
            map.repr.write(offset, src).unwrap();
        } else if ptr & PtrTag::Local as u64 != 0 {
            (&mut self.buf[offset..offset + src.len()]).copy_from_slice(src);
        } else {
            panic!("illegal access for pointer {ptr:X}")
        }
    }

    pub fn read_bytes(&self, ptr: u64, len: usize) -> Cow<'_, [u8]> {
        let offset = (ptr & PTR_OFFSET_MASK) as usize;

        if ptr & PtrTag::Map as u64 != 0 {
            let map_fd = (ptr & TAG_MAP_FD_MASK) >> TAG_MAP_FD_MASK.trailing_zeros();
            let map = self.prog.vm.find_map(map_fd as u16).unwrap();
            map.repr.read_bytes(offset, len).unwrap().into()
        } else if ptr & PtrTag::Local as u64 != 0 {
            (&self.buf[offset..offset + len]).into()
        } else {
            panic!("illegal pointer tag for {ptr:X}")
        }
    }

    pub fn try_buf(&self, ptr: u64) -> Option<&[u8]> {
        let offset = (ptr & PTR_OFFSET_MASK) as usize;

        if ptr & PtrTag::Local as u64 != 0 {
            self.buf.get(offset..)
        } else {
            None
        }
    }

    pub fn call(&mut self, _offset: i32) {
        todo!()
        // assert!(
        //     self.call_stack.len() < 8,
        //     "no more than 8 nested calls allowed"
        // );

        // self.call_stack.push(StackFrame {
        //     ret_addr: self.code.pc,
        //     registers: self.registers[6..=9].try_into().unwrap(),
        // });

        // self.registers[10] -= STACK_FUNCTION_SIZE as u64;
        // self.code.add_offset(offset as isize);
    }

    pub fn call_exit(&mut self) {
        self.exit = true;
        // TODO: pop stack
        // let Some(frame) = self.call_stack.pop() else {
        //     self.exit = true;
        //     return;
        // };

        // self.code.pc = frame.ret_addr;
        // self.registers[10] += STACK_FUNCTION_SIZE as u64;

        // // Registers R6-R9 are restored while R1-R5 are reset to unreadable.
        // // https://github.com/torvalds/linux/blob/master/Documentation/bpf/classic_vs_extended.rst
        // self.registers[1..=5].fill(0);
        // self.registers[6..=9].copy_from_slice(&frame.registers);
    }

    pub fn lookup_elem(&self, map_fd: u16, key: u64) -> Option<u64> {
        let map = self.prog.vm.find_map(map_fd).unwrap();
        let key = self.read_bytes(key, map.repr.key_size());
        let elem = map.repr.lookup(&key)?;
        Some(PtrTag::Map as u64 | ((map_fd as u64) << 40) | elem as u64)
    }

    pub fn map_update(&self, map_fd: u16, key_ptr: u64, value_ptr: u64) -> std::io::Result<()> {
        let map = self
            .prog
            .vm
            .find_map(map_fd)
            .ok_or(std::io::ErrorKind::NotFound)?;
        let key = self.read_bytes(key_ptr, map.repr.key_size());
        let value = self.read_bytes(value_ptr, map.repr.value_size());
        map.repr.update(&key, &value)
    }

    pub fn map_delete(&self, map_fd: u16, key_ptr: u64) -> std::io::Result<()> {
        let map = self
            .prog
            .vm
            .find_map(map_fd)
            .ok_or(std::io::ErrorKind::NotFound)?;
        let key = self.read_bytes(key_ptr, map.repr.key_size());
        map.repr.delete(&key)
    }

    pub fn map_push(&self, map_fd: u16, value_ptr: u64) -> std::io::Result<()> {
        let map = self
            .prog
            .vm
            .find_map(map_fd)
            .ok_or(std::io::ErrorKind::NotFound)?;
        let value = self.read_bytes(value_ptr, map.repr.value_size());
        map.repr.push(&value)
    }

    pub fn map_pop(&mut self, map_fd: u16, dest_ptr: u64) -> std::io::Result<()> {
        let map = self
            .prog
            .vm
            .find_map(map_fd)
            .ok_or(std::io::ErrorKind::NotFound)?;
        let value_size = map.repr.value_size();
        let offset = map.repr.pop().ok_or(std::io::ErrorKind::NotFound)?;
        let bytes = map
            .repr
            .read_bytes(offset, value_size)
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        self.write(dest_ptr, &bytes);
        Ok(())
    }

    pub fn map_peek(&mut self, map_fd: u16, dest_ptr: u64) -> std::io::Result<()> {
        let map = self
            .prog
            .vm
            .find_map(map_fd)
            .ok_or(std::io::ErrorKind::NotFound)?;
        let value_size = map.repr.value_size();
        let offset = map.repr.peek().ok_or(std::io::ErrorKind::NotFound)?;
        let bytes = map
            .repr
            .read_bytes(offset, value_size)
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        self.write(dest_ptr, &bytes);
        Ok(())
    }

    pub fn add_offset(&mut self, offset: isize) {
        self.pc = (self.pc as isize + offset) as usize;
    }
}

impl Drop for State {
    fn drop(&mut self) {
        let mut buf = std::mem::take(&mut self.buf);
        buf.fill(0);

        self.prog.buf_pool.write().unwrap().push(buf);
    }
}
