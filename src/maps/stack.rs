use std::io::{ErrorKind, Result};

use super::array::Array;
use crate::vm::mem::Memory;

#[derive(Debug)]
pub struct Stack {
    inner: Array,
    top: usize,
}

impl Stack {
    pub fn new(mem: &mut Memory, max_entries: u32, value_size: u32) -> Self {
        Self {
            inner: Array::new(mem, max_entries, value_size),
            top: 0,
        }
    }

    pub fn key_size(&self) -> usize {
        self.inner.key_size()
    }

    pub fn value_size(&self) -> usize {
        self.inner.value_size()
    }

    pub fn lookup(&self, _: &Memory, _key: &[u8]) -> Option<usize> {
        None
    }

    pub fn update(&mut self, _: &mut Memory, _key: &[u8], _value: &[u8]) -> Result<()> {
        Err(ErrorKind::Unsupported.into())
    }

    pub fn clear(&mut self, mem: &mut Memory) {
        self.top = 0;
        self.inner.clear(mem);
    }

    pub fn update_from_guest(
        &mut self,
        _mem: &mut Memory,
        _key_addr: usize,
        _value_addr: usize,
    ) -> Result<()> {
        Err(ErrorKind::Unsupported.into())
    }

    pub fn push(&mut self, mem: &mut Memory, value: &[u8]) -> Result<()> {
        let key = (self.top as u32).to_ne_bytes();
        self.inner.update(mem, &key, value)?;
        self.top += 1;
        Ok(())
    }

    pub fn push_from_guest(&mut self, mem: &mut Memory, value_addr: usize) -> Result<()> {
        let key = (self.top as u32).to_ne_bytes();
        let dest = self.inner.lookup(mem, &key).ok_or(ErrorKind::OutOfMemory)?;
        mem.copy_within(value_addr, dest, self.inner.value_size())?;
        self.top += 1;
        Ok(())
    }

    pub fn pop(&mut self, mem: &Memory) -> Option<usize> {
        if self.top == 0 {
            return None;
        }
        self.top -= 1;
        let key = (self.top as u32).to_ne_bytes();
        self.inner.lookup(mem, &key)
    }

    pub fn pop_from_guest(&mut self, mem: &mut Memory, value_addr: usize) -> Result<()> {
        if self.top == 0 {
            return Err(ErrorKind::NotFound.into());
        }
        self.top -= 1;
        let key = (self.top as u32).to_ne_bytes();
        let src = self.inner.lookup(mem, &key).ok_or(ErrorKind::NotFound)?;
        mem.copy_within(src, value_addr, self.inner.value_size())
    }

    pub fn peek_from_guest(&self, mem: &mut Memory, value_addr: usize) -> Result<()> {
        if self.top == 0 {
            return Err(ErrorKind::NotFound.into());
        }
        let key = ((self.top - 1) as u32).to_ne_bytes();
        let src = self.inner.lookup(mem, &key).ok_or(ErrorKind::NotFound)?;
        mem.copy_within(src, value_addr, self.inner.value_size())
    }
}
