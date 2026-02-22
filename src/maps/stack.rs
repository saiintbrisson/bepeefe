use std::io::{ErrorKind, Result};
use std::sync::Mutex;

use super::array::Array;

#[derive(Debug)]
pub struct Stack {
    inner: Array,
    top: Mutex<usize>,
}

impl Stack {
    pub fn new(max_entries: u32, value_size: u32) -> Self {
        Self {
            inner: Array::new(max_entries, value_size),
            top: Mutex::new(0),
        }
    }

    pub fn key_size(&self) -> usize {
        self.inner.key_size()
    }

    pub fn value_size(&self) -> usize {
        self.inner.value_size()
    }

    pub fn lookup(&self, _key: &[u8]) -> Option<usize> {
        None
    }

    pub fn update(&self, _key: &[u8], _value: &[u8]) -> Result<()> {
        Err(ErrorKind::Unsupported.into())
    }

    pub fn clear(&self) {
        *self.top.lock().unwrap() = 0;
        self.inner.clear();
    }

    pub fn push(&self, value: &[u8]) -> Result<()> {
        let mut top = self.top.lock().unwrap();
        let key = (*top as u32).to_ne_bytes();
        self.inner.update(&key, value)?;
        *top += 1;
        Ok(())
    }

    pub fn pop(&self) -> Option<usize> {
        let mut top = self.top.lock().unwrap();
        if *top == 0 {
            return None;
        }
        *top -= 1;
        let key = (*top as u32).to_ne_bytes();
        self.inner.lookup(&key)
    }

    pub fn peek(&self) -> Option<usize> {
        let top = self.top.lock().unwrap();
        if *top == 0 {
            return None;
        }
        let key = ((*top - 1) as u32).to_ne_bytes();
        self.inner.lookup(&key)
    }

    pub fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        self.inner.read(offset)
    }

    pub fn write(&self, offset: usize, src: &[u8]) -> Result<()> {
        self.inner.write(offset, src)
    }

    pub fn read_bytes(&self, offset: usize, len: usize) -> Option<Vec<u8>> {
        self.inner.read_bytes(offset, len)
    }
}
