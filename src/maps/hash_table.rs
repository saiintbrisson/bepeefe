#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Mutex::lock only fails if poisoned, region/flags indexing is guarded by check_bounds and idx < max_entries"
)]

use std::{
    alloc::Layout,
    hash::{Hash, Hasher},
    sync::Mutex,
};

use crate::error::RuntimeError;

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum Flag {
    Vacant,
    Deleted,
    Occupied,
}

#[derive(Debug)]
pub struct HashTable {
    flags: Mutex<Vec<Flag>>,
    region: Mutex<Vec<u8>>,

    max_entries: usize,

    key_layout: Layout,
    value_layout: Layout,
    entry_layout: Layout,

    value_offset: usize,
}

impl HashTable {
    pub fn new(key_size: u32, value_size: u32, max_entries: u32) -> Result<Self, &'static str> {
        if max_entries == 0 {
            return Err("max_entries must be greater than 0");
        }
        if key_size == 0 {
            return Err("key_size must be greater than 0");
        }
        if value_size == 0 {
            return Err("value_size must be greater than 0");
        }

        // The kernel aligns key and value to 8 bytes
        // https://github.com/torvalds/linux/blob/8765f467912ff0d4832eeaf26ae573792da877e7/kernel/bpf/hashtab.c#L516-L521
        let key_layout =
            Layout::from_size_align(key_size as usize, 8).map_err(|_| "invalid key layout")?;
        let value_layout =
            Layout::from_size_align(value_size as usize, 8).map_err(|_| "invalid value layout")?;
        let (entry_layout, value_offset) = key_layout
            .extend(value_layout)
            .map_err(|_| "entry layout overflow")?;
        let entry_layout = entry_layout.pad_to_align();

        let total = entry_layout
            .size()
            .checked_mul(max_entries as usize)
            .ok_or("map storage size overflow")?;

        Ok(Self {
            flags: Mutex::new(vec![Flag::Vacant; max_entries as usize]),
            region: Mutex::new(vec![0u8; total]),

            max_entries: max_entries as usize,

            key_layout,
            entry_layout,
            value_layout,
            value_offset,
        })
    }

    pub fn key_size(&self) -> usize {
        self.key_layout.size()
    }

    pub fn value_size(&self) -> usize {
        self.value_layout.size()
    }

    pub fn lookup(&self, key: &[u8]) -> Option<usize> {
        let flags = self.flags.lock().unwrap();
        let data = self.region.lock().unwrap();
        self.find_match(&flags, &data, key)
            .map(|entry| entry + self.value_offset)
    }

    pub fn update(&self, key: &[u8], value: &[u8]) -> Result<(), RuntimeError> {
        if key.len() != self.key_layout.size() {
            return Err(RuntimeError::MapWrongKeySize {
                expected: self.key_layout.size(),
                got: key.len(),
            });
        }
        if value.len() != self.value_layout.size() {
            return Err(RuntimeError::MapWrongValueSize {
                expected: self.value_layout.size(),
                got: value.len(),
            });
        }

        let mut flags = self.flags.lock().unwrap();
        let mut data = self.region.lock().unwrap();

        let entry = self
            .find_slot(&mut flags, &data, key)
            .ok_or(RuntimeError::MapFull)?;
        let val_start = entry + self.value_offset;

        data[entry..entry + key.len()].copy_from_slice(key);
        data[val_start..val_start + value.len()].copy_from_slice(value);

        Ok(())
    }

    pub fn delete(&self, key: &[u8]) -> Result<(), RuntimeError> {
        let mut flags = self.flags.lock().unwrap();
        let data = self.region.lock().unwrap();

        let entry = self
            .find_match(&flags, &data, key)
            .ok_or(RuntimeError::MapKeyNotFound)?;
        let idx = entry / self.entry_layout.size();
        flags[idx] = Flag::Deleted;

        Ok(())
    }

    pub fn clear(&self) {
        self.flags.lock().unwrap().fill(Flag::Vacant);
        self.region.lock().unwrap().fill(0);
    }

    /// Reads N bytes at `offset`, which must land inside a value region
    /// (not the key portion or stride padding).
    pub fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        self.check_bounds(offset, N)?;
        let data = self.region.lock().unwrap();
        Some(data[offset..offset + N].try_into().unwrap())
    }

    pub fn write(&self, offset: usize, src: &[u8]) -> Result<(), RuntimeError> {
        self.check_bounds(offset, src.len())
            .ok_or(RuntimeError::MapKeyNotFound)?;
        let mut data = self.region.lock().unwrap();
        data[offset..offset + src.len()].copy_from_slice(src);
        Ok(())
    }

    pub fn read_bytes(&self, offset: usize, len: usize) -> Option<Vec<u8>> {
        self.check_bounds(offset, len)?;
        let data = self.region.lock().unwrap();
        Some(data[offset..offset + len].to_vec())
    }

    pub fn for_each_entry(&self, mut f: impl FnMut(&[u8], &[u8])) {
        let flags = self.flags.lock().unwrap();
        let data = self.region.lock().unwrap();
        let stride = self.entry_layout.size();
        let key_size = self.key_layout.size();
        let value_size = self.value_layout.size();
        for (idx, flag) in flags.iter().enumerate() {
            if matches!(flag, Flag::Occupied) {
                let base = idx * stride;
                let key = &data[base..base + key_size];
                let value = &data[base + self.value_offset..base + self.value_offset + value_size];
                f(key, value);
            }
        }
    }

    /// Ensures the access lands within the value portion of a single entry,
    /// never overflowing into the key, stride padding, or adjacent entries.
    fn check_bounds(&self, offset: usize, len: usize) -> Option<()> {
        let stride = self.entry_layout.size();
        let total = stride * self.max_entries;

        if offset + len > total {
            return None;
        }
        let pos = offset % stride;
        if pos < self.value_offset || pos + len > self.value_offset + self.value_layout.size() {
            return None;
        }
        Some(())
    }

    fn find_match(&self, flags: &[Flag], data: &[u8], key: &[u8]) -> Option<usize> {
        let hash = hash(key);
        let mut idx = (hash % self.max_entries as u64) as usize;

        loop {
            let flag = flags[idx];
            let entry = idx * self.entry_layout.size();

            match flag {
                Flag::Vacant => return None,
                Flag::Deleted => {}
                Flag::Occupied => {
                    let entry_key = &data[entry..entry + self.key_layout.size()];
                    if entry_key == key {
                        return Some(entry);
                    }
                }
            }

            idx = (idx + 1) % self.max_entries;
        }
    }

    fn find_slot(&self, flags: &mut [Flag], data: &[u8], key: &[u8]) -> Option<usize> {
        let hash = hash(key);
        let start = (hash % self.max_entries as u64) as usize;
        let mut idx = start;
        let mut free_idx = None;

        loop {
            let flag = flags[idx];
            let entry = idx * self.entry_layout.size();

            match flag {
                Flag::Vacant => {
                    let slot = free_idx.unwrap_or(idx);
                    flags[slot] = Flag::Occupied;
                    return Some(slot * self.entry_layout.size());
                }
                Flag::Deleted => {
                    if free_idx.is_none() {
                        free_idx = Some(idx);
                    }
                }
                Flag::Occupied => {
                    let entry_key = &data[entry..entry + self.key_layout.size()];
                    if entry_key == key {
                        return Some(entry);
                    }
                }
            }

            idx = (idx + 1) % self.max_entries;
            if idx == start {
                return free_idx.map(|i| {
                    flags[i] = Flag::Occupied;
                    i * self.entry_layout.size()
                });
            }
        }
    }
}

fn hash(key: &[u8]) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

mod jhash {
    //! I should probably swap the default hasher used for this one to make the
    //! map behave like the actual one implemented by the kernel.
    //!
    //! Reference: <https://github.com/torvalds/linux/blob/master/include/linux/jhash.h>``
    #![allow(
        dead_code,
        reason = "reference port of the kernel jhash, not yet wired up"
    )]

    const JHASH_INITVAL: u32 = 0xDEADBEEF;

    fn jenkins2(k: &[u32], initval: u32) -> u32 {
        let len = k.len() as u32;
        let [mut a, mut b, mut c] = [JHASH_INITVAL + (len << 2) + initval; 3];

        let mut chunks = k.chunks(3).peekable();
        while let Some(chunk) = chunks.next() {
            a += chunk.first().copied().unwrap_or_default();
            b += chunk.get(1).copied().unwrap_or_default();
            c += chunk.get(2).copied().unwrap_or_default();

            if chunks.peek().is_some() {
                jenkins_mix(&mut a, &mut b, &mut c);
            } else {
                jenkins_finish(&mut a, &mut b, &mut c);
            }
        }

        c
    }

    #[inline(always)]
    fn jenkins_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
        *a -= *c;
        *a ^= c.rotate_left(4);
        *c += *b;
        *b -= *a;
        *b ^= a.rotate_left(6);
        *a += *c;
        *c -= *b;
        *c ^= b.rotate_left(8);
        *b += *a;
        *a -= *c;
        *a ^= c.rotate_left(16);
        *c += *b;
        *b -= *a;
        *b ^= a.rotate_left(19);
        *a += *c;
        *c -= *b;
        *c ^= b.rotate_left(4);
        *b += *a;
    }

    #[inline(always)]
    fn jenkins_finish(a: &mut u32, b: &mut u32, c: &mut u32) {
        *c ^= *b;
        *c -= b.rotate_left(14);
        *a ^= *c;
        *a -= c.rotate_left(11);
        *b ^= *a;
        *b -= a.rotate_left(25);
        *c ^= *b;
        *c -= b.rotate_left(16);
        *a ^= *c;
        *a -= c.rotate_left(4);
        *b ^= *a;
        *b -= a.rotate_left(14);
        *c ^= *b;
        *c -= b.rotate_left(24);
    }
}
