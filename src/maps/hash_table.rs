use std::{
    alloc::Layout,
    hash::{Hash, Hasher},
    io::{ErrorKind, Result},
};

use crate::vm::mem::{Memory, Region};

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum Flag {
    Vacant,
    Deleted,
    Occupied,
}

#[derive(Debug)]
enum Search {
    Match,
    Free,
    MatchOrFree,
}

#[derive(Debug)]
pub struct HashTable {
    data: Option<(Vec<Flag>, Region)>,

    max_entries: usize,

    key_layout: Layout,
    value_layout: Layout,
    entry_layout: Layout,

    value_offset: usize,
}

impl HashTable {
    pub fn new(key_size: u32, value_size: u32, max_entries: u32) -> Self {
        // The kernel aligns key and value to 8 bytes
        // https://github.com/torvalds/linux/blob/8765f467912ff0d4832eeaf26ae573792da877e7/kernel/bpf/hashtab.c#L516-L521
        let key_layout = Layout::from_size_align(key_size as usize, 8).unwrap();
        let value_layout = Layout::from_size_align(value_size as usize, 8).unwrap();
        let (entry_layout, value_offset) = key_layout.extend(value_layout).unwrap();

        Self {
            data: None,

            max_entries: max_entries as usize,

            key_layout,

            entry_layout: entry_layout.pad_to_align(),

            value_layout,
            value_offset,
        }
    }

    pub fn key_size(&self) -> usize {
        self.key_layout.size()
    }

    pub fn value_size(&self) -> usize {
        self.value_layout.size()
    }

    pub fn init(&mut self, mem: &mut Memory) {
        let entries_layout = Layout::from_size_align(
            self.entry_layout.size() * self.max_entries,
            self.entry_layout.align(),
        )
        .expect("invalid map config");

        let entries_region = mem.alloc_layout(entries_layout).expect("vm mem oom");
        self.data = Some((vec![Flag::Vacant; self.max_entries], entries_region))
    }

    fn find_match(&self, mem: &Memory, key: &[u8]) -> Option<usize> {
        let (flags, data_region) = self.data.as_ref().unwrap();
        let data_start = data_region.start();
        let hash = hash(key);
        let mut idx = (hash % self.max_entries as u64) as usize;

        loop {
            let flag = flags[idx];
            let entry_ptr = data_start + idx * self.entry_layout.size();

            match flag {
                Flag::Vacant => return None,
                Flag::Deleted => {}
                Flag::Occupied => {
                    let entry_key = mem.slice(entry_ptr, self.key_layout.size()).unwrap();
                    if entry_key == key {
                        return Some(entry_ptr);
                    }
                }
            }

            idx = (idx + 1) % self.max_entries;
        }
    }

    fn find_slot(&mut self, mem: &Memory, key: &[u8]) -> Option<usize> {
        let (flags, data_region) = self.data.as_mut().unwrap();
        let data_start = data_region.start();
        let hash = hash(key);
        let mut idx = (hash % self.max_entries as u64) as usize;
        let mut free_idx = None;

        loop {
            let flag = flags[idx];
            let entry_ptr = data_start + idx * self.entry_layout.size();

            match flag {
                Flag::Vacant => {
                    let slot_idx = free_idx.unwrap_or(idx);
                    flags[slot_idx] = Flag::Occupied;
                    return Some(data_start + slot_idx * self.entry_layout.size());
                }
                Flag::Deleted => {
                    if free_idx.is_none() {
                        free_idx = Some(idx);
                    }
                }
                Flag::Occupied => {
                    let entry_key = mem.slice(entry_ptr, self.key_layout.size()).unwrap();
                    if entry_key == key {
                        return Some(entry_ptr);
                    }
                }
            }

            idx = (idx + 1) % self.max_entries;
            if idx == (hash % self.max_entries as u64) as usize {
                return free_idx.map(|i| {
                    flags[i] = Flag::Occupied;
                    data_start + i * self.entry_layout.size()
                });
            }
        }
    }

    pub fn lookup(&self, mem: &Memory, key: &[u8]) -> Option<usize> {
        self.find_match(mem, key).map(|ptr| ptr + self.value_offset)
    }

    pub fn update(&mut self, mem: &mut Memory, key: &[u8], value: &[u8]) -> Result<()> {
        if key.len() != self.key_layout.size() {
            return Err(ErrorKind::InvalidInput.into());
        }
        if value.len() != self.value_layout.size() {
            return Err(ErrorKind::InvalidInput.into());
        }

        let key_ptr = self.find_slot(mem, key).ok_or(ErrorKind::OutOfMemory)?;
        let value_ptr = key_ptr + self.value_offset;

        mem.write_slice(key_ptr, key)?;
        mem.write_slice(value_ptr, value)?;

        Ok(())
    }

    pub(crate) fn update_from_guest(
        &mut self,
        mem: &mut Memory,
        key_addr: usize,
        value_addr: usize,
    ) -> Result<()> {
        let key_size = self.key_layout.size();
        let key = mem
            .slice(key_addr, key_size)
            .ok_or(ErrorKind::InvalidInput)?;

        let key_ptr = self.find_slot(mem, key).ok_or(ErrorKind::OutOfMemory)?;
        let value_ptr = key_ptr + self.value_offset;

        mem.copy_within(key_addr, key_ptr, key_size)?;
        mem.copy_within(value_addr, value_ptr, self.value_layout.size())?;

        Ok(())
    }
}

fn hash(key: &[u8]) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

// fn msi_lookup(hash: u64, exp: u32, idx: usize) -> usize {
//     let mask = (1 << exp) - 1;
//     let step = (hash as usize >> (64 - exp)) | 1;
//     return (idx + step) & mask;
// }

// // Compute the next candidate index. Initialize idx to the hash.
// int32_t ht_lookup(uint64_t hash, int exp, int32_t idx)
// {
//     uint32_t mask = ((uint32_t)1 << exp) - 1;
//     uint32_t step = (hash >> (64 - exp)) | 1;
//     return (idx + step) & mask;
// }

// Entry -> key + value

// (word << (shift & 31)) | (word >> ((-shift) & 31))

mod jhash {
    //! I should probably swap the default hasher used for this one to make the
    //! map behave like the actual one implemented by the kernel.
    //!
    //! Reference: <https://github.com/torvalds/linux/blob/master/include/linux/jhash.h>``
    #![allow(dead_code)]

    const JHASH_INITVAL: u32 = 0xDEADBEEF;

    fn jenkins2(k: &[u32], initval: u32) -> u32 {
        let len = k.len() as u32;
        let [mut a, mut b, mut c] = [JHASH_INITVAL + (len << 2) + initval; 3];

        let mut chunks = k.chunks(3).peekable();
        loop {
            let Some(chunk) = chunks.next() else {
                break;
            };

            a += chunk.get(0).copied().unwrap_or_default();
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
