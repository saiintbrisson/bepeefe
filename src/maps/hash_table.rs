use std::{
    alloc::Layout,
    hash::{Hash, Hasher},
    io::{ErrorKind, Result},
    ptr::NonNull,
};

#[repr(u8)]
enum Flag {
    Vacant,
    Deleted,
    Occupied,
}

enum Search {
    Match,
    Free,
    MatchOrFree,
}

#[derive(Debug)]
pub struct HashTable {
    flags_ptr: Option<NonNull<Flag>>,
    data_ptr: Option<NonNull<u8>>,

    max_entries: usize,

    key_layout: Layout,
    value_layout: Layout,
    entry_layout: Layout,

    value_offset: usize,
}

impl HashTable {
    pub fn new(key_size: u32, value_size: u32, max_entries: u32) -> Self {
        let key_layout = Layout::from_size_align(key_size as usize, 8).unwrap();
        let value_layout = Layout::from_size_align(value_size as usize, 8).unwrap();
        let (entry_layout, value_offset) = key_layout.extend(value_layout).unwrap();

        Self {
            flags_ptr: None,
            data_ptr: None,

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

    pub fn init(&mut self, mem: &mut crate::vm::mem::VmMem) {
        let flag_layout = Layout::new::<Flag>()
            .repeat_packed(self.max_entries)
            .expect("map capacity is over limit");

        let (entries_layout, _) = self
            .entry_layout
            .repeat(self.max_entries)
            .expect("invalid map config");

        let (map_layout, entries_offset) = flag_layout.extend(entries_layout).unwrap();

        let alloc_ptr = mem.alloc_layout(map_layout).expect("vm mem oom").as_ptr();
        self.flags_ptr = Some(alloc_ptr.cast());
        self.data_ptr = Some(alloc_ptr.map_addr(|ptr| ptr.saturating_add(entries_offset)));
    }

    fn find(&self, key: &[u8], search: Search) -> Option<NonNull<u8>> {
        let flags_ptr = self.flags_ptr.expect("map not initialized");
        let data_ptr = self.data_ptr.expect("map not initialized");

        let hash = hash(key);
        let mut idx = (hash % self.max_entries as u64) as usize;

        let mut last_free = None;

        loop {
            let flag_ptr = flags_ptr.map_addr(|ptr| ptr.checked_add(idx).unwrap());
            let entry_ptr =
                data_ptr.map_addr(|ptr| ptr.checked_add(idx * self.entry_layout.size()).unwrap());

            match (unsafe { flag_ptr.read() }, &search) {
                (Flag::Vacant | Flag::Deleted, Search::Free) => return Some(entry_ptr),
                (Flag::Vacant, Search::Match) => return None,
                (Flag::Deleted, Search::Match) | (Flag::Occupied, Search::Free) => {}

                (Flag::Occupied, Search::Match | Search::MatchOrFree) => {
                    let entry_key: &[u8] = unsafe {
                        std::slice::from_raw_parts(entry_ptr.as_ptr(), self.key_layout.size())
                    };

                    if entry_key == key {
                        return Some(entry_ptr);
                    }
                }
                (Flag::Deleted, Search::MatchOrFree) => {
                    last_free = Some(entry_ptr);
                }
                (Flag::Vacant, Search::MatchOrFree) => break,
            }

            idx += 1;
        }

        last_free
    }

    pub fn lookup_elem(&self, key: &[u8]) -> Option<*const u8> {
        self.find(key, Search::Match)
            .map(|ptr| ptr.as_ptr() as *const u8)
    }

    pub fn update_elem(&mut self, key: &[u8], value: *const u8) -> Result<()> {
        let ptr = self
            .find(key, Search::MatchOrFree)
            .map(|ptr| ptr.as_ptr() as *const u8)
            .ok_or(ErrorKind::OutOfMemory)?;
        let ptr = ptr.map_addr(|addr| addr + self.value_offset) as *mut u8;

        unsafe {
            ptr.copy_from(value, self.value_layout.size());
        }

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
