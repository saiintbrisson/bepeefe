use std::{
    alloc::Layout,
    hash::{Hash, Hasher},
};

pub struct HashTable {
    data: Box<[u8]>,
    table: hashbrown::HashTable<usize>,
    key_size: usize,
    value_size: usize,
    entry_capacity: usize,
    entry_layout: Layout,
    key_offset: usize,
    value_offset: usize,
}

impl HashTable {
    pub fn new(key_size: usize, value_size: usize, entry_capacity: usize) -> Self {
        let flag_layout = Layout::new::<u8>();
        let key_layout = Layout::from_size_align(key_size, 4).unwrap();
        let value_layout = Layout::from_size_align(value_size, 8).unwrap();

        let (entry_layout, key_offset) = flag_layout.extend(key_layout).unwrap();
        let (entry_layout, value_offset) = entry_layout.extend(value_layout).unwrap();
        let entry_layout = entry_layout.pad_to_align();



        Self {
            data: vec![0; entry_layout.size()].into_boxed_slice(),
            table: Default::default(),
            
            key_size,
            key_offset,
            
            value_size,
            value_offset,

            entry_capacity,
            entry_layout,
        }
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> &mut [u8] {
        assert_eq!(key.len(), self.key_size);

        let mut hasher = std::hash::DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();

        self.table.insert_unique(hash, value, hasher)

        let mut idx = hash as usize;
        loop {
            idx = msi_lookup(hash, exp, idx);

            if (!t->ht[i]) {
                // empty, insert here
                if ((uint32_t)t->len+1 == (uint32_t)1<<EXP) {
                    return 0;  // out of memory
                }
                t->len++;
                t->ht[i] = key;
                return key;
            } else if (!strcmp(t->ht[i], key)) {
                // found, return canonical instance
                return t->ht[i];
            }
        }
    }
}

fn msi_lookup(hash: u64, exp: u32, idx: usize) -> usize {
    let mask = (1 << exp) - 1;
    let step = (hash as usize >> (64 - exp)) | 1;
    return (idx + step) & mask;
}

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
