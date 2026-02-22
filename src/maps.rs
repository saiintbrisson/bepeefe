use std::sync::Arc;

use crate::btf::{Btf, BtfTypeId};

mod array;
mod hash_table;
mod stack;

pub const BPF_MAP_TYPE_UNSPEC: u32 = 0;
pub const BPF_MAP_TYPE_HASH: u32 = 1;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_PROG_ARRAY: u32 = 3;
pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: u32 = 4;
pub const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
pub const BPF_MAP_TYPE_STACK_TRACE: u32 = 7;
pub const BPF_MAP_TYPE_CGROUP_ARRAY: u32 = 8;
pub const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
pub const BPF_MAP_TYPE_LRU_PERCPU_HASH: u32 = 10;
pub const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
pub const BPF_MAP_TYPE_ARRAY_OF_MAPS: u32 = 12;
pub const BPF_MAP_TYPE_HASH_OF_MAPS: u32 = 13;
pub const BPF_MAP_TYPE_DEVMAP: u32 = 14;
pub const BPF_MAP_TYPE_SOCKMAP: u32 = 15;
pub const BPF_MAP_TYPE_CPUMAP: u32 = 16;
pub const BPF_MAP_TYPE_XSKMAP: u32 = 17;
pub const BPF_MAP_TYPE_SOCKHASH: u32 = 18;
pub const BPF_MAP_TYPE_CGROUP_STORAGE: u32 = 19;
pub const BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: u32 = 20;
pub const BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: u32 = 21;
pub const BPF_MAP_TYPE_QUEUE: u32 = 22;
pub const BPF_MAP_TYPE_STACK: u32 = 23;
pub const BPF_MAP_TYPE_SK_STORAGE: u32 = 24;
pub const BPF_MAP_TYPE_DEVMAP_HASH: u32 = 25;
pub const BPF_MAP_TYPE_STRUCT_OPS: u32 = 26;
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;
pub const BPF_MAP_TYPE_INODE_STORAGE: u32 = 28;
pub const BPF_MAP_TYPE_TASK_STORAGE: u32 = 29;
pub const BPF_MAP_TYPE_BLOOM_FILTER: u32 = 30;
pub const BPF_MAP_TYPE_USER_RINGBUF: u32 = 31;
pub const BPF_MAP_TYPE_CGRP_STORAGE: u32 = 32;

#[derive(Clone, Debug, Default)]
pub struct MapSpec {
    pub name: String,
    pub r#type: Option<u32>,

    pub sec_idx: usize,
    pub sec_offset: u32,

    pub max_entries: Option<u32>,
    pub map_flags: Option<u32>,
    pub map_extra: Option<u32>,
    pub numa_node: Option<u32>,
    pub key_size: Option<u32>,
    pub value_size: Option<u32>,
    pub key: Option<BtfTypeId>,
    pub value: Option<BtfTypeId>,
    pub values: Option<BtfTypeId>,
    pub pinning: MapPinning,
    pub initial_data: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Default)]
pub enum MapPinning {
    #[default]
    None,
    ByName,
}

pub struct BpfMap {
    pub fd: i32,
    pub repr: MapRepr,
    pub spec: MapSpec,
    pub btf: Arc<Btf>,
}

#[repr(u32)]
#[derive(Debug)]
pub enum MapRepr {
    Unspec,
    Hash(hash_table::HashTable),
    Array(array::Array),
    ProgArray,
    PerfEventArray,
    PercpuHash,
    PercpuArray,
    StackTrace,
    CgroupArray,
    LruHash,
    LruPercpuHash,
    LpmTrie,
    ArrayOfMaps,
    HashOfMaps,
    Devmap,
    Sockmap,
    Cpumap,
    Xskmap,
    Sockhash,
    CgroupStorage,
    ReuseportSockarray,
    PercpuCgroupStorage,
    Queue,
    Stack(stack::Stack),
    SkStorage,
    DevmapHash,
    StructOps,
    Ringbuf,
    InodeStorage,
    TaskStorage,
    BloomFilter,
    UserRingbuf,
    CgrpStorage,
}

macro_rules! delegate_map_impl {
    ($($name:ident,)+) => {
        pub fn key_size(&self) -> usize {
            match self {
                $(Self::$name(map) => map.key_size(),)+
                _ => todo!(),
            }
        }

        pub fn value_size(&self) -> usize {
            match self {
                $(Self::$name(map) => map.value_size(),)+
                _ => todo!(),
            }
        }

        pub fn lookup(&self, key: &[u8]) -> Option<usize> {
            match self {
                $(Self::$name(map) => map.lookup(key),)+
                _ => todo!(),
            }
        }

        pub fn update(&self, key: &[u8], value: &[u8]) -> std::io::Result<()> {
            match self {
                $(Self::$name(map) => map.update(key, value),)+
                _ => todo!(),
            }
        }

        pub fn clear(&self) {
            match self {
                $(Self::$name(map) => map.clear(),)+
                _ => todo!(),
            }
        }

        pub fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
            match self {
                $(Self::$name(map) => map.read(offset),)+
                _ => todo!(),
            }
        }

        pub fn write(&self, offset: usize, src: &[u8]) -> std::io::Result<()> {
            match self {
                $(Self::$name(map) => map.write(offset, src),)+
                _ => todo!(),
            }
        }

        pub fn read_bytes(&self, offset: usize, len: usize) -> Option<Vec<u8>> {
            match self {
                $(Self::$name(map) => map.read_bytes(offset, len),)+
                _ => todo!(),
            }
        }
    };
}

impl MapRepr {
    pub fn create_from_btf(btf: &Btf, spec: &MapSpec) -> Option<Self> {
        Some(match spec.r#type? {
            BPF_MAP_TYPE_UNSPEC => Self::Unspec,
            BPF_MAP_TYPE_HASH => Self::Hash(hash_table::HashTable::new(
                spec.key_size
                    .or_else(|| spec.key.and_then(|id| btf.get_type(id))?.kind.size(btf))
                    .expect("map missing key size"),
                spec.value_size
                    .or_else(|| spec.value.and_then(|id| btf.get_type(id))?.kind.size(btf))
                    .expect("map missing value size"),
                spec.max_entries?,
            )),
            BPF_MAP_TYPE_ARRAY => Self::Array(array::Array::new(
                spec.max_entries?,
                spec.value_size
                    .or_else(|| spec.value.and_then(|id| btf.get_type(id))?.kind.size(btf))
                    .expect("map missing value size"),
            )),
            BPF_MAP_TYPE_PROG_ARRAY => Self::ProgArray,
            BPF_MAP_TYPE_PERF_EVENT_ARRAY => Self::PerfEventArray,
            BPF_MAP_TYPE_PERCPU_HASH => Self::PercpuHash,
            BPF_MAP_TYPE_PERCPU_ARRAY => Self::PercpuArray,
            BPF_MAP_TYPE_STACK_TRACE => Self::StackTrace,
            BPF_MAP_TYPE_CGROUP_ARRAY => Self::CgroupArray,
            BPF_MAP_TYPE_LRU_HASH => Self::LruHash,
            BPF_MAP_TYPE_LRU_PERCPU_HASH => Self::LruPercpuHash,
            BPF_MAP_TYPE_LPM_TRIE => Self::LpmTrie,
            BPF_MAP_TYPE_ARRAY_OF_MAPS => Self::ArrayOfMaps,
            BPF_MAP_TYPE_HASH_OF_MAPS => Self::HashOfMaps,
            BPF_MAP_TYPE_DEVMAP => Self::Devmap,
            BPF_MAP_TYPE_SOCKMAP => Self::Sockmap,
            BPF_MAP_TYPE_CPUMAP => Self::Cpumap,
            BPF_MAP_TYPE_XSKMAP => Self::Xskmap,
            BPF_MAP_TYPE_SOCKHASH => Self::Sockhash,
            BPF_MAP_TYPE_CGROUP_STORAGE => Self::CgroupStorage,
            BPF_MAP_TYPE_REUSEPORT_SOCKARRAY => Self::ReuseportSockarray,
            BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE => Self::PercpuCgroupStorage,
            BPF_MAP_TYPE_QUEUE => Self::Queue,
            BPF_MAP_TYPE_STACK => Self::Stack(stack::Stack::new(
                spec.max_entries?,
                spec.value_size
                    .or_else(|| spec.value.and_then(|id| btf.get_type(id))?.kind.size(btf))
                    .expect("map missing value size"),
            )),
            BPF_MAP_TYPE_SK_STORAGE => Self::SkStorage,
            BPF_MAP_TYPE_DEVMAP_HASH => Self::DevmapHash,
            BPF_MAP_TYPE_STRUCT_OPS => Self::StructOps,
            BPF_MAP_TYPE_RINGBUF => Self::Ringbuf,
            BPF_MAP_TYPE_INODE_STORAGE => Self::InodeStorage,
            BPF_MAP_TYPE_TASK_STORAGE => Self::TaskStorage,
            BPF_MAP_TYPE_BLOOM_FILTER => Self::BloomFilter,
            BPF_MAP_TYPE_USER_RINGBUF => Self::UserRingbuf,
            BPF_MAP_TYPE_CGRP_STORAGE => Self::CgrpStorage,
            _ => return None,
        })
    }

    delegate_map_impl! {
        Array, Hash, Stack,
    }

    pub fn delete(&self, key: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Hash(map) => map.delete(key),
            _ => Err(std::io::ErrorKind::Unsupported.into()),
        }
    }

    pub fn push(&self, value: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Stack(map) => map.push(value),
            _ => Err(std::io::ErrorKind::Unsupported.into()),
        }
    }

    pub fn pop(&self) -> Option<usize> {
        match self {
            Self::Stack(map) => map.pop(),
            _ => None,
        }
    }

    pub fn peek(&self) -> Option<usize> {
        match self {
            Self::Stack(map) => map.peek(),
            _ => None,
        }
    }
}
