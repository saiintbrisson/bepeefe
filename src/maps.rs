use std::sync::Arc;

use crate::{
    btf::{Btf, BtfTypeId},
    vm::mem::Memory,
};

mod array;
mod hash_table;

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
    Stack,
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

        pub fn lookup(&self, mem: &crate::vm::mem::Memory, key: &[u8]) -> Option<usize> {
            match self {
                $(Self::$name(map) => map.lookup(mem, key),)+
                _ => todo!(),
            }
        }

        #[allow(dead_code)]
        pub fn update(
            &mut self,
            mem: &mut crate::vm::mem::Memory,
            key: &[u8],
            value: &[u8],
        ) -> std::io::Result<()> {
            match self {
                $(Self::$name(map) => map.update(mem, key, value),)+
                _ => todo!(),
            }
        }

        pub(crate) fn update_from_guest(
            &mut self,
            mem: &mut crate::vm::mem::Memory,
            key_addr: usize,
            value_addr: usize,
        ) -> std::io::Result<()> {
            match self {
                $(Self::$name(map) => map.update_from_guest(mem, key_addr, value_addr),)+
                _ => todo!(),
            }
        }
    };
}

impl MapRepr {
    pub fn create_from_btf(mem: &mut Memory, btf: &Btf, spec: &MapSpec) -> Option<Self> {
        Some(match spec.r#type? {
            0 => Self::Unspec,
            1 => Self::Hash(hash_table::HashTable::new(
                mem,
                spec.key_size
                    .or_else(|| spec.key.and_then(|id| btf.get_type(id))?.kind.size(btf))
                    .expect("map missing key size"),
                spec.value_size
                    .or_else(|| spec.value.and_then(|id| btf.get_type(id))?.kind.size(btf))
                    .expect("map missing value size"),
                spec.max_entries?,
            )),
            2 => Self::Array(array::Array::new(
                mem,
                spec.max_entries?,
                spec.value_size
                    .or_else(|| spec.value.and_then(|id| btf.get_type(id))?.kind.size(btf))
                    .expect("map missing value size"),
            )),
            3 => Self::ProgArray,
            4 => Self::PerfEventArray,
            5 => Self::PercpuHash,
            6 => Self::PercpuArray,
            7 => Self::StackTrace,
            8 => Self::CgroupArray,
            9 => Self::LruHash,
            10 => Self::LruPercpuHash,
            11 => Self::LpmTrie,
            12 => Self::ArrayOfMaps,
            13 => Self::HashOfMaps,
            14 => Self::Devmap,
            15 => Self::Sockmap,
            16 => Self::Cpumap,
            17 => Self::Xskmap,
            18 => Self::Sockhash,
            19 => Self::CgroupStorage,
            20 => Self::ReuseportSockarray,
            21 => Self::PercpuCgroupStorage,
            22 => Self::Queue,
            23 => Self::Stack,
            24 => Self::SkStorage,
            25 => Self::DevmapHash,
            26 => Self::StructOps,
            27 => Self::Ringbuf,
            28 => Self::InodeStorage,
            29 => Self::TaskStorage,
            30 => Self::BloomFilter,
            31 => Self::UserRingbuf,
            32 => Self::CgrpStorage,
            _ => return None,
        })
    }

    delegate_map_impl! {
        Array, Hash,
    }
}
