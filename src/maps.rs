use crate::loader::btf::{BpfMapDeclaration, Btf};

mod array;
mod hash_table;

pub struct BpfMap {
    pub fd: i32,
    #[allow(dead_code)]
    pub name: String,
    pub repr: MapRepr,
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

        pub fn init(&mut self, mem: &mut crate::vm::mem::VmMem) {
            match self {
                $(Self::$name(map) => map.init(mem),)+
                _ => todo!(),
            }
        }

        pub fn lookup_elem(&self, key: &[u8]) -> Option<*const u8> {
            match self {
                $(Self::$name(map) => map.lookup_elem(key),)+
                _ => todo!(),
            }
        }

        #[allow(dead_code)]
        pub fn update_elem(&mut self, key: &[u8], value: *const u8) -> std::io::Result<()> {
            match self {
                $(Self::$name(map) => map.update_elem(key, value),)+
                _ => todo!(),
            }
        }
    };
}

impl MapRepr {
    pub fn create_from_btf(btf: &Btf, map: &BpfMapDeclaration<'_>) -> Option<Self> {
        Some(match map.r#type? {
            0 => Self::Unspec,
            1 => Self::Hash(hash_table::HashTable::new(
                map.key_size
                    .or_else(|| map.key?.kind.size(btf))
                    .expect("map missing key size"),
                map.value_size
                    .or_else(|| map.value?.kind.size(btf))
                    .expect("map missing value size"),
                map.max_entries?,
            )),
            2 => Self::Array(array::Array::new(
                map.max_entries?,
                map.value_size
                    .or_else(|| map.value?.kind.size(btf))
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
