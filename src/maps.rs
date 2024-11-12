pub struct BpfMap {}

#[repr(u32)]
#[derive(Debug)]
pub enum MapType {
    Unspec = 0,
    Hash = 1,
    Array = 2,
    ProgArray = 3,
    PerfEventArray = 4,
    PercpuHash = 5,
    PercpuArray = 6,
    StackTrace = 7,
    CgroupArray = 8,
    LruHash = 9,
    LruPercpuHash = 10,
    LpmTrie = 11,
    ArrayOfMaps = 12,
    HashOfMaps = 13,
    Devmap = 14,
    Sockmap = 15,
    Cpumap = 16,
    Xskmap = 17,
    Sockhash = 18,
    CgroupStorage = 19,
    ReuseportSockarray = 20,
    PercpuCgroupStorage = 21,
    Queue = 22,
    Stack = 23,
    SkStorage = 24,
    DevmapHash = 25,
    StructOps = 26,
    Ringbuf = 27,
    InodeStorage = 28,
    TaskStorage = 29,
    BloomFilter = 30,
    UserRingbuf = 31,
    CgrpStorage = 32,
}

impl MapType {
    pub fn from_u32(n: u32) -> Option<Self> {
        Some(match n {
            0 => Self::Unspec,
            1 => Self::Hash,
            2 => Self::Array,
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
}

// trait Map<K> {
//     fn lookup_elem(&self, key: K);
// }

// struct Foo {
//     maps: HashMap<usize, Box<dyn Map>>,
// }
