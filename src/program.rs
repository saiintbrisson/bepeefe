use std::{collections::HashMap, rc::Rc};

use btf::Btf;
use object::{File, Object, ObjectSymbol, SectionIndex};

use crate::maps::BpfMap;

pub mod btf;
pub mod elf;

pub struct Program {
    pub code: Vec<u8>,
    pub entry: usize,
    #[allow(dead_code)]
    pub btf: Option<Btf>,
    pub maps: Vec<BpfMap>,
}

struct MapDecl {
    sec_idx: usize,
    sec_offset: u32,
}

pub fn load_object(object: Vec<u8>, entry_fn: &str) -> Program {
    let mut loader = Loader::new(&object);
    loader.load_sections();

    let mut maps = Vec::new();

    if let Some(btf) = &loader.btf
        && let Some(maps_sec) = loader.btf_maps_sec
    {
        for (fd, btf_map) in btf::load_maps(btf, maps_sec).into_iter().enumerate() {
            let repr =
                crate::maps::MapRepr::create_from_btf(btf, &btf_map).expect("invalid map type");

            let bpf_map = BpfMap {
                // TODO: global FD for multiple programs
                fd: fd as _,
                name: btf_map.name.to_string_lossy().to_string(),
                repr,
            };
            maps.push((
                bpf_map,
                MapDecl {
                    sec_idx: btf_map.sec_idx,
                    sec_offset: btf_map.sec_offset,
                },
            ));
        }
    }

    loader.resolve_relocations(&maps[..]);

    let entry_sym = loader.file.symbol_by_name(entry_fn).unwrap();
    let entry_sec = loader
        .loaded_sections
        .get(&entry_sym.section_index().unwrap())
        .unwrap();
    let entry = (entry_sec + entry_sym.address() as usize) / 8;

    let maps = maps.into_iter().map(|(map, _)| map).collect();

    Program {
        code: loader.loaded_prog,
        entry,
        btf: loader.btf,
        maps,
    }
}

struct Loader<'data> {
    file: Rc<File<'data, &'data [u8]>>,
    loaded_prog: Vec<u8>,
    loaded_sections: HashMap<SectionIndex, usize>,
    btf: Option<Btf>,
    btf_maps_sec: Option<SectionIndex>,
}

impl<'data> Loader<'data> {
    fn new(data: &'data [u8]) -> Self {
        Self {
            file: Rc::new(File::parse(data).unwrap()),
            loaded_prog: Vec::with_capacity(data.len()),
            loaded_sections: HashMap::new(),
            btf: None,
            btf_maps_sec: None,
        }
    }
}
