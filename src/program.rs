use std::{collections::HashMap, rc::Rc};

use btf::Btf;
use object::{File, Object, ObjectSymbol, SectionIndex};

use crate::maps::MapType;

pub mod btf;
pub mod elf;

pub struct Program {
    pub code: Vec<u8>,
    pub entry: usize,
    #[allow(dead_code)]
    pub btf: Option<Btf>,
    pub maps: Vec<ProgramMap>,
}

pub struct ProgramMap {
    #[allow(dead_code)]
    pub name: String,
    pub inner: MapType,
}

pub fn load_object(object: Vec<u8>, entry_fn: &str) -> Program {
    let mut loader = Loader::new(&object);

    let file = loader.file.clone();
    let entry_sym = file.symbol_by_name(entry_fn).unwrap();
    loader.load_func(&entry_sym);

    let mut maps = Vec::new();
    if let Some(btf) = loader.load_btf() {
        let btf_maps = btf.load_maps();
        for (name, map) in btf_maps {
            let map = crate::maps::MapType::create_from_btf(btf, map).expect("invalid map type");
            maps.push((name.to_owned(), map));
        }
    }

    loader.relocate_symbols(&maps[..]);

    let cursor = loader
        .loaded_sections
        .get(&entry_sym.section_index().unwrap())
        .unwrap();
    let entry = (cursor + entry_sym.address() as usize) / 8;

    let maps = maps
        .into_iter()
        .map(|(name, map)| ProgramMap {
            name: name.to_str().unwrap().to_owned(),
            inner: map,
        })
        .collect();

    Program {
        code: loader.code,
        entry,
        btf: loader.btf,
        maps,
    }
}

struct Loader<'data> {
    file: Rc<File<'data, &'data [u8]>>,
    code: Vec<u8>,
    loaded_sections: HashMap<SectionIndex, usize>,
    btf: Option<Btf>,
}

impl<'data> Loader<'data> {
    fn new(data: &'data [u8]) -> Self {
        Self {
            file: Rc::new(File::parse(data).unwrap()),
            code: Vec::with_capacity(data.len()),
            loaded_sections: HashMap::new(),
            btf: None,
        }
    }
}
