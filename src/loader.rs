use std::{collections::HashMap, path::Path, rc::Rc};

use btf::Btf;
use object::{File, Object, ObjectSymbol, SectionIndex};

mod btf;
mod elf;

pub struct Program {
    pub code: Vec<u8>,
    pub entry: usize,
    pub btf: Option<Btf>,
}

pub fn load_elf(path: &impl AsRef<Path>, entry_fn: &[u8]) -> Program {
    let data = std::fs::read(path).unwrap();
    let mut loader = Loader::new(&data);

    let file = loader.file.clone();
    let entry_sym = file.symbol_by_name_bytes(entry_fn).unwrap();
    loader.load_func(&entry_sym);

    if let Some(btf) = loader.load_btf() {
        dbg!(&btf);
        // let maps = btf.load_maps();
        // maps.iter().map(|(name, map)| {
        //     let ty = map.r#type.expect("map missing type");
        // });
    }

    loader.relocate_symbols();

    let cursor = loader
        .loaded_sections
        .get(&entry_sym.section_index().unwrap())
        .unwrap();
    let entry = (cursor + entry_sym.address() as usize) / 8;

    Program {
        code: loader.code,
        entry,
        btf: loader.btf,
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
