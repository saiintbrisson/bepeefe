use std::{collections::HashMap, path::Path, rc::Rc};

use object::{
    elf::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, STT_FUNC},
    File, Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget, SectionFlags,
    SectionIndex, Symbol, SymbolFlags,
};

// Relocation types

/// None
const R_BPF_NONE: u32 = 0;
/// ld_imm64 insn    32       r_offset + 4  S + A
const R_BPF_64_64: u32 = 1;
/// normal data      64       r_offset      S + A
const R_BPF_64_ABS64: u32 = 2;
/// normal data      32       r_offset      S + A
const R_BPF_64_ABS32: u32 = 3;
/// .BTF[.ext] data  32       r_offset      S + A
const R_BPF_64_NODYLD32: u32 = 4;
/// call insn        32       r_offset + 4  (S + A) / 8 - 1
const R_BPF_64_32: u32 = 10;

const EXECUTABLE_SECTION_FLAGS: u64 = (SHF_ALLOC | SHF_EXECINSTR) as u64;
const WRITABLE_SECTION_FLAGS: u64 = (SHF_ALLOC | SHF_WRITE) as u64;

pub fn load_elf(path: &impl AsRef<Path>, entry_fn: &[u8]) -> (Vec<u8>, usize) {
    let data = std::fs::read(path).unwrap();
    let mut loader = Loader::new(&data);

    let file = loader.file.clone();
    let main_sym = file.symbol_by_name_bytes(entry_fn).unwrap();
    loader.load_func(&main_sym);

    loader.relocate_symbols();

    let cursor = loader
        .loaded_sections
        .get(&main_sym.section_index().unwrap())
        .unwrap();
    let main_pos = (cursor + main_sym.address() as usize) / 8;

    (loader.code, main_pos)
}

struct Loader<'data> {
    file: Rc<File<'data, &'data [u8]>>,
    code: Vec<u8>,
    loaded_sections: HashMap<SectionIndex, usize>,
}

impl<'data> Loader<'data> {
    fn new(data: &'data [u8]) -> Self {
        Self {
            file: Rc::new(File::parse(data).unwrap()),
            code: Vec::with_capacity(data.len()),
            loaded_sections: HashMap::new(),
        }
    }

    fn load_section(&mut self, section: SectionIndex) {
        if self.loaded_sections.contains_key(&section) {
            return;
        }

        let file = self.file.clone();
        let section = file.section_by_index(section).expect("invalid section");

        match section.flags() {
            SectionFlags::Elf {
                sh_flags: EXECUTABLE_SECTION_FLAGS | WRITABLE_SECTION_FLAGS,
            } => {}
            _ => panic!("section is not executable"),
        }

        let cursor = self.code.len();
        let data = section.data().unwrap();
        self.code.extend_from_slice(data);

        self.loaded_sections.insert(section.index(), cursor);

        for (_, rel) in section.relocations() {
            match rel.target() {
                RelocationTarget::Symbol(target) => {
                    let target = self.file.symbol_by_index(target).unwrap();
                    let target = target.section_index().unwrap();
                    self.load_section(target);
                }
                RelocationTarget::Section(target) => self.load_section(target),
                _ => {}
            }
        }
    }

    fn load_func(&mut self, sym: &Symbol<'data, 'data, &'data [u8]>) {
        match sym.flags() {
            SymbolFlags::Elf { st_info, .. } if st_info & 0xF == STT_FUNC => {}
            _ => panic!("symbol {:?} is not a function", sym.name()),
        }

        let section = sym
            .section_index()
            .expect("symbol must be contained in a section");
        self.load_section(section);
    }

    fn relocate_symbols(&mut self) {
        for (section, cursor) in &self.loaded_sections {
            let section = self.file.section_by_index(*section).unwrap();

            for (offset, rel) in section.relocations() {
                let RelocationFlags::Elf { r_type } = rel.flags() else {
                    panic!("unknown flags {:?}", rel.flags());
                };

                match (r_type, rel.target()) {
                    (R_BPF_64_32, RelocationTarget::Symbol(target)) => {
                        let target = self.file.symbol_by_index(target).expect("invalid symbol");
                        let target_section = target.section_index().unwrap();
                        let target_section_offset =
                            self.loaded_sections.get(&target_section).unwrap();

                        let target_offset = *target_section_offset + target.address() as usize;
                        let offset = cursor + offset as usize + 4;

                        let call_offset = &self.code[offset..offset + 4];
                        let call_offset = i32::from_ne_bytes(call_offset.try_into().unwrap());

                        let fin =
                            (target_offset / 8) as i32 - ((offset - 4) / 8) as i32 + call_offset;

                        (&mut self.code[offset..offset + 4]).copy_from_slice(&fin.to_ne_bytes());
                    }
                    // (R_BPF_64_64, RelocationTarget::Symbol(target)) => {}
                    _ => unreachable!("{r_type}"),
                }
            }
        }
    }
}
