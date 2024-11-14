#![allow(dead_code)]

use std::ffi::CString;

use object::{
    elf::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, STT_FUNC},
    Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget, SectionFlags,
    SectionIndex, Symbol, SymbolFlags,
};

use crate::maps::MapType;

use super::Loader;

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

impl<'data> Loader<'data> {
    pub fn load_section(&mut self, section: SectionIndex) {
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
                _ => panic!(),
            }
        }
    }

    pub fn load_func(&mut self, sym: &Symbol<'data, 'data, &'data [u8]>) {
        match sym.flags() {
            SymbolFlags::Elf { st_info, .. } if st_info & 0xF == STT_FUNC => {}
            _ => panic!("symbol {:?} is not a function", sym.name()),
        }

        let section = sym
            .section_index()
            .expect("symbol must be contained in a section");
        self.load_section(section);
    }

    pub fn relocate_symbols(&mut self, maps: &[(CString, MapType)]) {
        for (section, cursor) in &self.loaded_sections {
            let section = self.file.section_by_index(*section).unwrap();

            for (offset, rel) in section.relocations() {
                let RelocationFlags::Elf { r_type } = rel.flags() else {
                    panic!("unknown flags {:?}", rel.flags());
                };

                let (relo_target_name, relo_target_offset) = match rel.target() {
                    RelocationTarget::Symbol(target) => {
                        let target = self.file.symbol_by_index(target).expect("invalid symbol");
                        let target_section = target.section_index().unwrap();
                        let target_section_offset =
                            self.loaded_sections.get(&target_section).unwrap();
                        let target_offset = *target_section_offset + target.address() as usize;
                        (target.name(), target_offset)
                    }
                    target => todo!("target not supported {target:?}"),
                };

                let relo_ref_offset = cursor + offset as usize + 4;
                let relo_addend_offset = &self.code[relo_ref_offset..relo_ref_offset + 4];
                let relo_addend_offset = i32::from_ne_bytes(relo_addend_offset.try_into().unwrap());

                let relocated_offset = match r_type {
                    R_BPF_64_32 => {
                        (relo_target_offset / 8) as i32 - ((relo_ref_offset - 4) / 8) as i32
                            + relo_addend_offset
                    }
                    R_BPF_64_64 => {
                        let map = relo_target_name.ok().and_then(|relo_target_name| {
                            maps.iter()
                                .enumerate()
                                .find(|(_, (name, _))| name.to_string_lossy() == relo_target_name)
                        });

                        if let Some((map_idx, _)) = map {
                            map_idx as i32
                        } else {
                            (relo_target_offset / 8) as i32 + relo_addend_offset
                        }
                    }
                    _ => todo!("relocation type not supported {r_type}"),
                };

                (&mut self.code[relo_ref_offset..relo_ref_offset + 4])
                    .copy_from_slice(&relocated_offset.to_ne_bytes());
            }
        }
    }
}
