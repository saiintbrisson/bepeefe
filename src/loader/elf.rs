#![allow(dead_code)]

use object::{
    Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget,
    elf::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE},
};

use crate::{
    isa::Insn,
    loader::{
        MapDecl,
        btf::types::{BtfKind, BtfType},
    },
    maps::BpfMap,
};

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
/// Relocation used for jumping to program-local functions.
/// The value is 32-bit wide and is usually summed with the
/// program counter. The value is in number of 64-bit instructions.
///
/// If the resulting value falls within a wide instruction, it is
/// undefined behavior.
///
/// Per the kernel docs:
/// call insn        32       r_offset + 4  (S + A) / 8 - 1
const R_BPF_64_32: u32 = 10;

const EXECUTABLE_SECTION_FLAGS: u64 = (SHF_ALLOC | SHF_EXECINSTR) as u64;
const WRITABLE_SECTION_FLAGS: u64 = (SHF_ALLOC | SHF_WRITE) as u64;

const BPF_PSEUDO_MAP_FD: u8 = 1;

impl<'data> Loader<'data> {
    /// Iterates through all sections and loads
    ///
    pub fn load_sections(&mut self) {
        for sec in self.file.sections() {
            let name = sec.name().unwrap();
            match name {
                "maps" => panic!("legacy 'maps' section is not supported, use .maps"),
                ".BTF" => {
                    self.btf = Some(super::btf::load_btf(&sec).expect("malformed BTF section"));
                    continue;
                }
                ".BTF.ext" => {
                    self.btf_ext =
                        Some(super::btf::ext::load_btf_ext(&sec).expect("malformed BTF section"));
                    continue;
                }
                ".maps" => {
                    self.btf_maps_sec = Some(sec.index());
                    self.loaded_sections.insert(sec.index(), 0);
                    continue;
                }
                _ => {}
            }

            let cursor = self.loaded_prog.len();
            if self.loaded_prog.len() % Insn::WIDTH != 0 {
                // VM assumes all instructions are 8 byte aligned,
                // so we add necessary padding
                let padding = Insn::WIDTH - (cursor % Insn::WIDTH);
                self.loaded_prog.extend((0..padding).map(|_| 0));
            }
            let cursor = self.loaded_prog.len();

            let data = sec.data().unwrap();
            self.loaded_prog.extend_from_slice(data);

            self.loaded_sections.insert(sec.index(), cursor);
        }

        self.fixup_btf_datasecs();
    }

    /// Calculates and updates the offsets and sizes for
    /// BTF datasec entries.
    ///
    /// `Datasec`s describe an ELF section and its contents,
    /// generally used to inform the Kernel of special structs
    /// defined by the program. Each datasec entry contains a
    /// BTF type ID, a size, and the offset at which the entry is
    /// located in the section.
    ///
    /// Clang, however, does not populate sizes and offsets, and
    /// that is left for the linker/loader to do.
    ///
    /// An example is the special ELF `.maps` section. It describes
    /// BPF maps used by the program during execution. Each map has
    /// a corresponding entry in the Datasec type for that section.
    /// During relocation, `R_BPF_64_64` rels might want to find the
    /// correct map referenced by an instruction by comparing the
    /// target's value to the map's offset in the BTF struct.
    ///
    /// From libbpf:
    /// > Clang leaves DATASEC size and VAR offsets as zeroes, so we need to
    /// > fix this up. But BPF static linker already fixes this up and fills
    /// > all the sizes and offsets during static linking. So this step has
    /// > to be optional. But the STV_HIDDEN handling is non-optional for any
    /// > non-extern DATASEC, so the variable fixup loop below handles both
    /// > functions at the same time, paying the cost of BTF VAR <-> ELF
    /// > symbol matching just once.
    ///
    /// Ref: <https://github.com/libbpf/libbpf/blob/3d451d916f833afed06bfc74026a3650de8dd649/src/libbpf.c#L3321>
    fn fixup_btf_datasecs(&mut self) {
        let Some(btf) = &mut self.btf else { return };

        // Ugly, but necessary to avoid changing
        // everything to Rc<RefCell<BtfType>>
        let fixes: Vec<_> = btf
            .types
            .iter()
            .filter_map(|(&idx, ty)| {
                let BtfKind::Datasec { secinfos, size } = &ty.kind else {
                    return None;
                };

                let mut secinfos: Vec<_> = secinfos
                    .iter()
                    .copied()
                    .map(|mut info| {
                        btf.types
                            .get(&info.r#type)
                            .and_then(|ty| btf.strings.get(&ty.name_off))
                            .and_then(|name| {
                                self.file.symbol_by_name(name.to_string_lossy().as_ref())
                            })
                            .inspect(|sym| info.offset = sym.address() as _);
                        info
                    })
                    .collect();
                secinfos.sort_unstable_by_key(|ty| ty.offset);

                let btf_type = BtfType {
                    btf_id: idx,
                    name_off: ty.name_off,
                    kind: BtfKind::Datasec {
                        secinfos,
                        size: *size,
                    },
                };

                Some((idx, btf_type))
            })
            .collect();

        for (idx, ty) in fixes {
            btf.types.insert(idx, ty);
        }
    }

    /// This function resolves relocations and updates the code
    /// with the correct values. The actual relocation performed
    /// here is very simple: we find the start of each loaded
    /// section, an index to our loaded code buffer.
    pub fn resolve_relocations(&mut self, maps: &[(BpfMap, MapDecl)]) {
        for (section, section_base) in &self.loaded_sections {
            let section = self.file.section_by_index(*section).unwrap();

            for (rel_offset, rel) in section.relocations() {
                let RelocationFlags::Elf { r_type } = rel.flags() else {
                    panic!("unknown flags {:?}", rel.flags());
                };

                let (target_sec_idx, target_offset, target_addr) = match rel.target() {
                    RelocationTarget::Symbol(target) => {
                        let target = self.file.symbol_by_index(target).expect("invalid symbol");
                        let target_section = target.section_index().unwrap();
                        let target_section_base =
                            self.loaded_sections.get(&target_section).unwrap();
                        let target_addr = *target_section_base + target.address() as usize;
                        (target_section, target.address(), target_addr)
                    }
                    target => todo!("target not supported {target:?}"),
                };

                let rel_addr = *section_base + rel_offset as usize;
                let mut insn = Insn(u64::from_ne_bytes(
                    self.loaded_prog[rel_addr..rel_addr + 8].try_into().unwrap(),
                ));

                match r_type {
                    R_BPF_64_32 => {
                        let target_idx = (target_addr / 8) as i32;
                        let pc = ((rel_addr - 4) / 8) as i32;
                        insn.with_imm(target_idx - pc + insn.imm() - 1);
                    }
                    R_BPF_64_64 => {
                        let map = maps.iter().find(|(_, decl)| {
                            decl.sec_idx == target_sec_idx.0
                                && decl.sec_offset as u64 == target_offset
                        });

                        if let Some((map, _)) = map {
                            // We only support FD lookups, so fixup the
                            // instruction
                            insn.with_src_reg(BPF_PSEUDO_MAP_FD);
                            insn.with_imm(map.fd);
                        } else {
                            insn.with_imm((target_addr / 8) as i32 + insn.imm());
                        }
                    }
                    // _ => todo!("relocation type not supported {r_type}"),
                    _ => continue,
                }

                (&mut self.loaded_prog[rel_addr..rel_addr + 8])
                    .copy_from_slice(&insn.0.to_ne_bytes());
            }
        }
    }
}
