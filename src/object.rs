use std::{
    collections::BTreeMap,
    ffi::CStr,
    io::{Error, ErrorKind},
    rc::Rc,
    sync::Arc,
};

use object::{
    File, Object, ObjectSection, ObjectSymbol, Relocation, RelocationFlags, RelocationTarget,
    Section, SectionIndex, SectionKind, SymbolKind,
};

use crate::{
    btf::{Btf, BtfKind, BtfTypeId, ext::BtfExt},
    error::LoaderError,
    hook::Hook,
    isa::Insn,
    maps::{BPF_MAP_TYPE_ARRAY, MapPinning, MapSpec},
};

pub struct EbpfObject<'file> {
    file: Rc<File<'file, &'file [u8]>>,
    license: Option<String>,
    btf: Arc<Btf>,
    maps: Vec<MapSpec>,
    functions: Vec<FunctionSignature>,
}

#[derive(Clone, Debug)]
pub struct FunctionSignature {
    pub name: String,
    /// Whether the symbol declaring this function is global, that is, it's an
    /// entrypoint program.
    pub is_global: bool,
    pub params_types: Vec<(String, BtfTypeId)>,
    pub return_type: Option<BtfTypeId>,

    pub section_idx: SectionIndex,
    pub section_offset: usize,
    pub size: usize,
}

impl<'file> EbpfObject<'file> {
    /// Parses an ELF object and pulls out everything we'll need to prepare
    /// programs later: the BTF type graph, BTF.ext (func_info, line_info, CO-RE
    /// relos), map declarations from `.maps`, synthesized data maps for
    /// `.rodata`/`.data`/`.bss`, and the list of function signatures.
    ///
    /// BTF is required. Without it the verifier has no way to describe context
    /// arguments to a program, and maps have no key/value schema. Objects
    /// compiled without BTF debug info will fail here.
    ///
    /// From here, use [`Self::load_prog`] to extract a specific entrypoint as
    /// an [`EbpfProgram`], then [`Vm::prepare`] to wire it up against a VM.
    /// Nothing in `from_elf` itself touches the VM: no maps created, no FDs
    /// assigned, no map relocations patched.
    ///
    /// [`Vm`]: crate::vm::Vm
    /// [`Vm::prepare`]: crate::vm::Vm::prepare
    pub fn from_elf(file: &'file [u8]) -> Result<Self, LoaderError> {
        let file = Rc::new(File::parse(file)?);

        let license = file.section_by_name("license").and_then(|sec| {
            sec.data()
                .ok()
                .and_then(|data| CStr::from_bytes_until_nul(data).ok())
                .map(|data| data.to_string_lossy().to_string())
        });

        let (btf, maps) = parse_btf(&file)?;
        let btf = btf.ok_or(LoaderError::MissingBtf)?;
        let functions = collect_functions(&file, &btf)?;

        Ok(Self {
            file,
            license,
            btf: Arc::new(btf),
            maps,
            functions: functions.into_iter().collect(),
        })
    }

    pub fn license(&self) -> Option<&str> {
        self.license.as_deref()
    }

    pub fn programs(&self) -> impl Iterator<Item = &FunctionSignature> {
        self.functions.iter().filter(|f| f.is_global)
    }

    pub fn functions(&self) -> &[FunctionSignature] {
        &self.functions
    }

    pub fn maps(&self) -> &[MapSpec] {
        &self.maps
    }

    pub fn section_name(&self, sec_idx: SectionIndex) -> Option<&str> {
        self.file.section_by_index(sec_idx).ok()?.name().ok()
    }

    pub fn btf(&self) -> &Arc<Btf> {
        &self.btf
    }

    /// Loads a named entrypoint from this object, flattening it together
    /// with any subprograms it calls into a single instruction stream
    /// ready to hand to [`Vm::prepare`].
    ///
    /// `name` must match a global symbol, typically a function annotated with
    /// `SEC(...)`. Static helpers and uncalled subprograms aren't reachable
    /// here, they only get pulled in when an entrypoint transitively calls
    /// them.
    ///
    /// Map and data-section relocations are recorded but not yet patched.
    /// Those FDs don't exist until the program is prepared against a [`Vm`], at
    /// which point the deferred relocations get rewritten with the assigned
    /// FDs.
    ///
    /// [`Vm`]: crate::vm::Vm
    /// [`Vm::prepare`]: crate::vm::Vm::prepare
    pub fn load_prog(&self, name: &str) -> Result<EbpfProgram, LoaderError> {
        let func = self
            .functions
            .iter()
            .find(|f| f.is_global && f.name == name)
            .ok_or_else(|| LoaderError::ProgramNotFound(name.to_string()))?;
        ProgLoader::load(self, func)
    }

    fn get_func(&self, sec_idx: SectionIndex, sec_off: usize) -> Option<&FunctionSignature> {
        self.functions
            .iter()
            .find(|p| p.section_idx == sec_idx && p.section_offset == sec_off)
    }

    fn rel_symbol_target(&self, rel: &Relocation) -> Result<(SectionIndex, usize), LoaderError> {
        let RelocationTarget::Symbol(idx) = rel.target() else {
            return Err(LoaderError::Unsupported("non-symbol relocation target"));
        };
        let sym = self.file.symbol_by_index(idx)?;
        let sym_sec = sym.section_index().ok_or_else(|| {
            LoaderError::Malformed(format!(
                "symbol {:?} has no associated section",
                sym.name().unwrap_or("?")
            ))
        })?;
        Ok((sym_sec, sym.address() as usize))
    }
}

#[derive(Clone)]
struct LoadedSubprog {
    /// Position in `ProgLoader::insns` where this subprogram was copied to.
    insn_pc: usize,
    func: FunctionSignature,
}

#[derive(Default)]
struct ProgLoader {
    insns: Vec<Insn>,
    /// All programs that have been copied into `insns`.
    loaded_progs: Vec<LoadedSubprog>,
    relos: Vec<(usize, Relocation)>,
}

impl ProgLoader {
    fn load<'obj>(
        obj: &'obj EbpfObject<'obj>,
        func: &FunctionSignature,
    ) -> Result<EbpfProgram, LoaderError> {
        let mut loader = ProgLoader::default();

        loader.load_code(func, obj)?;
        let deferred = loader.resolve_relocations(obj)?;
        let line_info = loader.collect_lines(obj);

        let subprogs = loader
            .loaded_progs
            .into_iter()
            .map(|p| (p.insn_pc, p.func))
            .collect();

        let hook = obj.section_name(func.section_idx).and_then(Hook::parse);

        Ok(EbpfProgram {
            insns: loader.insns,
            func: func.clone(),
            maps: obj.maps.clone(),
            btf: obj.btf.clone(),
            hook,
            deferred,
            line_info,
            subprogs,
        })
    }

    fn find_loaded(&self, section_idx: SectionIndex, byte_offset: usize) -> Option<usize> {
        self.loaded_progs
            .iter()
            .find(|p| p.func.section_idx == section_idx && p.func.section_offset == byte_offset)
            .map(|p| p.insn_pc)
    }

    /// Copies a function's instructions into the flat program buffer and
    /// recurses into any subprograms it calls so they end up in the same
    /// buffer. The point is to flatten what the compiler split across
    /// `.text` sections into a single instruction stream the VM can step
    /// through linearly.
    ///
    /// Subprogram calls come in two flavors:
    ///
    /// * `R_BPF_64_32` relocation against a text symbol, when the callee lives
    ///   in a different section. The symbol address tells us where the callee
    ///   is in its own section.
    /// * PC-relative call with no relocation, when the callee is in the same
    ///   section. The instruction's immediate is a count of 8-byte instructions
    ///   from the call site to the target.
    ///
    /// `ld_imm64` relocations (map and data-section references) are
    /// accumulated into `self.relos` for `resolve_relocations` to patch later,
    /// once the VM has assigned FDs.
    fn load_code<'obj>(
        &mut self,
        func: &FunctionSignature,
        obj: &'obj EbpfObject<'obj>,
    ) -> Result<(), LoaderError> {
        let sec = obj.file.section_by_index(func.section_idx)?;

        let (chunks, _) = sec
            .data()?
            .get(func.section_offset..func.section_offset + func.size)
            .ok_or_else(|| {
                LoaderError::Malformed(format!(
                    "function {:?} extends past section data",
                    func.name
                ))
            })?
            .as_chunks::<{ Insn::WIDTH }>();

        self.insns.reserve(chunks.len());
        self.loaded_progs.push(LoadedSubprog {
            insn_pc: self.insns.len(),
            func: func.clone(),
        });

        let mut sec_off = func.section_offset;
        for chunk in chunks {
            let insn = Insn(u64::from_le_bytes(*chunk));
            let flat_pc = self.insns.len();
            self.insns.push(insn);

            match sec.relocations().find(|(r, _)| *r as usize == sec_off) {
                Some((_, rel)) if insn.is_subprog_call() => {
                    let (sym_sec, sym_off) = obj.rel_symbol_target(&rel)?;
                    self.ensure_subprog_loaded(
                        obj,
                        sym_sec,
                        sym_off,
                        "subprogram referenced by symbol was not found in section",
                    )?;
                    self.relos.push((flat_pc, rel));
                }

                Some((_, rel)) if insn.is_ld_imm64() => self.relos.push((flat_pc, rel)),

                None if insn.is_subprog_call() => {
                    let target_off = sec_off + (insn.imm() as usize + 1) * Insn::WIDTH;
                    self.ensure_subprog_loaded(
                        obj,
                        func.section_idx,
                        target_off,
                        "pc-relative subprogram was not found in same section",
                    )?;
                }

                _ => {}
            }

            sec_off += Insn::WIDTH;
        }

        Ok(())
    }

    fn ensure_subprog_loaded<'obj>(
        &mut self,
        obj: &'obj EbpfObject<'obj>,
        sec_idx: SectionIndex,
        sec_off: usize,
        err: &'static str,
    ) -> Result<(), LoaderError> {
        if self.find_loaded(sec_idx, sec_off).is_some() {
            return Ok(());
        }
        let subprogram = obj
            .get_func(sec_idx, sec_off)
            .ok_or_else(|| LoaderError::Malformed(err.into()))?;
        self.load_code(subprogram, obj)
    }

    fn resolve_relocations<'obj>(
        &mut self,
        obj: &'obj EbpfObject<'obj>,
    ) -> Result<BTreeMap<usize, Deferred>, LoaderError> {
        let mut deferred = BTreeMap::new();

        for (insn_pc, rel) in std::mem::take(&mut self.relos) {
            let RelocationFlags::Elf { r_type } = rel.flags() else {
                return Err(LoaderError::Unsupported("non-ELF relocation flags"));
            };
            let RelocationTarget::Symbol(sym) = rel.target() else {
                return Err(LoaderError::Unsupported("non-symbol relocation target"));
            };

            let sym = obj.file.symbol_by_index(sym)?;
            let sec_idx = sym.section_index().ok_or_else(|| {
                LoaderError::Malformed(format!(
                    "relocation symbol {:?} has no section",
                    sym.name().unwrap_or("?")
                ))
            })?;

            let sec_name = obj
                .file
                .section_by_index(sec_idx)
                .ok()
                .and_then(|s| s.name().ok().map(String::from));

            let def =
                self.resolve_relo(insn_pc, r_type, sym.address(), sec_idx, sec_name.as_deref())?;

            if let Some(d) = def {
                deferred.insert(insn_pc, d);
            }
        }

        Ok(deferred)
    }

    /// Resolve a relocation following the Kernel rules for LLVM relos.
    ///
    /// Ref: <https://github.com/torvalds/linux/blob/master/Documentation/bpf/llvm_reloc.rst>
    fn resolve_relo(
        &mut self,
        insn_pc: usize,
        relo_type: u32,
        addr: u64,
        sec_idx: SectionIndex,
        sec_name: Option<&str>,
    ) -> Result<Option<Deferred>, LoaderError> {
        #![allow(dead_code)]
        /// Relocation used for jumping to program-local functions. The value is
        /// 32-bit wide and is usually summed with the program counter. The
        /// value is in number of 64-bit instructions. If the resulting value
        /// falls within a wide instruction, it is undefined behavior.
        ///
        /// call insn        32       r_offset + 4  (S + A) / 8 - 1
        const R_BPF_64_32: u32 = 10;
        /// Relocation targetting maps and data sections
        /// (`.rodata`/`.data`/`.bss`)
        ///
        /// ld_imm64 insn    32       r_offset + 4  S + A
        const R_BPF_64_64: u32 = 1;
        /// normal data      64       r_offset      S + A
        const R_BPF_64_ABS64: u32 = 2;
        /// normal data      32       r_offset      S + A
        const R_BPF_64_ABS32: u32 = 3;
        /// .BTF[.ext] data  32       r_offset      S + A
        const R_BPF_64_NODYLD32: u32 = 4;

        let target_pc = self.find_loaded(sec_idx, addr as usize);

        let insn = self.insns.get_mut(insn_pc).ok_or_else(|| {
            LoaderError::Malformed(format!(
                "relocation references insn offset {insn_pc} past loaded code"
            ))
        })?;

        match (relo_type, target_pc, insn.is_ld_imm64()) {
            (R_BPF_64_32, Some(target_pc), _) => {
                let addend = insn.imm() / 8;
                let rel = target_pc as i32 - insn_pc as i32 + addend - 1;
                insn.with_imm(rel);

                Ok(None)
            }

            (R_BPF_64_32, None, _) | (R_BPF_64_64, None, false) => {
                Err(LoaderError::Malformed(format!(
                    "relocation target at section {sec_idx:?} address {} was not loaded",
                    addr
                )))
            }

            (R_BPF_64_64, Some(_), _) => Err(LoaderError::Unsupported(
                "R_BPF_64_64 relocation against a code symbol",
            )),

            (R_BPF_64_64, None, true) => {
                let is_data_sec = sec_name
                    .is_some_and(|n| n.starts_with(".rodata") || n == ".data" || n == ".bss");

                if is_data_sec {
                    Ok(Some(Deferred::Data {
                        sec_idx,
                        offset: addr as usize + insn.imm() as usize,
                    }))
                } else {
                    Ok(Some(Deferred::Map {
                        sec_idx,
                        addr: addr as usize,
                    }))
                }
            }

            _ => Err(LoaderError::UnsupportedRelocation(relo_type)),
        }
    }

    fn collect_lines<'obj>(&self, obj: &'obj EbpfObject<'obj>) -> BTreeMap<usize, LineEntry> {
        let mut line_info = BTreeMap::new();

        for info in &obj.btf.ext.line_info {
            let Some(sec_name) = obj.btf.string(info.sec_name_off) else {
                continue;
            };

            let mut funcs: Vec<_> = self
                .loaded_progs
                .iter()
                .filter(|p| {
                    obj.file
                        .section_by_index(p.func.section_idx)
                        .ok()
                        .and_then(|s| s.name().ok())
                        .is_some_and(|n| n == sec_name.as_ref())
                })
                .map(|p| (p.func.section_offset, p.insn_pc))
                .collect();
            funcs.sort_by_key(|(sec_off, _)| *sec_off);

            for line in &info.data {
                let insn_off = line.insn_off as usize;
                let Some(&(sec_off, dst_off)) =
                    funcs.iter().rev().find(|(sec_off, _)| *sec_off <= insn_off)
                else {
                    continue;
                };

                let pc = dst_off + (insn_off - sec_off) / Insn::WIDTH;
                line_info.insert(
                    pc,
                    LineEntry {
                        line_off: line.line_off,
                        line_no: line.line_no,
                        column_no: line.column_no,
                    },
                );
            }
        }

        line_info
    }
}

/// A relocation that gets patched at program preparation time, once the VM has
/// assigned map FDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Deferred {
    /// `ld_imm64` with imm set to the FD of the map at `(sec_idx, addr)`.
    Map { sec_idx: SectionIndex, addr: usize },
    /// `ld_imm64` with imm set to the FD of the data map covering `sec_idx`,
    /// with `offset` written into the second half of the wide insn.
    Data {
        sec_idx: SectionIndex,
        offset: usize,
    },
}

fn parse_btf<'a>(
    file: &Rc<File<'a, &'a [u8]>>,
) -> Result<(Option<Btf>, Vec<MapSpec>), LoaderError> {
    let Some(btf_sec) = file.section_by_name(".BTF") else {
        return Ok(Default::default());
    };

    let mut btf = btf_sec
        .data()
        .map_err(|err| Error::new(ErrorKind::InvalidInput, err))
        .and_then(Btf::from_bytes)
        .map_err(LoaderError::InvalidBtf)?;
    fixup_btf_datasecs(&mut btf, file);

    if let Some(ext_sec) = file.section_by_name(".BTF.ext") {
        btf.ext = ext_sec
            .data()
            .map_err(|err| Error::new(ErrorKind::InvalidInput, err))
            .and_then(BtfExt::from_bytes)
            .map_err(LoaderError::InvalidBtfExt)?;
    }

    btf.validate()?;

    if file.section_by_name("maps").is_some() {
        return Err(LoaderError::DeprecatedMapsSection);
    }

    let mut maps = file
        .section_by_name(".maps")
        .map(|sec| parse_maps(&btf, &sec))
        .transpose()?
        .unwrap_or_default();

    for sec in file.sections() {
        let Ok(name) = sec.name() else { continue };
        if !name.starts_with(".rodata") {
            continue;
        }

        let datasec_id = find_or_create_datasec(&mut btf, &sec)?;

        let data = sec.data()?;
        maps.push(MapSpec {
            name: name.to_string(),
            r#type: Some(BPF_MAP_TYPE_ARRAY),
            sec_idx: sec.index().0,
            sec_offset: 0,
            max_entries: Some(1),
            key_size: Some(4),
            value_size: Some(data.len() as u32),
            value: Some(datasec_id),
            initial_data: Some(data.to_vec()),
            ..Default::default()
        });
    }

    Ok((Some(btf), maps))
}

/// Calculates and updates the offsets and sizes for BTF datasec entries.
///
/// `Datasec`s describe ELF sections and their contents, generally used to
/// inform the Kernel of special structs defined by the program. Each datasec
/// entry contains BTF type ID, a size, and the offset at which the entry is
/// located in the section.
///
/// Clang, however, does not populate sizes and offsets, and that is left for
/// the linker/loader to do.
///
/// An example is the special ELF `.maps` section. It describes BPF maps used by
/// the program during execution. Each map has a corresponding [`BtfVarSecInfo`]
/// entry in the Datasec type for that section. During resolution, a
/// `R_BPF_64_64` relocation searches for a map entry in the datasec where
/// `BtfVarSecInfo::offset` matches the relocation target offset (symbol address
/// of the map).
///
/// From libbpf:
/// > Clang leaves DATASEC size and VAR offsets as zeroes, so we need to fix
/// > this up. But BPF static linker already fixes this up and fills all the
/// > sizes and offsets during static linking. So this step has to be optional.
/// > But the STV_HIDDEN handling is non-optional for any non-extern DATASEC, so
/// > the variable fixup loop below handles both functions at the same time,
/// > paying the cost of BTF VAR <-> ELF symbol matching just once.
///
/// Ref: <https://github.com/libbpf/libbpf/blob/3d451d916f833afed06bfc74026a3650de8dd649/src/libbpf.c#L3321>
fn fixup_btf_datasecs<'a>(btf: &mut Btf, file: &'a File<'a, &'a [u8]>) {
    let datasecs: Vec<_> = btf
        .types
        .iter()
        .filter_map(|(id, ty)| match &ty.kind {
            BtfKind::Datasec(_) => Some((*id, ty.clone())),
            _ => None,
        })
        .collect();

    for (id, mut ty) in datasecs {
        let BtfKind::Datasec(datasec) = &mut ty.kind else {
            continue;
        };

        for info in &mut datasec.secinfos {
            if let Some(sec) = btf
                .types
                .get(&info.r#type)
                .and_then(|ty| btf.string(ty.name_off))
                .and_then(|sym| file.symbol_by_name(sym.as_ref()))
            {
                info.offset = sec.address() as u32;
                info.size = sec.size() as u32;
            }
        }
        datasec.secinfos.sort_unstable_by_key(|ty| ty.offset);

        btf.types.insert(id, ty);
    }
}

/// Finds or synthesizes a BTF DATASEC for a data section. The DATASEC just
/// needs the right size so `is_offset_valid` can do a bounds check.
fn find_or_create_datasec(btf: &mut Btf, sec: &Section) -> Result<BtfTypeId, LoaderError> {
    let name = sec.name()?;

    if let Some((id, _)) = btf.types.iter().find(|(_, ty)| {
        matches!(&ty.kind, BtfKind::Datasec(_))
            && btf.string(ty.name_off).is_some_and(|n| n == name)
    }) {
        return Ok(*id);
    }

    let name_off = btf.strings.len() as u32;
    btf.strings.extend(name.as_bytes());
    btf.strings.push(0);

    let btf_id = BtfTypeId(btf.types.len() as u32 + 1);
    btf.types.insert(
        btf_id,
        crate::btf::BtfType {
            btf_id,
            name_off,
            kind: BtfKind::Datasec(crate::btf::Datasec {
                secinfos: Vec::new(),
                size: sec.size() as u32,
                opaque: true,
            }),
        },
    );

    Ok(btf_id)
}

/// Finds declared maps by looking for the .maps section and matching it against
/// the .maps BTF type. Maps are BTF structs behind
/// [`VariableLinkage::GlobalAllocated`] variables. Once you find the struct,
/// its fields are behind PTR types, and when you finally get to the correct
/// type, it is either a type, say `unsigned int` for fields like `key`/`value`,
/// or as an ARRAY, where the value itself is the dimensionality of the array
/// for other fields, like `type`.
///
/// Ref: <https://github.com/libbpf/libbpf/blob/09b9e83102eb8ab9e540d36b4559c55f3bcdb95d/src/libbpf.c#L2429>
fn parse_maps(btf: &Btf, maps_sec: &Section) -> Result<Vec<MapSpec>, LoaderError> {
    let sec_name = maps_sec.name()?;
    let secinfos = btf
        .types
        .values()
        .filter(|ty| btf.string(ty.name_off).is_some_and(|n| n == sec_name))
        .find_map(|ty| match &ty.kind {
            BtfKind::Datasec(datasec) => Some(&datasec.secinfos),
            _ => None,
        })
        .ok_or(LoaderError::InvalidMapDeclaration(
            "missing datasec for .maps section",
        ))?;

    let mut maps = Vec::with_capacity(secinfos.len());

    for info in secinfos {
        #[expect(
            clippy::expect_used,
            reason = "BTF graph was validated upstream in parse_btf"
        )]
        let btf_ty = btf
            .get_type(info.r#type)
            .expect("secinfo references invalid type");
        let BtfKind::Var(var) = &btf_ty.kind else {
            return Err(LoaderError::InvalidMapDeclaration(
                "datasec entry is not a Var",
            ));
        };

        let map_name = btf
            .string(btf_ty.name_off)
            .ok_or(LoaderError::InvalidMapDeclaration("map var has no name"))?;

        #[expect(
            clippy::expect_used,
            reason = "BTF graph was validated upstream in parse_btf"
        )]
        let btf_ty = btf.get_type(var.ty).expect("missing map definition");
        let BtfKind::Struct(s) = &btf_ty.kind else {
            return Err(LoaderError::InvalidMapDeclaration(
                "map var does not point at a struct",
            ));
        };

        let mut map = MapSpec {
            sec_idx: maps_sec.index().0,
            sec_offset: info.offset,
            name: map_name.to_string(),
            ..Default::default()
        };

        for member in &s.members {
            let name = btf
                .string(member.name_off)
                .ok_or(LoaderError::InvalidMapDeclaration("map member has no name"))?;

            let ty = btf
                .get_type(member.r#type)
                .and_then(|m| match &m.kind {
                    BtfKind::Ptr(ty) => btf.get_type(*ty),
                    _ => None,
                })
                .ok_or(LoaderError::InvalidMapDeclaration(
                    "map member must be a pointer to a typed value",
                ))?;

            match name.as_ref() {
                "type" => map.r#type = ty.kind.array_no_elems(),
                "max_entries" => map.max_entries = ty.kind.array_no_elems(),
                "map_flags" => map.map_flags = ty.kind.array_no_elems(),
                "map_extra" => map.map_extra = ty.kind.array_no_elems(),
                "numa_node" => map.numa_node = ty.kind.array_no_elems(),
                "key_size" => map.key_size = ty.kind.array_no_elems(),
                "value_size" => map.value_size = ty.kind.array_no_elems(),
                "key" => {
                    map.key_size = Some(btf.type_size(ty.btf_id));
                    map.key = Some(ty.btf_id);
                }
                "value" => {
                    map.value_size = Some(btf.type_size(ty.btf_id));
                    map.value = Some(ty.btf_id);
                }
                "values" => map.values = Some(ty.btf_id),
                "pinning" => {
                    if let Some(1) = ty.kind.array_no_elems() {
                        map.pinning = MapPinning::ByName;
                    }
                }
                _ => return Err(LoaderError::InvalidMapDeclaration("unknown map field")),
            }
        }

        maps.push(map);
    }

    Ok(maps)
}

fn collect_functions<'file>(
    file: &Rc<File<'file, &'file [u8]>>,
    btf: &Btf,
) -> Result<Vec<FunctionSignature>, LoaderError> {
    let mut ext_programs = BTreeMap::new();

    let name = |off| {
        btf.string(off)
            .ok_or(LoaderError::InvalidBtfNameOffset(off))
    };

    for info in &btf.ext.func_info {
        let sec_name = name(info.sec_name_off)?;
        for func in &info.data {
            let section_offset = func.insn_off as usize * Insn::WIDTH;
            let func = btf.resolve_must(func.type_id).ty();
            let func_name = name(func.name_off)?;
            let proto = match &func.kind {
                BtfKind::Func(func) => btf.resolve_must(func.func_proto).ty(),
                _ => {
                    return Err(LoaderError::Malformed(
                        "func_info entry does not point at a Func BTF type".to_string(),
                    ));
                }
            };
            let proto = match &proto.kind {
                BtfKind::FuncProto(proto) => proto,
                _ => {
                    return Err(LoaderError::Malformed(
                        "Func.func_proto does not resolve to a FuncProto".to_string(),
                    ));
                }
            };

            let params_types = proto
                .params
                .iter()
                .map(|param| {
                    let name = name(param.name_off)?;
                    Ok((name.to_string(), param.r#type))
                })
                .collect::<Result<Vec<_>, LoaderError>>()?;

            ext_programs.insert(
                (sec_name.clone(), func_name.clone()),
                (section_offset, params_types, proto.return_type),
            );
        }
    }

    let mut functions = Vec::new();

    for sec in file.sections() {
        if sec.kind() != SectionKind::Text {
            continue;
        }
        let sec_name = sec.name()?;
        let data = sec.data()?;

        let syms = file
            .symbols()
            .filter(|s| s.kind() == SymbolKind::Text)
            .filter(|s| s.section_index().is_some_and(|i| i == sec.index()));

        for sym in syms {
            let prog_name = sym.name()?;

            let prog_size = sym.size() as usize;
            let prog_addr = sym.address() as usize;

            let insns = data.get(prog_addr..prog_addr + prog_size).ok_or_else(|| {
                LoaderError::Malformed(format!(
                    "program {prog_name:?} (size {prog_size}) extends past section {sec_name}"
                ))
            })?;

            if !insns.len().is_multiple_of(Insn::WIDTH) {
                return Err(LoaderError::Malformed(format!(
                    "program {prog_name:?} byte length is not a multiple of {}",
                    Insn::WIDTH
                )));
            }

            let (params, ret) = match ext_programs.get(&(sec_name.into(), prog_name.into())) {
                Some((offset, _, _)) if prog_addr != *offset => {
                    return Err(LoaderError::Malformed(format!(
                        "func_info insn offset {offset} does not match symbol address \
                         for {sec_name}:{prog_name}"
                    )));
                }
                Some((_, params, ret)) => (params.clone(), Some(*ret)),
                None => Default::default(),
            };

            functions.push(FunctionSignature {
                name: prog_name.to_string(),
                is_global: sym.is_global(),
                params_types: params,
                return_type: ret,

                section_idx: sec.index(),
                section_offset: prog_addr,
                size: prog_size,
            });
        }
    }

    Ok(functions)
}

#[derive(Clone, Debug)]
pub struct LineEntry {
    pub line_off: u32,
    pub line_no: u32,
    pub column_no: u32,
}

#[derive(Clone)]
pub struct EbpfProgram {
    pub(crate) insns: Vec<Insn>,
    pub(crate) func: FunctionSignature,
    pub(crate) maps: Vec<MapSpec>,
    pub(crate) btf: Arc<Btf>,
    /// Parsed `SEC(...)` annotation. `None` if the section name didn't match
    /// any known hook prefix.
    pub hook: Option<Hook>,
    pub(crate) deferred: BTreeMap<usize, Deferred>,
    pub(crate) line_info: BTreeMap<usize, LineEntry>,
    pub(crate) subprogs: BTreeMap<usize, FunctionSignature>,
}

impl EbpfProgram {
    pub fn insns(&self) -> &[Insn] {
        &self.insns
    }

    pub fn subprogs(&self) -> &BTreeMap<usize, FunctionSignature> {
        &self.subprogs
    }

    pub fn line_info(&self) -> &BTreeMap<usize, LineEntry> {
        &self.line_info
    }

    pub fn btf(&self) -> &Arc<Btf> {
        &self.btf
    }

    pub fn maps(&self) -> &[MapSpec] {
        &self.maps
    }
}

impl std::fmt::Debug for EbpfProgram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EbpfProgram")
            .field("sig", &self.func)
            .field("maps", &self.maps)
            .field("subprogs", &self.subprogs)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const R_BPF_64_64: u32 = 1;
    const R_BPF_64_32: u32 = 10;

    /// ld_imm64 r0, imm
    fn ld_imm64(imm: i32) -> Insn {
        Insn(0x18 | ((imm as u32 as u64) << 32))
    }

    fn call(imm: i32) -> Insn {
        Insn(0x85 | ((imm as u32 as u64) << 32))
    }

    fn loader_with(
        insn_pc: usize,
        insn: Insn,
        progs: &[(SectionIndex, usize, usize)],
    ) -> ProgLoader {
        let mut insns = vec![Insn(0); insn_pc + 1];
        insns[insn_pc] = insn;
        ProgLoader {
            insns,
            loaded_progs: progs
                .iter()
                .map(|&(section_idx, byte_offset, flat_pc)| LoadedSubprog {
                    insn_pc: flat_pc,
                    func: FunctionSignature {
                        name: String::new(),
                        is_global: false,
                        params_types: Vec::new(),
                        return_type: None,

                        section_idx,
                        section_offset: byte_offset,
                        size: 0,
                    },
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn subprog_call_patches_pc_relative_imm() {
        // call at PC 2, subprog at PC 5
        let mut loader = loader_with(2, call(0), &[(SectionIndex(1), 5 * 8, 5)]);

        let r = loader
            .resolve_relo(
                2,
                R_BPF_64_32,
                (5 * 8) as u64,
                SectionIndex(1),
                Some(".text"),
            )
            .unwrap();

        assert_eq!(r, None);
        assert_eq!(loader.insns[2].imm(), 2, "5 - 2 - 1 + 0");
    }

    #[test]
    fn subprog_call_includes_addend() {
        // addend set to 16 bytes
        let mut loader = loader_with(1, call(16), &[(SectionIndex(1), 7 * 8, 7)]);

        loader
            .resolve_relo(
                1,
                R_BPF_64_32,
                (7 * 8) as u64,
                SectionIndex(1),
                Some(".text"),
            )
            .unwrap();

        assert_eq!(loader.insns[1].imm(), 7, "7 - 1 - 1 + 2");
    }

    #[test]
    fn subprog_call_to_unloaded_target_errors() {
        let mut loader = loader_with(0, call(0), &[]);

        let err = loader
            .resolve_relo(0, R_BPF_64_32, 40, SectionIndex(1), Some(".text"))
            .unwrap_err();

        assert!(matches!(err, LoaderError::Malformed(_)));
    }

    #[test]
    fn map_ref_emits_deferred_and_leaves_insn_alone() {
        let mut loader = loader_with(0, ld_imm64(0), &[]);

        let r = loader
            .resolve_relo(0, R_BPF_64_64, 32, SectionIndex(7), Some(".maps"))
            .unwrap();

        assert_eq!(
            r,
            Some(Deferred::Map {
                sec_idx: SectionIndex(7),
                addr: 32,
            })
        );
        assert_eq!(
            loader.insns[0].imm(),
            0,
            "ld_imm64 must not be patched here"
        );
    }

    #[test]
    fn rodata_ref_carries_addr_plus_addend() {
        // addend set to 8 bytes
        let mut loader = loader_with(0, ld_imm64(8), &[]);

        let r = loader
            .resolve_relo(0, R_BPF_64_64, 64, SectionIndex(3), Some(".rodata"))
            .unwrap();

        assert_eq!(
            r,
            Some(Deferred::Data {
                sec_idx: SectionIndex(3),
                offset: 72, // 64 + 8
            })
        );
    }

    #[test]
    fn r_bpf_64_64_against_code_symbol_is_unsupported() {
        // R_BPF_64_64 relocations are reserved to maps, so we fail
        // if it lands in a loaded program signature
        let mut loader = loader_with(0, ld_imm64(0), &[(SectionIndex(1), 16, 2)]);

        let err = loader
            .resolve_relo(0, R_BPF_64_64, 16, SectionIndex(1), Some(".text"))
            .unwrap_err();

        assert!(matches!(err, LoaderError::Unsupported(_)));
    }

    #[test]
    fn unknown_r_type_is_rejected() {
        let mut loader = loader_with(0, call(0), &[]);

        let err = loader
            .resolve_relo(0, 99, 0, SectionIndex(0), None)
            .unwrap_err();

        assert!(matches!(err, LoaderError::UnsupportedRelocation(99)));
    }
}
