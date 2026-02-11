use std::{
    collections::{BTreeMap, HashMap},
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
    btf::{Btf, BtfKind, BtfType, BtfTypeId, ext::BtfExt},
    isa::Insn,
    maps::{BPF_MAP_TYPE_ARRAY, MapPinning, MapSpec},
};

#[derive(Debug, thiserror::Error)]
pub enum LoaderError {
    #[error("malformed BTF section: {0:?}")]
    InvalidBtf(std::io::Error),
    #[error("malformed BTF extension section: {0:?}")]
    InvalidBtfExt(std::io::Error),
    #[error("invalid BTF name offset: {0:?}")]
    InvalidBtfNameOffset(u32),
    #[error("invalid BTF type ID: {0:?}")]
    InvalidBtfTypeId(BtfTypeId),

    #[error("deprecated 'maps' section, use '.maps' format instead")]
    DeprecatedMapsSection,

    #[error("invalid map declaration: {0:?}")]
    InvalidMapDeclaration(&'static str),
}

pub struct EbpfObject<'file> {
    file: Rc<File<'file, &'file [u8]>>,
    license: Option<String>,
    btf: Option<Arc<Btf>>,
    maps: Vec<MapSpec>,
    functions: Vec<Arc<FunctionSignature>>,
}

#[derive(Clone)]
pub struct FunctionSignature {
    pub name: String,
    pub is_global: bool,
    pub section_idx: SectionIndex,
    pub params_types: Vec<(String, BtfTypeId)>,
    pub return_type: Option<BtfTypeId>,

    pub insn_offset: usize,
    pub insn_size: usize,
}

#[derive(Default)]
struct ProgLoader {
    insns: Vec<Insn>,
    loaded_progs: HashMap<(SectionIndex, usize), usize>,
    relos: Vec<(usize, Relocation)>,
    map_relos: HashMap<usize, (SectionIndex, usize)>,
    data_relos: HashMap<usize, (SectionIndex, usize)>,
}

impl<'file> EbpfObject<'file> {
    /// Parses an ELF file, extracting all BTF and extension
    pub fn from_elf(file: &'file [u8]) -> Result<Self, LoaderError> {
        let file = Rc::new(File::parse(file).unwrap());

        let license = file.section_by_name("license").and_then(|sec| {
            sec.data()
                .ok()
                .and_then(|data| CStr::from_bytes_until_nul(data).ok())
                .and_then(|data| Some(data.to_string_lossy().to_string()))
        });

        let (btf, maps) = parse_btf(&file)?;
        let functions = collect_functions(&file, &btf)?;

        Ok(Self {
            file,
            license,
            btf: btf.map(Arc::new),
            maps,
            functions: functions.into_iter().map(Arc::new).collect(),
        })
    }

    pub fn license(&self) -> Option<&str> {
        self.license.as_deref()
    }

    pub fn programs(&self) -> impl Iterator<Item = &Arc<FunctionSignature>> {
        self.functions.iter().filter(|f| f.is_global)
    }

    pub fn load_prog(&self, name: &str) -> Result<EbpfProgram, LoaderError> {
        let prog = self
            .functions
            .iter()
            .find(|f| f.is_global && f.name == name)
            .unwrap_or_else(|| panic!(r#"program "{name}" not found"#));

        let mut program = ProgLoader::default();
        self.load_code(&prog, &mut program);
        self.resolve_relocations(&mut program);

        let line_info = self.collect_lines(&program);

        Ok(EbpfProgram {
            insns: program.insns,
            sig: prog.clone(),
            maps: self.maps.clone(),
            btf: self.btf.clone(),
            map_relos: program.map_relos,
            data_relos: program.data_relos,
            line_info,
        })
    }

    fn collect_lines(&self, program: &ProgLoader) -> BTreeMap<usize, LineEntry> {
        let Some(btf) = &self.btf else {
            return Default::default();
        };
        let mut line_info = BTreeMap::new();

        for info in &btf.ext.line_info {
            let Some(sec_name) = btf.string(info.sec_name_off) else {
                continue;
            };

            let mut funcs: Vec<_> = program
                .loaded_progs
                .iter()
                .filter(|((sec, _), _)| {
                    self.file.section_by_index(*sec).unwrap().name().unwrap() == sec_name.as_ref()
                })
                .map(|((_, sec_off), dst_off)| (*sec_off, *dst_off))
                .collect();
            funcs.sort_by_key(|(sec_off, _)| *sec_off);

            for line in &info.data {
                let insn_off = line.insn_off as usize;
                let Some(&(sec_off, dst_off)) =
                    funcs.iter().rev().find(|(sec_off, _)| *sec_off <= insn_off)
                else {
                    continue;
                };

                let pc = dst_off + (insn_off - sec_off) / 8;
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

    fn load_code(&self, prog: &FunctionSignature, loader: &mut ProgLoader) {
        let sec = self.file.section_by_index(prog.section_idx).unwrap();
        let data = sec.data().unwrap();

        let sec_data_offset = prog.insn_offset * 8;
        let sec_data_len = prog.insn_size * 8;

        let insns = &data[sec_data_offset..sec_data_offset + sec_data_len];
        let (insns, _) = insns.as_chunks::<8>();

        let prog_dst_offset = loader.insns.len();
        loader
            .loaded_progs
            .insert((prog.section_idx, sec_data_offset), prog_dst_offset);

        loader
            .insns
            .extend(insns.iter().map(|&insn| Insn(u64::from_le_bytes(insn))));

        for (insn_offset, insn) in insns
            .iter()
            .map(|&insn| Insn(u64::from_le_bytes(insn)))
            .enumerate()
        {
            if !insn.is_ld_imm64() && !insn.is_subprog_call() {
                continue;
            }

            let sec_insn_offset = sec_data_offset + insn_offset * 8;
            let prog_dst_insn_offset = prog_dst_offset + insn_offset;
            let rel = sec.relocations().find(|r| r.0 as usize == sec_insn_offset);

            if let Some((_, rel)) = rel {
                let RelocationTarget::Symbol(sym) = rel.target() else {
                    todo!("unsupported call rel target")
                };

                let sym = self
                    .file
                    .symbol_by_index(sym)
                    .unwrap_or_else(|_| todo!("sym points to unknown symbol decl"));
                let sym_insn = sym.address() as usize / Insn::WIDTH;
                let sym_sec = sym
                    .section_index()
                    .unwrap_or_else(|| todo!("symbol must be related to section"));

                if insn.is_subprog_call() {
                    let subprogram = self
                        .functions
                        .iter()
                        .find(|p| p.section_idx == sym_sec && p.insn_offset == sym_insn)
                        .unwrap_or_else(|| {
                            todo!("symbol subprogram was not found in same section")
                        });

                    if !loader
                        .loaded_progs
                        .contains_key(&(sym_sec, sym.address() as usize))
                    {
                        self.load_code(subprogram, loader);
                    }
                }

                loader.relos.push((prog_dst_insn_offset, rel));
            } else if insn.is_subprog_call() {
                let target_insn = sec_insn_offset + insn.imm() as usize;
                let subprogram = self
                    .functions
                    .iter()
                    .find(|p| p.section_idx == prog.section_idx && p.insn_offset == target_insn)
                    .unwrap_or_else(|| todo!("pc-rel subprogram was not found in same section"));
                if !loader
                    .loaded_progs
                    .contains_key(&(sec.index(), target_insn * 8))
                {
                    self.load_code(subprogram, loader);
                }
            }
        }
    }

    /// This function resolves relocations and updates the code
    /// with the correct values. The actual relocation performed
    /// here is very simple: we find the start of each loaded
    /// section, an index to our loaded code buffer.
    fn resolve_relocations(&self, loader: &mut ProgLoader) {
        #![allow(dead_code)]

        /// ld_imm64 insn    32       r_offset + 4  S + A
        const R_BPF_64_64: u32 = 1;
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

        /// normal data      64       r_offset      S + A
        const R_BPF_64_ABS64: u32 = 2;
        /// normal data      32       r_offset      S + A
        const R_BPF_64_ABS32: u32 = 3;
        /// .BTF[.ext] data  32       r_offset      S + A
        const R_BPF_64_NODYLD32: u32 = 4;

        for (insn_offset, rel) in &loader.relos {
            let mut insn = loader.insns[*insn_offset];

            let RelocationFlags::Elf { r_type } = rel.flags() else {
                panic!("unknown flags {:?}", rel.flags());
            };
            assert!(
                r_type == R_BPF_64_32 || r_type == R_BPF_64_64,
                "{r_type:?} rel type not supported"
            );

            let RelocationTarget::Symbol(sym) = rel.target() else {
                todo!("unsupported call rel target")
            };

            let sym = self.file.symbol_by_index(sym).expect("invalid symbol");
            let sym_sec = sym.section_index().unwrap();

            let target_insn_offset = loader.loaded_progs.get(&(sym_sec, sym.address() as usize));

            if insn.is_ld_imm64() && r_type == R_BPF_64_64 && target_insn_offset.is_none() {
                let sec_name = self
                    .file
                    .section_by_index(sym_sec)
                    .ok()
                    .and_then(|s| s.name().ok().map(|n| n.to_string()));
                let is_data_sec = sec_name
                    .as_deref()
                    .is_some_and(|n| n.starts_with(".rodata") || n == ".data" || n == ".bss");

                if is_data_sec {
                    let offset = sym.address() as usize + insn.imm() as usize;
                    loader.data_relos.insert(*insn_offset, (sym_sec, offset));
                } else {
                    loader
                        .map_relos
                        .insert(*insn_offset, (sym_sec, sym.address() as usize));
                }
                continue;
            }

            let target_insn_offset =
                target_insn_offset.unwrap_or_else(|| todo!("target not loaded"));

            match r_type {
                R_BPF_64_32 => {
                    let target_offset = *target_insn_offset as i32 - *insn_offset as i32;
                    let addend = insn.imm() / 8;
                    insn.with_imm(target_offset + addend - 1);
                }
                R_BPF_64_64 => {
                    insn.with_imm((target_insn_offset / 8) as i32 + insn.imm());
                }
                _ => todo!("relocation type not supported {r_type}"),
            }

            loader.insns[*insn_offset] = insn;
        }
    }
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

    if file.section_by_name("maps").is_some() {
        return Err(LoaderError::DeprecatedMapsSection);
    }

    let mut maps = file
        .section_by_name(".maps")
        .map(|sec| parse_maps(&btf, &sec))
        .transpose()
        .map_err(LoaderError::InvalidMapDeclaration)?
        .unwrap_or_default();

    for sec in file.sections() {
        let Ok(name) = sec.name() else { continue };
        if !name.starts_with(".rodata") {
            continue;
        }

        let datasec_id = find_or_create_datasec(&mut btf, &sec);

        let data = sec.data().unwrap();
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

/// Calculates and updates the offsets and sizes for BTF datasec
/// entries.
///
/// `Datasec`s describe ELF sections and their contents, generally
/// used to inform the Kernel of special structs defined by the
/// program. Each datasec entry contains BTF type ID, a size, and
/// the offset at which the entry is located in the section.
///
/// Clang, however, does not populate sizes and offsets, and that
/// is left for the linker/loader to do.
///
/// An example is the special ELF `.maps` section. It describes
/// BPF maps used by the program during execution. Each map has a
/// corresponding [`BtfVarSecInfo`] entry in the Datasec type for
/// that section. During resolution, a `R_BPF_64_64` relocation
/// searches for a map entry in the datasec where
/// `BtfVarSecInfo::offset` matches the relocation target offset
/// (symbol address of the map).
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
            unreachable!()
        };

        for info in &mut datasec.secinfos {
            btf.types
                .get(&info.r#type)
                .and_then(|ty| btf.string(ty.name_off))
                .and_then(|name| file.symbol_by_name(name.as_ref()))
                .inspect(|sym| info.offset = sym.address() as _);
        }
        datasec.secinfos.sort_unstable_by_key(|ty| ty.offset);

        btf.types.insert(id, ty);
    }
}

/// Finds or synthesizes a BTF DATASEC for a data section. The
/// DATASEC just needs the right size so `is_offset_valid` can
/// do a bounds check.
fn find_or_create_datasec(btf: &mut Btf, sec: &Section) -> BtfTypeId {
    let name = sec.name().unwrap();

    if let Some((id, _)) = btf.types.iter().find(|(_, ty)| {
        matches!(&ty.kind, BtfKind::Datasec(_)) && btf.string(ty.name_off).is_some_and(|n| n == name)
    }) {
        return *id;
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

    btf_id
}

/// Finds declared maps by looking for the .maps section and matching it
/// against the .maps BTF type. Maps are BTF structs behind
/// [`VariableLinkage::GlobalAllocated`] variables. Once you find the
/// struct, its fields are behind PTR types, and when you finally get to
/// the correct type, it is either a type, say `unsigned int` for fields
/// like `key`/`value`, or as an ARRAY, where the value itself is the
/// dimensionality of the array for other fields, like `type`.
///
/// TODO: Support .data, .rodata, .bss maps
///
/// Ref: <https://github.com/libbpf/libbpf/blob/09b9e83102eb8ab9e540d36b4559c55f3bcdb95d/src/libbpf.c#L2429>
fn parse_maps(btf: &Btf, maps_sec: &Section) -> std::result::Result<Vec<MapSpec>, &'static str> {
    let sec_name = maps_sec.name().map_err(|_| "missing section name")?;
    let secinfos = btf
        .types
        .values()
        .filter(|ty| btf.string(ty.name_off).is_some_and(|n| n == sec_name))
        .find_map(|ty| match &ty.kind {
            BtfKind::Datasec(datasec) => Some(&datasec.secinfos),
            _ => None,
        })
        .ok_or("missing datasec for .maps section")?;

    let mut maps = Vec::with_capacity(secinfos.len());

    for info in secinfos {
        let btf_ty = btf
            .get_type(info.r#type)
            .expect("secinfo references invalid type");
        let BtfKind::Var(var) = &btf_ty.kind else {
            return Err("unexpected map btf type");
        };

        let Some(map_name) = btf.string(btf_ty.name_off) else {
            return Err("map type missing name");
        };

        let btf_ty = btf.get_type(var.ty).expect("missing map definition");
        let BtfKind::Struct(s) = &btf_ty.kind else {
            return Err("unexpected map btf type");
        };

        let mut map = MapSpec {
            sec_idx: maps_sec.index().0,
            sec_offset: info.offset,
            name: map_name.to_string(),
            ..Default::default()
        };

        for member in &s.members {
            let Some(name) = btf.string(member.name_off) else {
                panic!("struct member missing name");
            };

            let ty = btf
                .get_type(member.r#type)
                .and_then(|m| match &m.kind {
                    BtfKind::Ptr(ty) => btf.get_type(*ty),
                    kind => panic!("wrong map field ty {name:?}: {kind:?}"),
                })
                .expect("map field references invalid ty {name:?}");

            match name.as_ref() {
                "type" => map.r#type = ty.kind.array_no_elems(),
                "max_entries" => map.max_entries = ty.kind.array_no_elems(),
                "map_flags" => map.map_flags = ty.kind.array_no_elems(),
                "map_extra" => map.map_extra = ty.kind.array_no_elems(),
                "numa_node" => map.numa_node = ty.kind.array_no_elems(),
                "key_size" => map.key_size = ty.kind.array_no_elems(),
                "value_size" => map.value_size = ty.kind.array_no_elems(),
                "key" => {
                    map.key_size = Some(btf.type_size(ty.btf_id).ok_or("invalid type key")?);
                    map.key = Some(ty.btf_id);
                }
                "value" => {
                    map.value_size = Some(btf.type_size(ty.btf_id).ok_or("invalid type value")?);
                    map.value = Some(ty.btf_id);
                }
                "values" => map.values = Some(ty.btf_id),
                "pinning" => {
                    if let Some(1) = ty.kind.array_no_elems() {
                        map.pinning = MapPinning::ByName;
                    }
                }
                name => panic!("unknown map field: {name:?}"),
            }
        }

        maps.push(map);
    }

    Ok(maps)
}

fn collect_functions<'file>(
    file: &Rc<File<'file, &'file [u8]>>,
    btf: &Option<Btf>,
) -> Result<Vec<FunctionSignature>, LoaderError> {
    let mut ext_programs = HashMap::new();

    if let Some(btf) = btf {
        for info in &btf.ext.func_info {
            let sec_name = btf
                .string(info.sec_name_off)
                .ok_or(LoaderError::InvalidBtfNameOffset(info.sec_name_off))?;
            for func in &info.data {
                let offset = func.insn_off;
                let func = btf
                    .get_type(func.type_id)
                    .ok_or(LoaderError::InvalidBtfTypeId(func.type_id))?;
                let func_name = btf
                    .string(func.name_off)
                    .ok_or(LoaderError::InvalidBtfNameOffset(func.name_off))?;
                let proto = match &func.kind {
                    BtfKind::Func(func) => btf
                        .get_type(func.func_proto)
                        .ok_or(LoaderError::InvalidBtfTypeId(func.func_proto))?,
                    kind => todo!("only funcs are allowed in this position, got: {kind:?}"),
                };
                let proto = match &proto.kind {
                    BtfKind::FuncProto(proto) => proto,
                    kind => todo!("only protos are allowed in this position, got: {kind:?}"),
                };

                let params_types = proto
                    .params
                    .iter()
                    .map(|param| {
                        let name = btf.string(param.name_off)?;
                        btf.get_type(param.r#type)?;
                        Some((name.to_string(), param.r#type))
                    })
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| todo!("invalid func params"))?;

                let _ = btf
                    .get_type(proto.return_type)
                    .ok_or_else(|| todo!("invalid func return"));

                ext_programs.insert(
                    (sec_name.clone(), func_name.clone()),
                    (offset as usize, params_types, proto.return_type),
                );
            }
        }
    }

    let mut functions = Vec::new();

    for sec in file.sections() {
        if sec.kind() != SectionKind::Text {
            continue;
        }
        let Ok(sec_name) = sec.name() else {
            todo!("progbits exec section must have name");
        };
        let Ok(data) = sec.data() else {
            todo!("progbits exec section must have data");
        };

        let syms = file
            .symbols()
            .filter(|s| s.kind() == SymbolKind::Text)
            .filter(|s| s.section_index().is_some_and(|i| i == sec.index()));

        for sym in syms {
            let Ok(prog_name) = sym.name() else {
                todo!("program must have valid name");
            };

            let prog_size = sym.size() as usize;
            let prog_addr = sym.address() as usize;
            let prog_insn_offset = prog_addr / Insn::WIDTH;

            let Some(insns) = data.get(prog_addr..prog_addr + prog_size) else {
                todo!("prog size exceeds section boundary");
            };

            if !insns.len().is_multiple_of(8) {
                todo!("progbits exec must be multiple of insn size");
            }

            let (params, ret) = match ext_programs.get(&(sec_name.into(), prog_name.into())) {
                Some((offset, _, _)) if prog_insn_offset != *offset => {
                    todo!("func information does not match symbol address {sec_name}:{prog_name}")
                }
                Some((_, params, ret)) => (params.clone(), Some(ret.clone())),
                None => Default::default(),
            };

            functions.push(FunctionSignature {
                name: prog_name.to_string(),
                is_global: sym.is_global(),
                section_idx: sec.index(),
                params_types: params,
                return_type: ret,

                insn_offset: prog_insn_offset,
                insn_size: prog_size / Insn::WIDTH,
            });
        }
    }

    Ok(functions)
}

pub struct LineEntry {
    pub line_off: u32,
    pub line_no: u32,
    pub column_no: u32,
}

pub struct EbpfProgram {
    pub(crate) insns: Vec<Insn>,
    pub(crate) sig: Arc<FunctionSignature>,
    pub(crate) maps: Vec<MapSpec>,
    pub(crate) btf: Option<Arc<Btf>>,
    pub(crate) map_relos: HashMap<usize, (SectionIndex, usize)>,
    pub(crate) data_relos: HashMap<usize, (SectionIndex, usize)>,
    pub(crate) line_info: BTreeMap<usize, LineEntry>,
}

impl EbpfProgram {
    /// Given a function name, we search for a matching BTF
    /// function entry. The `ctx_params` are a list of
    /// `(field name, value)` used to generate a function
    /// context, the eBPFs proogram parameter, like `__sk_buff`.
    ///
    /// The function uses BTF information to generate the entire
    /// struct, and each entry in `ctx_params` overrides one of
    /// the context's fields.
    ///
    /// # Example
    ///
    /// An entrypoint that takes `__sk_buff` can be built with:
    ///
    /// ```
    /// # use bepeefe::{vm::Vm, object::*};
    /// # let file = std::fs::read("./examples/bpf/map_array.o").unwrap();
    /// let obj = EbpfObject::from_elf(&file).unwrap();
    /// let prog = obj.load_prog("entry").unwrap();
    /// let ctx = prog
    ///     .build_ctx(
    ///         &[
    ///             [
    ///                 ("local_port", Val::Number(3000)),
    ///                 ("len", Val::Number(64))
    ///             ].into()
    ///         ]
    ///     );
    /// # let mut vm = Vm::new();
    /// let prog_id = vm.prepare(prog, Default::default());
    /// vm.run(&prog_id, &ctx);
    /// ```
    ///
    /// The resulting `Entrypoint::ctx` will be a zeroed buffer of
    /// the size of the `__sk_buff` struct as described by the BTF
    /// type, populated with the `local_port` and `len` fields.
    pub fn build_ctx(&self, ctx_params: &[Val]) -> Vec<Context> {
        assert_eq!(
            self.sig.params_types.len(),
            ctx_params.len(),
            "function takes {} arguments but only received {}",
            self.sig.params_types.len(),
            ctx_params.len()
        );
        let btf = self.btf.as_ref().unwrap();

        let params = self
            .sig
            .params_types
            .iter()
            .map(|(name, ty)| (name, btf.get_type(*ty).unwrap()))
            .zip(ctx_params);

        let mut ctx = Vec::with_capacity(self.sig.params_types.len());

        for ((_, param_ty), ctx_val) in params {
            ctx.push(build_ctx_val(btf, param_ty, ctx_val));
        }

        ctx
    }
}

fn build_ctx_val(btf: &Arc<Btf>, param_ty: &crate::btf::BtfType, ctx_val: &Val) -> Context {
    let size = param_ty.kind.size(btf).unwrap() as usize;

    match ctx_val {
        Val::Zeroed => Context::Buffer(vec![0; size]),
        Val::Number(num) => {
            ctx_val.to_bytes(btf, param_ty);
            Context::Value(*num as u64)
        }
        Val::Map(map) => {
            let BtfKind::Ptr(p) = &param_ty.kind else {
                todo!("expected param to be ptr");
            };
            let ptr = btf
                .get_type(*p)
                .unwrap_or_else(|| todo!("ptr points to invalid btf type"));
            let BtfKind::Struct(s) = &ptr.kind else {
                todo!("expected param to be struct");
            };

            let mut used_fields = Vec::with_capacity(map.len());
            let mut buf = Vec::with_capacity(size);
            for ele in &s.members {
                let member_ty = btf.get_type(ele.r#type).unwrap();
                let name = btf
                    .string(ele.name_off)
                    .unwrap_or_else(|| todo!("missing name"));
                let member_size = member_ty.kind.size(btf).unwrap() as usize;

                let Some(member_val) = map.get(name.as_ref()) else {
                    buf.resize(buf.len() + member_size, 0);
                    continue;
                };

                match build_ctx_val(btf, member_ty, member_val) {
                    Context::Buffer(items) => buf.extend(items),
                    Context::Value(v) => buf.extend(&v.to_ne_bytes()[..member_size]),
                }

                used_fields.push(name);
            }

            for (struct_field, _) in map {
                if !used_fields.contains(&struct_field.as_str().into()) {
                    todo!("field {struct_field:?} does not exist in struct");
                }
            }

            Context::Buffer(buf)
        }
    }
}

#[derive(Debug)]
pub enum Context {
    Buffer(Vec<u8>),
    Value(u64),
}

#[derive(Clone, Debug, Default)]
pub enum Val {
    #[default]
    Zeroed,
    Number(i64),
    Map(HashMap<String, Val>),
}

impl Val {
    pub fn to_bytes<'b>(&self, btf: &'b Btf, mut ty: &'b BtfType) -> Vec<u8> {
        let size = ty.kind.size(btf).unwrap() as usize;

        match self {
            Val::Zeroed => vec![0; size],
            Val::Number(num) => match &ty.kind {
                BtfKind::Int(int) => {
                    if num.unbounded_shr(int.bits as _) > 0 {
                        todo!("number {num} is larger than param size ({} bits)", int.bits);
                    }
                    num.to_ne_bytes()[..int.size as usize].to_vec()
                }
                BtfKind::Enum(e) => {
                    e.values
                        .iter()
                        .find(|v| v.val == *num as i32)
                        .expect("incorrect enum value");
                    num.to_ne_bytes()[..e.size as usize].to_vec()
                }
                BtfKind::Enum64(e) => {
                    e.values
                        .iter()
                        .find(|v| ((v.val_hi32 as i64) << 32 | v.val_lo32 as i64) == *num)
                        .expect("incorrect enum64 value");
                    num.to_ne_bytes()[..e.size as usize].to_vec()
                }
                _ => todo!("expected numeric type"),
            },
            Val::Map(map) => {
                if let BtfKind::Ptr(p) = &ty.kind {
                    ty = btf
                        .get_type(*p)
                        .unwrap_or_else(|| todo!("ptr points to invalid btf type"));
                }

                let BtfKind::Struct(s) = &ty.kind else {
                    todo!("expected param to be struct");
                };

                let mut used_fields = Vec::with_capacity(map.len());
                let mut buf = Vec::with_capacity(size);
                for ele in &s.members {
                    let member_ty = btf.get_type(ele.r#type).unwrap();
                    let name = btf
                        .string(ele.name_off)
                        .unwrap_or_else(|| todo!("missing name"));
                    let member_size = member_ty.kind.size(btf).unwrap() as usize;

                    let Some(member_val) = map.get(name.as_ref()) else {
                        buf.resize(buf.len() + member_size, 0);
                        continue;
                    };

                    buf.extend(member_val.to_bytes(btf, member_ty));

                    used_fields.push(name);
                }

                for (struct_field, _) in map {
                    if !used_fields.contains(&struct_field.as_str().into()) {
                        todo!("field {struct_field:?} does not exist in struct");
                    }
                }

                buf
            }
        }
    }
}

impl Val {
    pub fn from_bytes(btf: &Btf, ty: &BtfType, bytes: &[u8]) -> Val {
        match &ty.kind {
            BtfKind::Int(int) => {
                let size = int.size as usize;
                let mut buf = [0u8; 8];
                buf[..size].copy_from_slice(&bytes[..size]);
                Val::Number(i64::from_ne_bytes(buf))
            }
            BtfKind::Enum(e) => {
                let size = e.size as usize;
                let mut buf = [0u8; 8];
                buf[..size].copy_from_slice(&bytes[..size]);
                Val::Number(i64::from_ne_bytes(buf))
            }
            BtfKind::Enum64(e) => {
                let size = e.size as usize;
                let mut buf = [0u8; 8];
                buf[..size].copy_from_slice(&bytes[..size]);
                Val::Number(i64::from_ne_bytes(buf))
            }
            BtfKind::Struct(s) => {
                let mut map = HashMap::new();
                for member in &s.members {
                    let member_ty = btf.get_type(member.r#type).unwrap();
                    let name = btf.string(member.name_off).unwrap();
                    let byte_offset = (member.offset / 8) as usize;
                    let member_size = member_ty.kind.size(btf).unwrap() as usize;
                    let val = Val::from_bytes(
                        btf,
                        member_ty,
                        &bytes[byte_offset..byte_offset + member_size],
                    );
                    map.insert(name.to_string(), val);
                }
                Val::Map(map)
            }
            _ => todo!("from_bytes: unsupported BTF kind"),
        }
    }
}

impl<const N: usize> From<[(&str, Val); N]> for Val {
    fn from(value: [(&str, Val); N]) -> Self {
        Self::Map(value.map(|(key, val)| (key.to_owned(), val)).into())
    }
}
