use std::{collections::HashMap, ffi::CString, rc::Rc};

use btf::Btf;
use object::{File, Object, ObjectSymbol, SectionIndex};

use crate::{
    loader::btf::{
        ext::{BpfFuncInfo, BtfExt},
        types::{BtfKind, BtfTypeIndex},
    },
    maps::BpfMap,
};

pub mod btf;
pub mod elf;

pub struct Program {
    pub code: Vec<u8>,
    pub symbols: HashMap<String, usize>,
    pub functions: HashMap<String, ParsedFunc>,
    #[allow(dead_code)]
    pub btf: Option<Btf>,
    pub btf_ext: Option<BtfExt>,
    pub maps: Vec<BpfMap>,
}

struct ParsedFunc {
    secname: String,
    offset: usize,
    params: Vec<u32>,
    ret: u32,
}

pub struct Entrypoint {
    pub offset: usize,
    pub ctx: Option<Context>,
    pub secname: String,
}

pub struct ProgramFunction {
    pub offset: usize,
    pub secname: String,
    ctx_type: Option<ResolvedType>,
}

impl ProgramFunction {
    pub fn build_entrypoint(&self, ctx_params: &Val) -> Entrypoint {
        let ctx = self.ctx_type.as_ref().map(|ty| match ty {
            ResolvedType::Struct {
                name,
                size,
                members,
            } => {
                let mut vec = Vec::with_capacity(*size);
                let Val::Map(ctx_map) = ctx_params else {
                    panic!("expected Map value for struct parameter");
                };

                let mut used_fields = Vec::with_capacity(ctx_map.len());

                for member in members {
                    let Some(field) = ctx_map.get(&member.name) else {
                        let size = match &member.ty {
                            &ResolvedType::Int { size, .. } => size,
                            &ResolvedType::Struct { size, .. }
                            | &ResolvedType::Unknown { size } => size,
                        };
                        vec.extend(std::iter::repeat_n(0, size));
                        continue;
                    };

                    used_fields.push(member.name.as_str());

                    match &member.ty {
                        &ResolvedType::Int { size, bits } => match field {
                            Val::Number(n) if (n >> bits > 0) => {
                                panic!("number {n} is larger than field size");
                            }
                            Val::Number(n) => {
                                vec.extend_from_slice(&n.to_le_bytes()[..size as usize]);
                            }
                            _ => panic!("expected Number value for integer field"),
                        },
                        &ResolvedType::Struct { size, .. } | &ResolvedType::Unknown { size } => {
                            vec.extend(std::iter::repeat_n(0, size));
                        }
                    }
                }

                for (provided_field, _) in ctx_map {
                    if !used_fields.contains(&provided_field.as_str()) {
                        panic!("field {provided_field:?} does not exist in struct {name:?}");
                    }
                }

                Context::Buffer(vec)
            }
            ResolvedType::Int { bits, .. } => {
                let Val::Number(num) = ctx_params else {
                    panic!("expected Number value for integer parameter");
                };

                if *num >> bits > 0 {
                    panic!("number {num} is larger than parameter size");
                }

                Context::Value(*num as u64)
            }
            _ => todo!(),
        });

        Entrypoint {
            offset: self.offset,
            ctx,
            secname: self.secname.clone(),
        }
    }
}

enum ResolvedType {
    Struct {
        name: String,
        size: usize,
        members: Vec<ResolvedMember>,
    },
    Int {
        size: usize,
        bits: u8,
    },
    Unknown {
        size: usize,
    },
}

struct ResolvedMember {
    name: String,
    ty: ResolvedType,
}

pub enum Context {
    Buffer(Vec<u8>),
    Value(u64),
}

pub enum Val {
    Number(i64),
    Map(HashMap<String, Val>),
}

impl<const N: usize> From<[(&str, Val); N]> for Val {
    fn from(value: [(&str, Val); N]) -> Self {
        Self::Map(value.map(|(key, val)| (key.to_owned(), val)).into())
    }
}

impl Program {
    pub fn from_object(object: &[u8]) -> Self {
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
        let maps = maps.into_iter().map(|(map, _)| map).collect();
        let symbols = collect_syms(&loader);
        let functions = collect_funcs(&loader, &symbols);

        Program {
            code: loader.loaded_prog,
            symbols,
            functions,
            btf: loader.btf,
            btf_ext: loader.btf_ext,
            maps,
        }
    }

    /// Finds and parses a BTF function. The returned struct
    /// describes a function signature and its parameter types,
    /// allowing entrypoint contexts to be built without the need
    /// of the BTF type information.
    pub fn resolve_function(&self, funcname: &str) -> Option<ProgramFunction> {
        let parsed = self.functions.get(funcname)?;
        let btf = self.btf.as_ref()?;

        let ctx_type = parsed.params.first().and_then(|&type_id| {
            let ty = btf.get_type(type_id)?;
            match &ty.kind {
                BtfKind::Struct { members, size } => {
                    let name = btf.strings.get(&ty.name_off)?.to_string_lossy().to_string();

                    let resolved_members = members
                        .iter()
                        .filter_map(|member| {
                            let ty = btf.get_type(member.r#type)?;
                            let name = btf.strings.get(&member.name_off)?;
                            let member_ty = match &ty.kind {
                                &BtfKind::Int { size, bits, .. } => ResolvedType::Int {
                                    size: size as usize,
                                    bits: bits,
                                },
                                _ => {
                                    let size = ty.kind.size(btf)?;
                                    ResolvedType::Unknown {
                                        size: size as usize,
                                    }
                                }
                            };
                            Some(ResolvedMember {
                                name: name.to_str().ok()?.to_string(),
                                ty: member_ty,
                            })
                        })
                        .collect();

                    Some(ResolvedType::Struct {
                        name,
                        size: *size as usize,
                        members: resolved_members,
                    })
                }
                &BtfKind::Int { size, bits, .. } => Some(ResolvedType::Int {
                    size: size as usize,
                    bits: bits as u8,
                }),
                _ => None,
            }
        });

        Some(ProgramFunction {
            offset: parsed.offset,
            secname: parsed.secname.clone(),
            ctx_type,
        })
    }

    /// Given a function name, we search for a matching BTF
    /// function entry. The `ctx_params` are a list of
    /// `(field name, value)` used to generate a function
    /// context, the eBPFs proogram parameter, like `__sk_buff`.
    ///
    /// The function uses BTF information to generate the entire
    /// struct, and each entry in `ctx_params` overrides one of
    /// the context's fields.
    ///
    /// For example, an entrypoint that takes `__sk_buff` can be
    /// built with:
    ///
    /// ```
    /// # use bepeefe::{vm::Vm, loader::*};
    /// # let file = std::fs::read("./examples/bpf/map_array.o").unwrap();
    /// let program = Program::from_object(&file);
    /// let entrypoint = program
    ///     .build_entrypoint(
    ///         "entry",
    ///         &[
    ///             ("local_port", Val::Number(3000)),
    ///             ("len", Val::Number(64))
    ///         ].into()
    ///     ).expect("failed to build entrypoint");
    /// # let mut vm = Vm::new(program);
    /// vm.run(entrypoint);
    /// ```
    ///
    /// The resulting `Entrypoint::ctx` will be a zeroed buffer of
    /// the size of the `__sk_buff` struct as described by the BTF
    /// type, populated with the `local_port` and `len` fields.
    ///
    /// # Note
    ///
    /// When calling this function multiple times, check [`Program::resolve_function`],
    /// and [`ProgramFunction::build_entrypoint`].
    pub fn build_entrypoint(&self, funcname: &str, ctx_params: &Val) -> Option<Entrypoint> {
        let func = self.resolve_function(funcname)?;
        Some(func.build_entrypoint(ctx_params))
    }
}

fn collect_syms(loader: &Loader<'_>) -> HashMap<String, usize> {
    let symbols: HashMap<String, usize> = loader
        .file
        .symbols()
        .filter_map(|symbol| {
            if !symbol.is_definition() || symbol.is_undefined() {
                return None;
            }

            let name = symbol.name().ok()?.to_string();
            let sec_idx = symbol.section_index()?;
            let sec_base = *loader.loaded_sections.get(&sec_idx)?;
            let byte_offset = sec_base + symbol.address() as usize;

            assert!(
                byte_offset.is_multiple_of(8),
                "symbol '{}' at offset {} is not 8-byte aligned",
                name,
                byte_offset
            );

            Some((name, byte_offset / 8))
        })
        .collect();
    symbols
}

fn collect_funcs(
    loader: &Loader<'_>,
    symbols: &HashMap<String, usize>,
) -> HashMap<String, ParsedFunc> {
    let Some((btf, btf_ext)) = &loader.btf.as_ref().zip(loader.btf_ext.as_ref()) else {
        return HashMap::new();
    };

    btf_ext
        .func_info
        .iter()
        .flat_map(|info| {
            let secname = btf
                .strings
                .get(&info.sec_name_off)?
                .to_string_lossy()
                .to_string();
            let funcs = parse_func_list(btf, &info.data);

            Some(funcs.into_iter().filter_map(move |func| {
                let name = func.name.to_str().ok()?.to_string();
                let offset = symbols.get(&name).copied()?;
                let params = func.params.iter().map(|(_, type_id)| *type_id).collect();

                Some((
                    name,
                    ParsedFunc {
                        secname: secname.clone(),
                        offset,
                        params,
                        ret: func.ret,
                    },
                ))
            }))
        })
        .flatten()
        .collect()
}

#[derive(Debug)]
struct Func {
    name: CString,
    insn_off: u32,
    params: Vec<(u32, BtfTypeIndex)>,
    ret: BtfTypeIndex,
}

fn parse_func_list(btf: &Btf, func_info: &[BpfFuncInfo]) -> Vec<Func> {
    fn resolve_type(btf: &Btf, type_id: u32) -> Option<u32> {
        let resolved = btf.get_type(type_id).and_then(|m| match &m.kind {
            BtfKind::Ptr(ty) => btf.get_type(*ty),
            _ => Some(m),
        })?;

        Some(resolved.btf_id)
    }

    fn parse_func(
        btf: &Btf,
        func_proto: &BtfKind,
    ) -> Option<(Vec<(u32, BtfTypeIndex)>, BtfTypeIndex)> {
        let BtfKind::FuncProto {
            params,
            return_type,
        } = func_proto
        else {
            return None;
        };

        let params = params
            .iter()
            .filter_map(|p| {
                let type_id = resolve_type(btf, p.r#type)?;
                Some((p.name_off, type_id))
            })
            .collect();

        Some((params, resolve_type(btf, *return_type)?))
    }

    func_info
        .iter()
        .filter_map(|info| {
            let ty = btf.types.get(&info.type_id)?;
            let name = btf.strings.get(&ty.name_off)?;

            let BtfKind::Func { func_proto, .. } = &ty.kind else {
                return None;
            };

            let proto = btf.types.get(func_proto)?;
            let (params, ret) = parse_func(btf, &proto.kind)?;

            Some(Func {
                name: name.clone(),
                insn_off: info.insn_off,
                params,
                ret,
            })
        })
        .collect()
}

struct MapDecl {
    sec_idx: usize,
    sec_offset: u32,
}

struct Loader<'data> {
    file: Rc<File<'data, &'data [u8]>>,
    loaded_prog: Vec<u8>,
    loaded_sections: HashMap<SectionIndex, usize>,
    btf: Option<Btf>,
    btf_ext: Option<BtfExt>,
    btf_maps_sec: Option<SectionIndex>,
}

impl<'data> Loader<'data> {
    fn new(data: &'data [u8]) -> Self {
        Self {
            file: Rc::new(File::parse(data).unwrap()),
            loaded_prog: Vec::with_capacity(data.len()),
            loaded_sections: HashMap::new(),
            btf: None,
            btf_ext: None,
            btf_maps_sec: None,
        }
    }
}
