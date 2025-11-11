use std::{collections::HashMap, ffi::CString, iter::from_fn, rc::Rc};

use btf::Btf;
use object::{File, Object, ObjectSymbol, SectionIndex};

use crate::{
    loader::btf::{
        ext::{BpfFuncInfo, BtfExt},
        types::BtfKind,
    },
    maps::BpfMap,
};

pub mod btf;
pub mod elf;

pub struct Program {
    pub code: Vec<u8>,
    pub symbols: HashMap<String, usize>,
    #[allow(dead_code)]
    pub btf: Option<Btf>,
    pub btf_ext: Option<BtfExt>,
    pub maps: Vec<BpfMap>,
}

pub struct Entrypoint {
    pub offset: usize,
    pub ctx: Option<Context>,
    pub secname: String,
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

        Program {
            code: loader.loaded_prog,
            symbols,
            btf: loader.btf,
            btf_ext: loader.btf_ext,
            maps,
        }
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
    ///         ]
    ///     ).expect("failed to build entrypoint");
    /// let mut vm = Vm::new_with_entrypoint(program, entrypoint);
    /// ```
    ///
    /// The resulting `Entrypoint::ctx` will be a zeroed buffer of
    /// the size of the `__sk_buff` struct as described by the BTF
    /// type, populated with the `local_port` and `len` fields.
    pub fn build_entrypoint(&self, funcname: &str, ctx_params: &Val) -> Option<Entrypoint> {
        let offset = *self.symbols.get(funcname)?;

        let btf = self.btf.as_ref()?;
        let btf_ext = self.btf_ext.as_ref()?;

        let (secname, func) = btf_ext.func_info.iter().find_map(|info| {
            let funcs = parse_func_list(btf, &info.data);
            let func = funcs
                .into_iter()
                .find(|f| f.name.to_str().ok().map(|n| n == funcname).unwrap_or(false))?;
            let sec_name = btf.strings.get(&info.sec_name_off)?;
            Some((sec_name.to_string_lossy().to_string(), func))
        })?;

        let ctx = build_context(btf, &func, ctx_params);

        Some(Entrypoint {
            offset,
            ctx,
            secname,
        })
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

struct Func {
    name: CString,
    insn_off: u32,
    params: Vec<FuncInnerType>,
    ret: FuncInnerType,
}

struct FuncInnerType {
    name: Option<CString>,
    type_name: CString,
    type_id: u32,
}

fn resolve_type(btf: &Btf, type_id: u32) -> Option<(u32, &CString)> {
    let resolved = btf.get_type(type_id).and_then(|m| match &m.kind {
        BtfKind::Ptr(ty) => btf.get_type(*ty),
        _ => Some(m),
    })?;

    let type_name = btf.strings.get(&resolved.name_off)?;
    Some((resolved.btf_id, type_name))
}

fn parse_func(btf: &Btf, func_proto: &BtfKind) -> Option<(Vec<FuncInnerType>, FuncInnerType)> {
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
            let param_name = btf.strings.get(&p.name_off)?;
            let (type_id, type_name) = resolve_type(btf, p.r#type)?;
            Some(FuncInnerType {
                name: Some(param_name.clone()),
                type_name: type_name.clone(),
                type_id,
            })
        })
        .collect();

    let (type_id, type_name) = resolve_type(btf, *return_type)?;
    let ret = FuncInnerType {
        name: None,
        type_name: type_name.clone(),
        type_id,
    };

    Some((params, ret))
}

fn parse_func_list(btf: &Btf, func_info: &[BpfFuncInfo]) -> Vec<Func> {
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

fn build_context(btf: &Btf, func: &Func, ctx_val: &Val) -> Option<Context> {
    let ctx = func.params.first()?;
    let ty = btf.get_type(ctx.type_id).unwrap();
    match &ty.kind {
        BtfKind::Struct { members, size } => {
            let mut vec: Vec<_> = Vec::with_capacity(*size as usize);
            let Val::Map(ctx_map) = ctx_val else {
                panic!();
            };

            for ele in members {
                let ty = btf.get_type(ele.r#type).unwrap();
                let name = btf.strings.get(&ele.name_off).unwrap();

                let Some(field) = ctx_map.get(name.to_str().unwrap()) else {
                    let size = ty.kind.size(btf).expect("missing size") as usize;
                    vec.extend(from_fn(|| Some(0)).take(size));
                    continue;
                };

                match ty.kind {
                    BtfKind::Int { size, bits, .. } => match field {
                        Val::Number(n) if (n >> bits > 0) => {
                            panic!("number {n} is larger than field size");
                        }
                        Val::Number(n) => {
                            vec.extend_from_slice(&n.to_le_bytes()[..size as usize]);
                        }
                        _ => todo!("unsupported type"),
                    },
                    _ => {}
                }
            }

            Some(Context::Buffer(vec))
        }
        BtfKind::Int { bits, .. } => {
            let Val::Number(num) = ctx_val else {
                panic!("expected Number value for integer parameter");
            };

            if *num >> bits > 0 {
                panic!("number {num} is larger than parameter size");
            }

            Some(Context::Value(*num as u64))
        }
        _ => {
            todo!()
        }
    }
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
