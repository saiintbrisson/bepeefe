use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
};

use byteorder::{LittleEndian, ReadBytesExt};
use object::{Object, ObjectSection};
use types::{BtfKind, BtfStrOffset, BtfType, BtfTypeIndex, BtfVariable, BtfVariableLinkage};

use super::Loader;

pub mod ext;
pub mod types;

#[derive(Debug)]
pub struct Btf {
    /// A map of strings contained in the BTF section, keyed by their byte
    /// offset within the section. Used in combination with `name_off` values.
    pub strings: BTreeMap<BtfStrOffset, CString>,
    /// A map of types described in the BTF section, keyed in the same order
    /// they are layed out. Starts from 1, 0 is reserved for void values.
    pub types: BTreeMap<BtfTypeIndex, BtfType>,
}

impl Btf {
    fn get_type(&self, idx: BtfTypeIndex) -> Option<&BtfType> {
        self.resolve_indirections(self.types.get(&idx)?)
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct BtfHeader {
    /// For now, 1.
    version: u8,
    flags: u8,
    /// Header length in bytes, same as `size_of::<BtfHeader>()`.
    hdr_len: u32,

    /// Beginning of the type section relative to the end of the BTF header.
    type_off: u32,
    /// Length of type section in bytes.
    type_len: u32,
    /// Beginning of the string section relative to the end of the BTF header.
    str_off: u32,
    /// Length of string section in bytes.
    str_len: u32,
}

impl<'data> Loader<'data> {
    pub fn load_btf(&mut self) -> Option<&Btf> {
        let section = self.file.section_by_name(".BTF")?;

        let data = section.data().unwrap();
        assert_eq!(data[..2], BTF_MAGIC);

        let header_data = &mut &data[2..];
        let header = BtfHeader {
            version: header_data.read_u8().unwrap(),
            flags: header_data.read_u8().unwrap(),
            hdr_len: header_data.read_u32::<LittleEndian>().unwrap(),
            type_off: header_data.read_u32::<LittleEndian>().unwrap(),
            type_len: header_data.read_u32::<LittleEndian>().unwrap(),
            str_off: header_data.read_u32::<LittleEndian>().unwrap(),
            str_len: header_data.read_u32::<LittleEndian>().unwrap(),
        };

        let str_off = (header.hdr_len + header.str_off) as usize;
        let str_data = &data[str_off..str_off + header.str_len as usize];
        let mut strings: BTreeMap<u32, CString> = BTreeMap::new();
        let mut str_cursor = 0;

        while str_cursor < str_data.len() {
            let s = CStr::from_bytes_until_nul(&str_data[str_cursor..]).unwrap();
            strings.insert(str_cursor as u32, s.to_owned());
            str_cursor += s.count_bytes() + 1;
        }

        let type_off = (header.hdr_len + header.type_off) as usize;
        let type_data = &mut &data[type_off..type_off + header.type_len as usize];
        let mut types = BTreeMap::new();

        while !type_data.is_empty() {
            let name_off = type_data.read_u32::<LittleEndian>().unwrap();
            let info = type_data.read_u32::<LittleEndian>().unwrap();
            let data = type_data.read_u32::<LittleEndian>().unwrap();

            let kind = BtfKind::from_ty(info, data, type_data).unwrap();
            types.insert(types.len() as u32 + 1, BtfType { name_off, kind });
        }

        let btf = Btf { strings, types };

        self.btf = Some(btf);
        self.btf.as_ref()
    }
}

impl Btf {
    /// Finds declared maps by looking for the .maps section and matching it
    /// against the .maps BTF type. Maps are BTF structs behind
    /// [`BtfVariableLinkage::GlobalAllocated`] variables. Once you find the
    /// struct, its fields are behind PTR types, and when you finally get to
    /// the correct type, it is either a type, say `unsigned int` for fields
    /// like `key`/`value`, or as an ARRAY, where the value itself is the
    /// dimensionality of the array for other fields, like `type`.
    ///
    /// Reference: <https://github.com/libbpf/libbpf/blob/09b9e83102eb8ab9e540d36b4559c55f3bcdb95d/src/libbpf.c#L2429>
    pub fn load_maps(&self) -> BTreeMap<&CStr, BtfMap<'_>> {
        let Some((name_off, _)) = self
            .strings
            .iter()
            .find(|(_, name)| name.to_string_lossy() == ".maps")
        else {
            return Default::default();
        };

        let Some(btf_ty) = self.types.values().find(|ty| ty.name_off == *name_off) else {
            panic!("maps section does not have corresponding BTF type");
        };

        let secinfos = match &btf_ty.kind {
            BtfKind::Datasec { secinfos, .. } => secinfos,
            _ => panic!("expected BTF map type to be data section"),
        };

        let mut maps = BTreeMap::new();

        for info in secinfos {
            let btf_ty = self
                .get_type(info.r#type)
                .expect("secinfo references invalid type");

            let BtfKind::Var {
                ty,
                variable:
                    BtfVariable {
                        linkage: BtfVariableLinkage::GlobalAllocated,
                    },
            } = &btf_ty.kind
            else {
                continue;
            };

            let map_name = self.strings.get(&btf_ty.name_off);

            let btf_ty = self.get_type(*ty).expect("missing map definition");
            let BtfKind::Struct { members, .. } = &btf_ty.kind else {
                continue;
            };

            let Some(map_name) = map_name.or_else(|| self.strings.get(&btf_ty.name_off)) else {
                panic!("map missing name");
            };

            let mut map_builder = BtfMap::default();
            for member in members {
                let Some(name) = self.strings.get(&member.name_off) else {
                    panic!("struct member missing name");
                };

                let ty = self
                    .get_type(member.r#type)
                    .and_then(|m| match &m.kind {
                        BtfKind::Ptr(ty) => self.get_type(*ty),
                        kind => panic!("wrong map field ty {name:?}: {kind:?}"),
                    })
                    .expect("map field references invalid ty {name:?}");

                match &*name.to_string_lossy() {
                    "type" => map_builder.r#type = ty.kind.array_no_elems(),
                    "max_entries" => map_builder.max_entries = ty.kind.array_no_elems(),
                    "map_flags" => map_builder.map_flags = ty.kind.array_no_elems(),
                    "map_extra" => map_builder.map_extra = ty.kind.array_no_elems(),
                    "numa_node" => map_builder.numa_node = ty.kind.array_no_elems(),
                    "key_size" => map_builder.key_size = ty.kind.array_no_elems(),
                    "value_size" => map_builder.value_size = ty.kind.array_no_elems(),
                    "key" => map_builder.key = Some(ty),
                    "value" => map_builder.value = Some(ty),
                    "values" => map_builder.values = Some(ty),
                    name => panic!("unknown map field: {name:?}"),
                }
            }

            maps.insert(map_name.as_c_str(), map_builder);
        }

        maps
    }

    /// Ignore modifier and type definition indirections.
    fn resolve_indirections<'a>(&'a self, mut btf_ty: &'a BtfType) -> Option<&'a BtfType> {
        loop {
            let btf_id = match btf_ty.kind {
                BtfKind::Typedef(btf_id)
                | BtfKind::Volatile(btf_id)
                | BtfKind::Const(btf_id)
                | BtfKind::Restrict(btf_id) => btf_id,
                BtfKind::TypeTag => todo!(),
                _ => return Some(btf_ty),
            };

            btf_ty = self.types.get(&btf_id)?;
        }
    }
}

pub const BTF_MAGIC: [u8; 2] = [0x9F, 0xEB];

#[derive(Debug, Default)]
pub struct BtfMap<'b> {
    pub r#type: Option<u32>,
    pub max_entries: Option<u32>,
    pub map_flags: Option<u32>,
    pub map_extra: Option<u32>,
    pub numa_node: Option<u32>,
    pub key_size: Option<u32>,
    pub value_size: Option<u32>,
    pub key: Option<&'b BtfType>,
    pub value: Option<&'b BtfType>,
    pub values: Option<&'b BtfType>,
}
