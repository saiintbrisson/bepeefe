use std::{borrow::Cow, collections::BTreeMap, ffi::CStr};

mod builder;
pub use builder::BtfBuilder;

pub mod ext;
pub use ext::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BtfTypeId(pub u32);

type BtfStrOffset = u32;

#[derive(Clone, Debug)]
pub struct Btf {
    /// A map of strings contained in the BTF section, keyed by their byte
    /// offset within the section. Used in combination with `name_off` values.
    pub strings: Vec<u8>,
    /// A map of types described in the BTF section, keyed in the same order
    /// they are layed out. Starts from 1, 0 is reserved for void values.
    pub types: BTreeMap<BtfTypeId, BtfType>,
    /// Extension information on the object. Contains function declarations,
    /// code line mapping, and CO-RE relocations.
    pub ext: ext::BtfExt,
}

impl Default for Btf {
    fn default() -> Self {
        Self {
            strings: Default::default(),
            types: BTreeMap::new(),
            ext: Default::default(),
        }
    }
}

impl Btf {
    /// Finds a name at the given offset if the offset is within bounds.
    pub fn name(&self, offset: u32) -> Option<Cow<'_, str>> {
        CStr::from_bytes_until_nul(self.strings.get(offset as usize..)?)
            .ok()
            .map(CStr::to_string_lossy)
    }

    pub fn find_name(&self, name: &str) -> Option<u32> {
        if self.strings.len() < name.len() {
            return None;
        } else if name.len() == 0 {
            return Some(0);
        }

        let mut f = self.strings.iter().enumerate();
        loop {
            let (idx, _) = f.by_ref().skip_while(|(_, b)| **b == 0).next()?;

            let bytes = self.strings.get(idx..idx + name.len() - 1)?;
            let s = CStr::from_bytes_with_nul(bytes).ok()?.to_str().ok()?;

            if s == name {
                return Some(idx as u32);
            }
        }
    }

    pub fn get_type(&self, idx: BtfTypeId) -> Option<&BtfType> {
        self.resolve_indirections(self.types.get(&idx)?)
    }

    pub fn type_size(&self, idx: BtfTypeId) -> Option<u32> {
        self.get_type(idx)?.kind.size(self)
    }

    /// Ignore modifier and type definition indirections.
    ///
    /// Ref: <https://github.com/libbpf/libbpf/blob/09b9e83102eb8ab9e540d36b4559c55f3bcdb95d/src/libbpf.c#L2360>
    fn resolve_indirections<'a>(&'a self, mut btf_ty: &'a BtfType) -> Option<&'a BtfType> {
        loop {
            let btf_id = match btf_ty.kind {
                BtfKind::Typedef(btf_id)
                | BtfKind::Volatile(btf_id)
                | BtfKind::Const(btf_id)
                | BtfKind::Restrict(btf_id)
                | BtfKind::TypeTag(btf_id) => btf_id,
                _ => return Some(btf_ty),
            };

            btf_ty = self.types.get(&btf_id)?;
        }
    }

    pub fn is_offset_valid(&self, idx: BtfTypeId, offset: u32, len: u32) -> Option<bool> {
        let ty_size = self.type_size(idx)?;
        if offset + len > ty_size {
            return Some(false);
        }

        let btf_type = self.get_type(idx)?;

        match &btf_type.kind {
            BtfKind::Int(_) | BtfKind::Float(_) | BtfKind::Enum(_) | BtfKind::Enum64(_) => {
                Some(offset == 0 && len == ty_size)
            }
            BtfKind::Ptr(idx)
            | BtfKind::Volatile(idx)
            | BtfKind::Const(idx)
            | BtfKind::Restrict(idx) => self.is_offset_valid(*idx, offset, len),
            BtfKind::Array(array) => {
                let elem_size = self.type_size(array.r#type)?;
                let elem_offset = offset % elem_size;
                self.is_offset_valid(array.r#type, elem_offset, len)
            }
            BtfKind::Struct(Struct { members, .. }) | BtfKind::Union(Union { members, .. }) => {
                members.iter().find_map(|member| {
                    let offset = offset.checked_sub(member.offset / u8::BITS)?;
                    if offset + len > self.type_size(member.r#type)? {
                        return None;
                    }

                    self.is_offset_valid(member.r#type, offset, len)
                })
            }
            BtfKind::Fwd(fwd) => todo!(),
            BtfKind::Typedef(btf_type_id) => todo!(),
            BtfKind::Func(func) => todo!(),
            BtfKind::FuncProto(func_proto) => todo!(),
            BtfKind::Var(var) => todo!(),
            BtfKind::Datasec(datasec) => todo!(),
            BtfKind::DeclTag => todo!(),
            BtfKind::TypeTag(btf_type_id) => todo!(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BtfType {
    pub btf_id: BtfTypeId,
    pub name_off: BtfStrOffset,
    pub kind: BtfKind,
}

#[derive(Clone, Debug)]
pub enum BtfKind {
    Int(Int),
    Ptr(BtfTypeId),
    Array(Array),
    Struct(Struct),
    Union(Union),
    Enum(Enum),
    Fwd(Fwd),
    Typedef(BtfTypeId),
    Volatile(BtfTypeId),
    Const(BtfTypeId),
    Restrict(BtfTypeId),
    Func(Func),
    FuncProto(FuncProto),
    Var(Var),
    Datasec(Datasec),
    Float(Float),
    DeclTag,
    TypeTag(BtfTypeId),
    Enum64(Enum64),
}

pub const BTF_KIND_INT: u32 = 1;
pub const BTF_KIND_PTR: u32 = 2;
pub const BTF_KIND_ARRAY: u32 = 3;
pub const BTF_KIND_STRUCT: u32 = 4;
pub const BTF_KIND_UNION: u32 = 5;
pub const BTF_KIND_ENUM: u32 = 6;
pub const BTF_KIND_FWD: u32 = 7;
pub const BTF_KIND_TYPEDEF: u32 = 8;
pub const BTF_KIND_VOLATILE: u32 = 9;
pub const BTF_KIND_CONST: u32 = 10;
pub const BTF_KIND_RESTRICT: u32 = 11;
pub const BTF_KIND_FUNC: u32 = 12;
pub const BTF_KIND_FUNC_PROTO: u32 = 13;
pub const BTF_KIND_VAR: u32 = 14;
pub const BTF_KIND_DATASEC: u32 = 15;
pub const BTF_KIND_FLOAT: u32 = 16;
pub const BTF_KIND_DECL_TAG: u32 = 17;
pub const BTF_KIND_TYPE_TAG: u32 = 18;
pub const BTF_KIND_ENUM64: u32 = 19;

impl BtfKind {
    pub fn size(&self, btf: &Btf) -> Option<u32> {
        match self {
            BtfKind::Int(Int { size, .. })
            | BtfKind::Struct(Struct { size, .. })
            | BtfKind::Union(Union { size, .. })
            | BtfKind::Enum(Enum { size, .. })
            | BtfKind::Enum64(Enum64 { size, .. })
            | BtfKind::Float(Float { size })
            | BtfKind::Datasec(Datasec { size, .. }) => Some(*size),

            BtfKind::Array(btf_array) => {
                let elem_ty = btf
                    .types
                    .get(&btf_array.r#type)
                    .expect("missing array type");
                let elem_size = elem_ty.kind.size(btf)?;
                Some(elem_size * btf_array.no_elems)
            }

            BtfKind::Ptr(ty)
            | BtfKind::Typedef(ty)
            | BtfKind::Volatile(ty)
            | BtfKind::Const(ty)
            | BtfKind::Restrict(ty)
            | BtfKind::Var(Var { ty, .. })
            | BtfKind::TypeTag(ty) => {
                let elem_ty = btf.types.get(ty).expect("missing array type");
                elem_ty.kind.size(btf)
            }

            BtfKind::Fwd(Fwd { .. })
            | BtfKind::Func(Func { .. })
            | BtfKind::FuncProto(FuncProto { .. }) => None,

            BtfKind::DeclTag => todo!(),
        }
    }

    /// Returns the number of elements in the array, if the kind represents an
    /// array.
    pub fn array_no_elems(&self) -> Option<u32> {
        match self {
            BtfKind::Array(arr) => Some(arr.no_elems),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Int {
    /// size in bytes
    pub size: u32,

    // BTF_INT_SIGNED  (1 << 0)
    // BTF_INT_CHAR    (1 << 1)
    // BTF_INT_BOOL    (1 << 2)
    pub encoding: u8,
    pub offset: u8,
    pub bits: u8,
}

#[derive(Clone, Debug)]
pub struct Union {
    pub members: Vec<StructMember>,
    /// size of the struct in bytes
    pub size: u32,
}

/// Forward
#[derive(Clone, Debug)]
pub struct Fwd {
    pub kind_flag: bool,
}

#[derive(Clone, Debug)]
pub struct Func {
    pub linkage: FuncLinkage,
    pub func_proto: BtfTypeId,
}

#[derive(Clone, Debug)]
pub struct FuncProto {
    pub params: Vec<Param>,
    pub return_type: BtfTypeId,
}

#[derive(Clone, Debug)]
pub struct Var {
    pub ty: BtfTypeId,
    pub variable: Variable,
}

/// Section
#[derive(Clone, Debug)]
pub struct Datasec {
    pub secinfos: Vec<VarSecInfo>,
    pub size: u32,
}

#[derive(Clone, Debug)]
pub struct Float {
    pub size: u32,
}

/// Enumeration up to 32-bit values
#[derive(Clone, Debug)]
pub struct Enum {
    pub signed: bool,
    pub size: u32,
    pub values: Vec<EnumValue>,
}

#[derive(Clone, Debug)]
pub struct EnumValue {
    pub name_off: BtfStrOffset,
    pub val: i32,
}

#[derive(Clone, Debug)]
pub struct Array {
    pub r#type: BtfTypeId,
    pub index_type: BtfTypeId,
    pub no_elems: u32,
}

#[derive(Clone, Debug)]
pub struct Struct {
    pub members: Vec<StructMember>,
    /// size of the struct in bytes
    pub size: u32,
}

#[derive(Clone, Debug)]
pub struct StructMember {
    pub name_off: BtfStrOffset,
    pub r#type: BtfTypeId,
    pub bitfield_size: Option<u32>,
    // Member bit offset from struct beginning
    pub offset: u32,
}

#[derive(Clone, Debug)]
pub struct Variable {
    pub linkage: VariableLinkage,
}

#[derive(Clone, Debug)]
pub struct Param {
    pub name_off: BtfStrOffset,
    pub r#type: BtfTypeId,
}

#[derive(Copy, Clone, Debug)]
pub struct VarSecInfo {
    pub r#type: BtfTypeId,
    pub offset: u32,
    pub size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FuncLinkage {
    /// definition of subprogram not visible outside containing compilation unit
    Static = 0x0,
    /// definition of subprogram visible outside containing compilation unit
    Global = 0x1,
    /// declaration of a subprogram whose definition is outside the containing
    /// compilation unit
    Extern = 0x2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VariableLinkage {
    /// definition of global variable not visible outside containing compilation
    /// unit
    Static = 0x0,
    /// definition of global variable visible outside containing compilation
    /// unit
    GlobalAllocated = 0x1,
    /// declaration of global variable whose definition is outside the
    /// containing compilation unit
    GlobalExtern = 0x2,
}

#[derive(Clone, Debug)]
/// Enumeration up to 64-bit values
pub struct Enum64 {
    pub signed: bool,
    pub size: u32,
    pub values: Vec<Enum64Value>,
}

#[derive(Clone, Debug)]
pub struct Enum64Value {
    pub name_off: u32,
    pub val_lo32: u32,
    pub val_hi32: u32,
}

mod parser {
    use std::io::Result;

    use crate::btf::{Datasec, Enum, Enum64, Float, Func, FuncProto, Fwd, Int, Struct, Union, Var};

    use super::*;
    use byteorder::{LittleEndian, ReadBytesExt};

    pub const BTF_MAGIC: [u8; 2] = [0x9F, 0xEB];

    #[allow(dead_code)]
    #[derive(Clone, Debug)]
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

    impl Btf {
        pub fn from_bytes(data: &[u8]) -> Result<Self> {
            assert_eq!(data[..2], BTF_MAGIC);

            let header_data = &mut &data[2..];
            let header = BtfHeader {
                version: header_data.read_u8()?,
                flags: header_data.read_u8()?,
                hdr_len: header_data.read_u32::<LittleEndian>()?,
                type_off: header_data.read_u32::<LittleEndian>()?,
                type_len: header_data.read_u32::<LittleEndian>()?,
                str_off: header_data.read_u32::<LittleEndian>()?,
                str_len: header_data.read_u32::<LittleEndian>()?,
            };

            let str_off = (header.hdr_len + header.str_off) as usize;
            let strings = data[str_off..str_off + header.str_len as usize].to_vec();

            let type_off = (header.hdr_len + header.type_off) as usize;
            let type_data = &mut &data[type_off..type_off + header.type_len as usize];
            let mut types = BTreeMap::new();

            while !type_data.is_empty() {
                let name_off = type_data.read_u32::<LittleEndian>()?;
                let info = type_data.read_u32::<LittleEndian>()?;
                let data = type_data.read_u32::<LittleEndian>()?;

                let kind = BtfKind::from_ty(info, data, type_data)?;
                let btf_id = BtfTypeId(types.len() as u32 + 1);
                types.insert(
                    btf_id,
                    BtfType {
                        btf_id,
                        name_off,
                        kind,
                    },
                );
            }

            Ok(Btf {
                strings,
                types,
                ..Default::default()
            })
        }
    }

    impl BtfKind {
        pub fn from_ty(info: u32, size_or_type: u32, data: &mut &[u8]) -> Result<Self> {
            let vlen = info & 0xFFFF;
            let kind = (info >> 24) & 0x1F;
            // TODO: support kind flag for decl_tag and type_tag
            let kind_flag = info >> 31 == 1;

            let kind = match kind {
                BTF_KIND_INT => {
                    let data = data.read_u32::<LittleEndian>()?;

                    Self::Int(Int {
                        encoding: ((data >> 24) & 0x0F) as u8,
                        offset: ((data >> 16) & 0xFF) as u8,
                        bits: (data & 0xFF) as u8,
                        size: size_or_type,
                    })
                }
                BTF_KIND_PTR => Self::Ptr(BtfTypeId(size_or_type)),
                BTF_KIND_ARRAY => Self::Array(Array {
                    r#type: BtfTypeId(data.read_u32::<LittleEndian>()?),
                    index_type: BtfTypeId(data.read_u32::<LittleEndian>()?),
                    no_elems: data.read_u32::<LittleEndian>()?,
                }),
                BTF_KIND_STRUCT => {
                    let mut members = Vec::with_capacity(vlen as usize);
                    for _ in 0..vlen {
                        let name_off = data.read_u32::<LittleEndian>()?;
                        let r#type = BtfTypeId(data.read_u32::<LittleEndian>()?);
                        let offset = data.read_u32::<LittleEndian>()?;
                        members.push(StructMember {
                            name_off,
                            r#type,
                            bitfield_size: if kind_flag { Some(offset >> 24) } else { None },
                            offset: if kind_flag { offset & 0xFFFFFF } else { offset },
                        });
                    }

                    Self::Struct(Struct {
                        members,
                        size: size_or_type,
                    })
                }
                BTF_KIND_UNION => {
                    let mut members = Vec::with_capacity(vlen as usize);
                    for _ in 0..vlen {
                        let name_off = data.read_u32::<LittleEndian>()?;
                        let r#type = BtfTypeId(data.read_u32::<LittleEndian>()?);
                        let offset = data.read_u32::<LittleEndian>()?;
                        members.push(StructMember {
                            name_off,
                            r#type,
                            bitfield_size: if kind_flag { Some(offset >> 24) } else { None },
                            offset: if kind_flag { offset & 0xFFFFFF } else { offset },
                        });
                    }

                    Self::Union(Union {
                        members,
                        size: size_or_type,
                    })
                }
                BTF_KIND_ENUM => {
                    let mut values = Vec::with_capacity(vlen as usize);
                    for _ in 0..vlen {
                        values.push(EnumValue {
                            name_off: data.read_u32::<LittleEndian>()?,
                            val: data.read_i32::<LittleEndian>()?,
                        });
                    }

                    Self::Enum(Enum {
                        signed: kind_flag,
                        size: size_or_type,
                        values,
                    })
                }
                BTF_KIND_FWD => Self::Fwd(Fwd { kind_flag }),
                BTF_KIND_TYPEDEF => Self::Typedef(BtfTypeId(size_or_type)),
                BTF_KIND_VOLATILE => Self::Volatile(BtfTypeId(size_or_type)),
                BTF_KIND_CONST => Self::Const(BtfTypeId(size_or_type)),
                BTF_KIND_RESTRICT => Self::Restrict(BtfTypeId(size_or_type)),
                BTF_KIND_FUNC => Self::Func(Func {
                    func_proto: BtfTypeId(size_or_type),
                    linkage: match vlen {
                        0x0 => FuncLinkage::Static,
                        0x1 => FuncLinkage::Global,
                        0x2 => FuncLinkage::Extern,
                        _ => unreachable!(),
                    },
                }),
                BTF_KIND_FUNC_PROTO => {
                    let mut params = Vec::with_capacity(vlen as usize);
                    for _ in 0..vlen {
                        params.push(Param {
                            name_off: data.read_u32::<LittleEndian>()?,
                            r#type: BtfTypeId(data.read_u32::<LittleEndian>()?),
                        });
                    }

                    Self::FuncProto(FuncProto {
                        params,
                        return_type: BtfTypeId(size_or_type),
                    })
                }
                BTF_KIND_VAR => Self::Var(Var {
                    variable: Variable {
                        linkage: match data.read_u32::<LittleEndian>()? {
                            0x0 => VariableLinkage::Static,
                            0x1 => VariableLinkage::GlobalAllocated,
                            0x2 => VariableLinkage::GlobalExtern,
                            _ => unreachable!(),
                        },
                    },
                    ty: BtfTypeId(size_or_type),
                }),
                BTF_KIND_DATASEC => {
                    let mut secinfos = Vec::with_capacity(vlen as usize);
                    for _ in 0..vlen {
                        secinfos.push(VarSecInfo {
                            r#type: BtfTypeId(data.read_u32::<LittleEndian>()?),
                            offset: data.read_u32::<LittleEndian>()?,
                            size: data.read_u32::<LittleEndian>()?,
                        });
                    }

                    Self::Datasec(Datasec {
                        secinfos,
                        size: size_or_type,
                    })
                }
                BTF_KIND_FLOAT => Self::Float(Float { size: size_or_type }),
                BTF_KIND_DECL_TAG => todo!(),
                BTF_KIND_TYPE_TAG => Self::TypeTag(BtfTypeId(size_or_type)),
                BTF_KIND_ENUM64 => {
                    let mut values = Vec::with_capacity(vlen as usize);
                    for _ in 0..vlen {
                        values.push(Enum64Value {
                            name_off: data.read_u32::<LittleEndian>()?,
                            val_lo32: data.read_u32::<LittleEndian>()?,
                            val_hi32: data.read_u32::<LittleEndian>()?,
                        });
                    }

                    Self::Enum64(Enum64 {
                        signed: kind_flag,
                        size: size_or_type,
                        values,
                    })
                }
                _ => unreachable!(),
            };

            Ok(kind)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_names_by_offset_and_str() {
        let mut btf = Btf::default();
        btf.strings = b"\0struct\0func_name\0\0u32\0".to_vec();

        assert_eq!(btf.name(1).unwrap(), "struct");
        assert_eq!(btf.name(8).unwrap(), "func_name");
        assert_eq!(btf.name(19).unwrap(), "u32");

        assert_eq!(btf.find_name("struct").unwrap(), 1);
        assert_eq!(btf.find_name("func_name").unwrap(), 8);
        assert_eq!(btf.find_name("u32").unwrap(), 19);
    }
}
