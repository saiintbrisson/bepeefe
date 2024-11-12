#![allow(dead_code)]

use byteorder::{LittleEndian, ReadBytesExt};

pub type BtfStrOffset = u32;
pub type BtfTypeIndex = u32;

#[derive(Debug)]
pub struct BtfType {
    pub name_off: BtfStrOffset,
    pub kind: BtfKind,
}

#[derive(Debug)]
pub enum BtfKind {
    Int {
        /// size in bytes
        size: u32,

        // BTF_INT_SIGNED  (1 << 0)
        // BTF_INT_CHAR    (1 << 1)
        // BTF_INT_BOOL    (1 << 2)
        encoding: u8,
        offset: u8,
        bits: u8,
    },
    Ptr(BtfTypeIndex),
    Array(BtfArray),
    Struct {
        members: Vec<BtfStructMember>,
        /// size of the struct in bytes
        size: u32,
    },
    Union {
        members: Vec<BtfStructMember>,
        /// size of the struct in bytes
        size: u32,
    },
    /// Enumeration up to 32-bit values
    Enum {
        signed: bool,
        size: u32,
        values: Vec<BtfEnumValue>,
    },
    /// Forward
    Fwd {
        kind_flag: u32,
    },
    Typedef(BtfTypeIndex),
    Volatile(BtfTypeIndex),
    Const(BtfTypeIndex),
    Restrict(BtfTypeIndex),
    Func {
        linkage: BtfFuncLinkage,
        func_proto: BtfTypeIndex,
    },
    FuncProto {
        params: Vec<BtfParam>,
        return_type: BtfTypeIndex,
    },
    Var {
        ty: BtfTypeIndex,
        variable: BtfVariable,
    },
    /// Section
    Datasec {
        secinfos: Vec<BtfVarSecinfo>,
        size: u32,
    },
    Float {
        size: u32,
    },
    DeclTag,
    TypeTag,
    /// Enumeration up to 64-bit values
    Enum64,
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
    pub fn from_ty(info: u32, size_or_type: u32, data: &mut &[u8]) -> std::io::Result<Self> {
        let vlen = info & 0xFFFF;
        let kind = (info >> 24) & 0x1F;

        let kind = match kind {
            BTF_KIND_INT => {
                let data = data.read_u32::<LittleEndian>()?;

                Self::Int {
                    encoding: (data >> 24) as u8,
                    offset: (data >> 16) as u8,
                    bits: data as u8,
                    size: size_or_type,
                }
            }
            BTF_KIND_PTR => Self::Ptr(size_or_type),
            BTF_KIND_ARRAY => Self::Array(BtfArray {
                r#type: data.read_u32::<LittleEndian>()?,
                index_type: data.read_u32::<LittleEndian>()?,
                no_elems: data.read_u32::<LittleEndian>()?,
            }),
            BTF_KIND_STRUCT => {
                let mut members = Vec::with_capacity(vlen as usize);
                for _ in 0..vlen {
                    members.push(BtfStructMember {
                        name_off: data.read_u32::<LittleEndian>()?,
                        r#type: data.read_u32::<LittleEndian>()?,
                        offset: data.read_u32::<LittleEndian>()?,
                    });
                }

                Self::Struct {
                    members,
                    size: size_or_type,
                }
            }
            BTF_KIND_UNION => {
                let mut members = Vec::with_capacity(vlen as usize);
                for _ in 0..vlen {
                    members.push(BtfStructMember {
                        name_off: data.read_u32::<LittleEndian>()?,
                        r#type: data.read_u32::<LittleEndian>()?,
                        offset: data.read_u32::<LittleEndian>()?,
                    });
                }

                Self::Union {
                    members,
                    size: size_or_type,
                }
            }
            BTF_KIND_ENUM => {
                let mut values = Vec::with_capacity(vlen as usize);
                for _ in 0..vlen {
                    values.push(BtfEnumValue {
                        name_off: data.read_u32::<LittleEndian>()?,
                        val: data.read_i32::<LittleEndian>()?,
                    });
                }

                Self::Enum {
                    signed: info >> 31 != 0,
                    size: size_or_type,
                    values,
                }
            }
            BTF_KIND_FWD => Self::Fwd {
                kind_flag: info >> 31,
            },
            BTF_KIND_TYPEDEF => Self::Typedef(size_or_type),
            BTF_KIND_VOLATILE => Self::Volatile(size_or_type),
            BTF_KIND_CONST => Self::Const(size_or_type),
            BTF_KIND_RESTRICT => Self::Restrict(size_or_type),
            BTF_KIND_FUNC => Self::Func {
                func_proto: size_or_type,
                linkage: match vlen {
                    0x0 => BtfFuncLinkage::Static,
                    0x1 => BtfFuncLinkage::Global,
                    0x2 => BtfFuncLinkage::Extern,
                    _ => unreachable!(),
                },
            },
            BTF_KIND_FUNC_PROTO => {
                let mut params = Vec::with_capacity(vlen as usize);
                for _ in 0..vlen {
                    params.push(BtfParam {
                        name_off: data.read_u32::<LittleEndian>()?,
                        r#type: data.read_u32::<LittleEndian>()?,
                    });
                }

                Self::FuncProto {
                    params,
                    return_type: size_or_type,
                }
            }
            BTF_KIND_VAR => Self::Var {
                variable: BtfVariable {
                    linkage: match data.read_u32::<LittleEndian>()? {
                        0x0 => BtfVariableLinkage::Static,
                        0x1 => BtfVariableLinkage::GlobalAllocated,
                        0x2 => BtfVariableLinkage::GlobalExtern,
                        _ => unreachable!(),
                    },
                },
                ty: size_or_type,
            },
            BTF_KIND_DATASEC => {
                let mut secinfos = Vec::with_capacity(vlen as usize);
                for _ in 0..vlen {
                    secinfos.push(BtfVarSecinfo {
                        r#type: data.read_u32::<LittleEndian>()?,
                        offset: data.read_u32::<LittleEndian>()?,
                        size: data.read_u32::<LittleEndian>()?,
                    });
                }

                Self::Datasec {
                    secinfos,
                    size: size_or_type,
                }
            }
            BTF_KIND_FLOAT => Self::Float { size: size_or_type },
            BTF_KIND_DECL_TAG => todo!(),
            BTF_KIND_TYPE_TAG => todo!(),
            BTF_KIND_ENUM64 => todo!(),
            _ => unreachable!(),
        };

        Ok(kind)
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

#[derive(Debug)]
pub struct BtfEnumValue {
    pub name_off: BtfStrOffset,
    pub val: i32,
}

#[derive(Debug)]
pub struct BtfArray {
    pub r#type: BtfTypeIndex,
    pub index_type: BtfTypeIndex,
    pub no_elems: u32,
}

#[derive(Debug)]
pub struct BtfStructMember {
    pub name_off: BtfStrOffset,
    pub r#type: BtfTypeIndex,
    pub offset: u32,
}

#[derive(Debug)]
pub struct BtfVariable {
    pub linkage: BtfVariableLinkage,
}

#[derive(Debug)]
pub struct BtfParam {
    pub name_off: BtfStrOffset,
    pub r#type: BtfTypeIndex,
}

#[derive(Debug)]
pub struct BtfVarSecinfo {
    pub r#type: BtfTypeIndex,
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug)]
pub enum BtfFuncLinkage {
    /// definition of subprogram not visible outside containing compilation unit
    Static = 0x0,
    /// definition of subprogram visible outside containing compilation unit
    Global = 0x1,
    /// declaration of a subprogram whose definition is outside the containing
    /// compilation unit
    Extern = 0x2,
}

#[derive(Debug)]
pub enum BtfVariableLinkage {
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
