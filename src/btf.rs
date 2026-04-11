use std::{borrow::Cow, collections::BTreeMap, ffi::CStr};

mod builder;
pub use builder::BtfBuilder;

pub mod ext;
pub use ext::*;

pub mod value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct BtfTypeId(pub u32);

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum BtfValidationError {
    #[error("BTF type {from:?} references non-existent type {to:?}")]
    DanglingTypeRef { from: BtfTypeId, to: BtfTypeId },

    #[error("BTF type {from:?} contains member of unsized type {member:?}")]
    UnsizedMember { from: BtfTypeId, member: BtfTypeId },
}

/// Borrowed view of a single BTF type alongside its containing BTF.
#[derive(Clone, Copy)]
pub struct BtfRef<'a> {
    btf: &'a Btf,
    ty: &'a BtfType,
}

impl<'a> BtfRef<'a> {
    pub fn id(&self) -> BtfTypeId {
        self.ty.btf_id
    }

    pub fn ty(&self) -> &'a BtfType {
        self.ty
    }

    pub fn kind(&self) -> &'a BtfKind {
        &self.ty.kind
    }

    pub fn name(&self) -> Option<Cow<'a, str>> {
        self.btf.string(self.ty.name_off)
    }

    pub fn size(&self) -> u32 {
        self.ty.kind.size(self.btf)
    }

    pub fn is_sized(&self) -> bool {
        self.ty.kind.is_sized()
    }

    pub fn btf(&self) -> &'a Btf {
        self.btf
    }

    pub fn resolve(&self, id: BtfTypeId) -> Option<BtfRef<'a>> {
        self.btf.resolve(id)
    }
}

impl std::fmt::Debug for BtfRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtfRef")
            .field("id", &self.ty.btf_id)
            .field("kind", &self.ty.kind)
            .finish()
    }
}

type BtfStrOffset = u32;

#[derive(Clone, Debug, Default)]
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

impl Btf {
    pub fn string(&self, offset: u32) -> Option<Cow<'_, str>> {
        CStr::from_bytes_until_nul(self.strings.get(offset as usize..)?)
            .ok()
            .map(CStr::to_string_lossy)
    }

    pub fn find_string(&self, name: &str) -> Option<u32> {
        if self.strings.len() < name.len() {
            return None;
        } else if name.is_empty() {
            return Some(0);
        }

        let mut f = self.strings.iter().enumerate();
        loop {
            let (idx, _) = f.by_ref().find(|(_, b)| **b != 0)?;

            let bytes = self.strings.get(idx..)?;
            let s = CStr::from_bytes_until_nul(bytes).ok()?.to_str().ok()?;

            if s.starts_with(name) {
                return Some(idx as u32);
            }
        }
    }

    pub fn get_type(&self, idx: BtfTypeId) -> Option<&BtfType> {
        self.resolve_indirections(self.types.get(&idx)?)
    }

    /// Byte size of the type at `idx`. Returns 0 if the id doesn't resolve or
    /// resolves to an unsized kind.
    pub fn type_size(&self, idx: BtfTypeId) -> u32 {
        self.get_type(idx).map_or(0, |t| t.kind.size(self))
    }

    /// Resolves a type id into a borrowed view that carries the BTF context
    /// alongside the type, so subsequent traversals don't need to re-pass
    /// `&Btf`.
    pub fn resolve(&self, id: BtfTypeId) -> Option<BtfRef<'_>> {
        Some(BtfRef {
            btf: self,
            ty: self.get_type(id)?,
        })
    }

    /// Resolves an id that is known to exist in the BTF, typically because it
    /// was either previously extracted from another resolved type, or because
    /// `validate()` has confirmed the BTF graph has no dangling references.
    ///
    /// # Panics
    ///
    /// Callers must establish the id's validity beforehand. Otherwise this
    /// panics.
    #[expect(clippy::expect_used, reason = "caller is expected to pass a valid id")]
    pub fn resolve_must(&self, id: BtfTypeId) -> BtfRef<'_> {
        self.resolve(id)
            .expect("BTF type id was expected to resolve but did not")
    }

    /// Walks every type in this BTF to guarantee:
    ///
    /// 1. that every `BtfTypeId` reference (member types, pointer targets,
    ///    function proto params, etc.) resolves to an existing type.
    /// 2. Every position that needs a byte size (array elements and
    ///    struct/union members) resolves to a sized type.
    pub fn validate(&self) -> Result<(), BtfValidationError> {
        for ty in self.types.values() {
            for child in ty.kind.referenced_ids() {
                if !self.types.contains_key(&child) {
                    return Err(BtfValidationError::DanglingTypeRef {
                        from: ty.btf_id,
                        to: child,
                    });
                }
            }

            let must_be_sized: Box<dyn Iterator<Item = BtfTypeId>> = match &ty.kind {
                BtfKind::Array(a) => Box::new(std::iter::once(a.r#type)),
                BtfKind::Struct(Struct { members, .. }) | BtfKind::Union(Union { members, .. }) => {
                    Box::new(members.iter().map(|m| m.r#type))
                }
                _ => Box::new(std::iter::empty()),
            };

            for id in must_be_sized {
                let resolved = self
                    .resolve(id)
                    .ok_or(BtfValidationError::DanglingTypeRef {
                        from: ty.btf_id,
                        to: id,
                    })?;
                if !resolved.is_sized() {
                    return Err(BtfValidationError::UnsizedMember {
                        from: ty.btf_id,
                        member: id,
                    });
                }
            }
        }
        Ok(())
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

    /// Finds the BTF type that starts exactly at `offset` within type `idx`,
    /// walking into structs, unions, and arrays as needed.
    ///
    /// Take `struct point { u32 x; u32 y; }` arranged as `struct point arr[4]`.
    /// Querying `arr` at offset 12 descends into the array (`12 % 8 = 4`, so
    /// element 1), then into the struct (offset 4 hits `y`), then into the
    /// `u32`, which only matches because we're now at offset 0 of the scalar.
    /// The returned type is `u32`. Asking for offset 2 instead would bail at
    /// the scalar step: `u32` accepts only offset 0, so we'd get `None`.
    ///
    /// Returns `None` when `offset` lands mid-member, in padding, or past the
    /// end.
    pub fn get_type_at_offset(&self, idx: BtfTypeId, offset: u32) -> Option<&BtfType> {
        let ty_size = self.type_size(idx);
        if offset >= ty_size {
            return None;
        }

        let btf_type = self.get_type(idx)?;
        match &btf_type.kind {
            BtfKind::Int(_)
            | BtfKind::Float(_)
            | BtfKind::Enum(_)
            | BtfKind::Enum64(_)
            | BtfKind::Ptr(_) => (offset == 0).then_some(btf_type),
            BtfKind::Array(array) => {
                let elem_size = self.type_size(array.r#type);
                self.get_type_at_offset(array.r#type, offset % elem_size)
            }
            BtfKind::Struct(Struct { members, .. }) | BtfKind::Union(Union { members, .. }) => {
                members.iter().find_map(|member| {
                    let start = member.offset / u8::BITS;
                    let off = offset.checked_sub(start)?;
                    let msz = self.type_size(member.r#type);
                    (off < msz)
                        .then(|| self.get_type_at_offset(member.r#type, off))
                        .flatten()
                })
            }
            BtfKind::Datasec(datasec) if datasec.opaque => Some(btf_type),
            BtfKind::Datasec(datasec) => datasec.secinfos.iter().find_map(|info| {
                let entry_offset = offset.checked_sub(info.offset)?;
                if entry_offset >= info.size {
                    return None;
                }
                let var_type = self.resolve_must(info.r#type).ty();
                let underlying = match &var_type.kind {
                    BtfKind::Var(var) => var.ty,
                    _ => info.r#type,
                };
                self.get_type_at_offset(underlying, entry_offset)
            }),
            _ => None,
        }
    }

    /// Whether `offset..offset + len` is a valid byte range within the type at
    /// `idx`. This differs from [`Self::get_type_at_offset`] in that the former
    /// asks "what single type starts exactly here?" while `is_offset_valid`
    /// asks "can a load or store of `len` bytes start here without crossing
    /// padding or partially overlapping a field?".
    ///
    /// The range may cover multiple aligned fields or array elements in a row,
    /// which is what lets the verifier accept coalesced writes, but never
    /// partial primitives or padding bytes. Continuing the `struct point
    /// arr[4]` example: an 8-byte access at offset 0 is valid (it covers
    /// `arr[0]`'s `x` and `y` in one go), a 4-byte access at offset 0 is valid
    /// (just `x`), but a 4-byte access at offset 2 is rejected because it'd
    /// partially access `x` (upper 2 bytes) and `y` (lower 2 bytes).
    pub fn is_access_valid(&self, idx: BtfTypeId, offset: u32, len: u32) -> bool {
        let ty_size = self.type_size(idx);
        if offset + len > ty_size {
            return false;
        }

        let Some(btf_type) = self.get_type(idx) else {
            return false;
        };

        match &btf_type.kind {
            BtfKind::Int(_)
            | BtfKind::Float(_)
            | BtfKind::Enum(_)
            | BtfKind::Enum64(_)
            | BtfKind::Ptr(_) => offset == 0 && len == ty_size,
            BtfKind::Volatile(idx) | BtfKind::Const(idx) | BtfKind::Restrict(idx) => {
                self.is_access_valid(*idx, offset, len)
            }
            BtfKind::Array(array) => {
                let elem_size = self.type_size(array.r#type);
                let mut remaining = len;
                let mut cur_in_elem = offset % elem_size;

                while remaining > 0 {
                    let avail = elem_size - cur_in_elem;
                    let chunk = remaining.min(avail);

                    if !self.is_access_valid(array.r#type, cur_in_elem, chunk) {
                        return false;
                    }

                    remaining -= chunk;
                    cur_in_elem = 0;
                }

                true
            }
            BtfKind::Struct(Struct { members, .. }) | BtfKind::Union(Union { members, .. }) => {
                let mut remaining = len;
                let mut cur = offset;

                while remaining > 0 {
                    let Some((member, off_in_member)) = members.iter().find_map(|m| {
                        let start = m.offset / u8::BITS;
                        let off = cur.checked_sub(start)?;
                        let msz = self.type_size(m.r#type);
                        (off < msz).then_some((m, off))
                    }) else {
                        return false;
                    };

                    let msz = self.type_size(member.r#type);
                    let avail = msz - off_in_member;
                    let chunk = remaining.min(avail);

                    if !self.is_access_valid(member.r#type, off_in_member, chunk) {
                        return false;
                    }

                    cur += chunk;
                    remaining -= chunk;
                }

                true
            }
            BtfKind::Datasec(datasec) if datasec.opaque => true,
            BtfKind::Datasec(datasec) => datasec
                .secinfos
                .iter()
                .find_map(|info| {
                    let entry_offset = offset.checked_sub(info.offset)?;
                    if entry_offset + len > info.size {
                        return None;
                    }
                    let var_type = self.resolve_must(info.r#type).ty();
                    let underlying = match &var_type.kind {
                        BtfKind::Var(var) => var.ty,
                        _ => info.r#type,
                    };
                    Some(self.is_access_valid(underlying, entry_offset, len))
                })
                .unwrap_or(false),
            _ => false,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct BtfType {
    pub btf_id: BtfTypeId,
    pub name_off: BtfStrOffset,
    pub kind: BtfKind,
}

#[derive(Clone, Debug, serde::Serialize, strum::EnumDiscriminants, strum::AsRefStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
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
    /// Returns every `BtfTypeId` this kind directly references in the BTF
    /// type graph.
    ///
    /// The void id `0` is filtered out.
    fn referenced_ids(&self) -> Vec<BtfTypeId> {
        let mut out = Vec::new();
        match self {
            BtfKind::Int(_)
            | BtfKind::Float(_)
            | BtfKind::Enum(_)
            | BtfKind::Enum64(_)
            | BtfKind::Fwd(_)
            | BtfKind::DeclTag => {}
            BtfKind::Ptr(id)
            | BtfKind::Typedef(id)
            | BtfKind::Volatile(id)
            | BtfKind::Const(id)
            | BtfKind::Restrict(id)
            | BtfKind::TypeTag(id) => out.push(*id),
            BtfKind::Array(a) => {
                out.push(a.r#type);
                out.push(a.index_type);
            }
            BtfKind::Struct(Struct { members, .. }) | BtfKind::Union(Union { members, .. }) => {
                out.extend(members.iter().map(|m| m.r#type));
            }
            BtfKind::Var(v) => out.push(v.ty),
            BtfKind::Func(f) => out.push(f.func_proto),
            BtfKind::FuncProto(p) => {
                out.extend(p.params.iter().map(|param| param.r#type));
                out.push(p.return_type);
            }
            BtfKind::Datasec(d) => {
                out.extend(d.secinfos.iter().map(|s| s.r#type));
            }
        }
        out.retain(|id| id.0 != 0);
        out
    }

    pub fn size(&self, btf: &Btf) -> u32 {
        match self {
            BtfKind::Int(Int { size, .. })
            | BtfKind::Struct(Struct { size, .. })
            | BtfKind::Union(Union { size, .. })
            | BtfKind::Enum(Enum { size, .. })
            | BtfKind::Enum64(Enum64 { size, .. })
            | BtfKind::Float(Float { size })
            | BtfKind::Datasec(Datasec { size, .. }) => *size,

            BtfKind::Array(btf_array) => {
                btf.resolve_must(btf_array.r#type).size() * btf_array.no_elems
            }

            BtfKind::Ptr(_) => 8,

            BtfKind::Typedef(ty)
            | BtfKind::Volatile(ty)
            | BtfKind::Const(ty)
            | BtfKind::Restrict(ty)
            | BtfKind::Var(Var { ty, .. })
            | BtfKind::TypeTag(ty) => btf.resolve_must(*ty).size(),

            BtfKind::Fwd(_) | BtfKind::Func(_) | BtfKind::FuncProto(_) | BtfKind::DeclTag => 0,
        }
    }

    pub fn is_sized(&self) -> bool {
        !matches!(
            self,
            BtfKind::Fwd(_) | BtfKind::Func(_) | BtfKind::FuncProto(_) | BtfKind::DeclTag
        )
    }

    pub fn array_no_elems(&self) -> Option<u32> {
        match self {
            BtfKind::Array(arr) => Some(arr.no_elems),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
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

#[derive(Clone, Debug, serde::Serialize)]
pub struct Union {
    pub members: Vec<StructMember>,
    /// size of the struct in bytes
    pub size: u32,
}

/// Forward
#[derive(Clone, Debug, serde::Serialize)]
pub struct Fwd {
    pub kind_flag: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Func {
    pub linkage: FuncLinkage,
    pub func_proto: BtfTypeId,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct FuncProto {
    pub params: Vec<Param>,
    pub return_type: BtfTypeId,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Var {
    pub ty: BtfTypeId,
    pub variable: Variable,
}

/// Section
#[derive(Clone, Debug, serde::Serialize)]
pub struct Datasec {
    pub secinfos: Vec<VarSecInfo>,
    pub size: u32,
    /// Set by the loader for synthesized data sections (.rodata, etc.)
    /// where any byte-aligned access within bounds is valid. Cannot
    /// be set through parsed BTF headers.
    pub opaque: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Float {
    pub size: u32,
}

/// Enumeration up to 32-bit values
#[derive(Clone, Debug, serde::Serialize)]
pub struct Enum {
    pub signed: bool,
    pub size: u32,
    pub values: Vec<EnumValue>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct EnumValue {
    pub name_off: BtfStrOffset,
    pub val: i32,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Array {
    pub r#type: BtfTypeId,
    pub index_type: BtfTypeId,
    pub no_elems: u32,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Struct {
    pub members: Vec<StructMember>,
    /// size of the struct in bytes
    pub size: u32,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct StructMember {
    pub name_off: BtfStrOffset,
    pub r#type: BtfTypeId,
    pub bitfield_size: Option<u32>,
    // Member bit offset from struct beginning
    pub offset: u32,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Variable {
    pub linkage: VariableLinkage,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Param {
    pub name_off: BtfStrOffset,
    pub r#type: BtfTypeId,
}

#[derive(Copy, Clone, Debug, serde::Serialize)]
pub struct VarSecInfo {
    pub r#type: BtfTypeId,
    pub offset: u32,
    pub size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum FuncLinkage {
    /// definition of subprogram not visible outside containing compilation unit
    Static = 0x0,
    /// definition of subprogram visible outside containing compilation unit
    Global = 0x1,
    /// declaration of a subprogram whose definition is outside the containing
    /// compilation unit
    Extern = 0x2,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
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

#[derive(Clone, Debug, serde::Serialize)]
/// Enumeration up to 64-bit values
pub struct Enum64 {
    pub signed: bool,
    pub size: u32,
    pub values: Vec<Enum64Value>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Enum64Value {
    pub name_off: u32,
    pub val_lo32: u32,
    pub val_hi32: u32,
}

mod parser {
    use std::io::{Error, ErrorKind, Result};

    use crate::btf::{Datasec, Enum, Enum64, Float, Func, FuncProto, Fwd, Int, Struct, Union, Var};

    use super::*;
    use byteorder::{LittleEndian, ReadBytesExt};

    pub const BTF_MAGIC: [u8; 2] = [0x9F, 0xEB];

    fn invalid<T: Into<String>>(msg: T) -> Error {
        Error::new(ErrorKind::InvalidData, msg.into())
    }

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
        /// Beginning of the string section relative to the end of the BTF
        /// header.
        str_off: u32,
        /// Length of string section in bytes.
        str_len: u32,
    }

    impl Btf {
        pub fn from_bytes(data: &[u8]) -> Result<Self> {
            let magic = data
                .get(..2)
                .ok_or_else(|| invalid("BTF section is shorter than 2 bytes"))?;
            if magic != BTF_MAGIC {
                return Err(invalid("BTF magic bytes do not match"));
            }

            let header_data = &mut data
                .get(2..)
                .ok_or_else(|| invalid("BTF section truncated after magic"))?;
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
            let str_end = str_off + header.str_len as usize;
            let strings = data
                .get(str_off..str_end)
                .ok_or_else(|| invalid("BTF string section out of bounds"))?
                .to_vec();

            let type_off = (header.hdr_len + header.type_off) as usize;
            let type_end = type_off + header.type_len as usize;
            let type_data = &mut data
                .get(type_off..type_end)
                .ok_or_else(|| invalid("BTF type section out of bounds"))?;
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
                        other => return Err(invalid(format!("invalid Func linkage {other}"))),
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
                            other => {
                                return Err(invalid(format!("invalid Var linkage {other}")));
                            }
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
                        opaque: false,
                    })
                }
                BTF_KIND_FLOAT => Self::Float(Float { size: size_or_type }),
                BTF_KIND_DECL_TAG => {
                    return Err(invalid("BTF DeclTag parsing is not implemented"));
                }
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
                other => return Err(invalid(format!("unknown BTF kind {other}"))),
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

        assert_eq!(btf.string(1).unwrap(), "struct");
        assert_eq!(btf.string(8).unwrap(), "func_name");
        assert_eq!(btf.string(19).unwrap(), "u32");

        assert_eq!(btf.find_string("struct").unwrap(), 1);
        assert_eq!(btf.find_string("func_name").unwrap(), 8);
        assert_eq!(btf.find_string("u32").unwrap(), 19);
    }

    // Builds a BTF matching struct snake { u32 dir; u8 len; u8 head; u16 body[64];
    // } Total size = 4 + 1 + 1 + 128 = 134. No padding between members.
    fn make_snake_btf() -> (Btf, BtfTypeId) {
        let mut b = BtfBuilder::default();
        let u8_ty = b.add_int("u8", 1, 0);
        let u16_ty = b.add_int("u16", 2, 0);
        let u32_ty = b.add_int("u32", 4, 0);
        let u32_idx = b.add_int("__u32", 4, 0);
        let body_ty = b.add_array("", u16_ty, u32_idx, 64);
        let snake = b.make_struct("snake", 134, |s| {
            s.field("dir", u32_ty, 0); // byte 0
            s.field("len", u8_ty, 32); // byte 4
            s.field("head", u8_ty, 40); // byte 5
            s.field("body", body_ty, 48); // byte 6
        });
        (b.build(), snake)
    }

    #[test]
    fn single_field_access() {
        let (btf, snake) = make_snake_btf();
        assert!(btf.is_access_valid(snake, 0, 4)); // dir
        assert!(btf.is_access_valid(snake, 4, 1)); // len
        assert!(btf.is_access_valid(snake, 5, 1)); // head
        assert!(btf.is_access_valid(snake, 6, 2)); // body[0]
        assert!(btf.is_access_valid(snake, 8, 2)); // body[1]
    }

    #[test]
    fn coalesced_write_across_members() {
        let (btf, snake) = make_snake_btf();
        // len (1) + head (1) + body[0] (2) = 4 bytes at offset 4
        assert!(btf.is_access_valid(snake, 4, 4));
    }

    #[test]
    fn coalesced_write_across_array_elements() {
        let (btf, snake) = make_snake_btf();
        // body[0] (2) + body[1] (2) = 4 bytes at offset 6
        assert!(btf.is_access_valid(snake, 6, 4));
    }

    #[test]
    fn partial_primitive_rejected() {
        let (btf, snake) = make_snake_btf();
        // 2 bytes of a u32 (dir) is not a full-width access
        assert!(!btf.is_access_valid(snake, 0, 2));
    }

    #[test]
    fn write_across_padding_rejected() {
        // struct padded { u8 a; /* 1 byte pad */; u16 b; }
        let mut b = BtfBuilder::default();
        let u8_ty = b.add_int("u8", 1, 0);
        let u16_ty = b.add_int("u16", 2, 0);
        let padded = b.make_struct("padded", 4, |s| {
            s.field("a", u8_ty, 0); // byte 0
            s.field("b", u16_ty, 16); // byte 2, byte 1 is pad
        });
        let btf = b.build();

        // Writing 4 bytes at offset 0 hits padding at byte 1
        assert!(!btf.is_access_valid(padded, 0, 4));
        // Single-field accesses still work
        assert!(btf.is_access_valid(padded, 0, 1));
        assert!(btf.is_access_valid(padded, 2, 2));
    }

    #[test]
    fn mid_member_write_rejected() {
        let (btf, snake) = make_snake_btf();
        // Starting at byte 1 (mid-dir) makes no member start exactly there
        assert!(!btf.is_access_valid(snake, 1, 1));
    }

    #[test]
    fn write_past_struct_rejected() {
        let (btf, snake) = make_snake_btf();
        assert!(!btf.is_access_valid(snake, 133, 2));
    }
}
