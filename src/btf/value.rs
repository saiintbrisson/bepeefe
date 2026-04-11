use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{btf::BtfTypeId, vm::ptr::TaggedPtr};

use super::{BtfKind, BtfKindDiscriminants, BtfRef};

pub use deser::{from_value, to_value};

#[derive(Debug, thiserror::Error)]
pub enum ValueError {
    #[error("unknown btf type {0:?}")]
    UnknownBtfType(BtfTypeId),
    #[error("expected btf kind in {expected:?}, got {got:?}")]
    IncompatibleTypes {
        expected: &'static [BtfKindDiscriminants],
        got: BtfKindDiscriminants,
    },
    #[error("btf type {0:?} has no size")]
    UnsizedType(BtfTypeId),
    #[error("number {0} is larger than allowed ({1} bits)")]
    NumberOverflow(i64, u8),
    #[error("can't encode float with {0} bytes")]
    UnsupportedFloatSize(u32),
    #[error("enum {0:?} has no variant {1}")]
    UnknownEnumVariant(BtfTypeId, i64),
    #[error("array is larger than allowed: {0} > {1}")]
    ArrayOutOfBounds(usize, usize),
    #[error("struct {container:?} has a member with unresolvable name at offset {name_off}")]
    MissingMemberName { container: BtfTypeId, name_off: u32 },
    #[error("field {0:?} does not exist in target struct")]
    UnknownField(String),
    #[error("from_bytes is not implemented for btf kind {0:?} ({1:?})")]
    UnsupportedKind(BtfKindDiscriminants, BtfTypeId),
    /// Returned when a byte buffer handed to `from_bytes` is shorter than the
    /// BTF type it describes, typically a sign that the caller read fewer bytes
    /// from a map than the value schema needs.
    #[error("insufficient bytes for type {ty:?}: need {expected}, got {got}")]
    InsufficientBytes {
        ty: BtfTypeId,
        expected: usize,
        got: usize,
    },
    /// Returned when a scalar BTF type (`Int`, `Enum`, `Enum64`) declares a
    /// width that doesn't fit in an `i64`, `__int128` and friends. We don't
    /// currently support widths beyond 8 bytes.
    #[error("scalar btf type {ty:?} declares unsupported width {size}")]
    OversizedScalar { ty: BtfTypeId, size: u32 },
    /// [`Value::TaggedPtr`] only supports local, kernel, and user region
    /// pointers.
    #[error("map-tagged pointers are not supported")]
    UnsupportedMapPtr,
    #[error("{0}")]
    Serde(String),
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum Value {
    #[default]
    Zeroed,
    /// A BTF type represented as a number. Can be `Int`, `Enum`, `Enum64` and
    /// `Ptr` (though prefer [`Value::TaggetPtr`]).
    ///
    /// Supports up to 8-byte integers. Use an array for larger numbers.
    Number(i64),
    Float(f64),
    /// A region-tagged pointer. Allowed regions are `Local`, `Kernel` and
    /// `User`.
    TaggedPtr(TaggedPtr),
    /// Encodes a fixed-size array of elements. Array cannot be larger than the
    /// number of elements declared in its BTF type.
    ///
    /// It's also compatible with number based types: `Int`, `Enum`, `Enum64`,
    /// and `Ptr`.
    Array(Vec<Value>),
    /// A BTF struct or union.
    ///
    /// Map is keyed by field name. If a field is anon, use `_anon_<idx>` where
    /// `idx` is the field index in the BTF type.
    ///
    /// # Example
    ///
    /// Given a BTF type with the following structure:
    ///
    /// ```c
    /// union (anon) {
    ///     __addrpair skc_addrpair;
    ///     struct (anon) {
    ///         __be32 skc_daddr;
    ///         __be32 skc_rcv_saddr;
    ///     };
    /// };
    /// ```
    ///
    /// To match on the anon struct, declare a map with `_anon_1`:
    ///
    /// ```json
    /// {
    ///   "_anon_1": { "skc_daddr": 0, "skc_rcv_saddr": 0 }
    /// }
    /// ```
    Map(BTreeMap<String, Value>),
}

impl<const N: usize> From<[(&str, Value); N]> for Value {
    fn from(value: [(&str, Value); N]) -> Self {
        Self::Map(value.map(|(key, val)| (key.to_owned(), val)).into())
    }
}

impl Value {
    pub fn to_bytes(&self, ty: BtfRef<'_>) -> Result<Vec<u8>, ValueError> {
        if !ty.is_sized() {
            return Err(ValueError::UnsizedType(ty.id()));
        }
        match self {
            Value::Zeroed => Ok(vec![0; ty.size() as usize]),
            Value::Number(n) => to::number(*n, ty),
            Value::Float(f) => to::float(*f, ty),
            Value::Array(elems) => to::array(elems, ty),
            Value::Map(map) => to::map(map, ty),
            Value::TaggedPtr(tp) => to::tagged_ptr(*tp, ty),
        }
    }

    pub fn from_bytes(ty: BtfRef<'_>, bytes: &[u8]) -> Result<Value, ValueError> {
        match ty.kind() {
            BtfKind::Int(int) => from::scalar(int.size, ty, bytes).map(Value::Number),
            BtfKind::Enum(e) => from::scalar(e.size, ty, bytes).map(Value::Number),
            BtfKind::Enum64(e) => from::scalar(e.size, ty, bytes).map(Value::Number),
            BtfKind::Float(float) => from::float(float.size, ty, bytes),
            BtfKind::Array(arr) => from::array(arr, ty, bytes),
            BtfKind::Struct(s) => from::strct(s, ty, bytes),
            _ => Err(ValueError::UnsupportedKind(ty.kind().into(), ty.id())),
        }
    }
}

mod to {
    use std::collections::BTreeMap;

    use crate::btf::{BtfKind, BtfKindDiscriminants, BtfRef};

    use super::*;

    pub(super) fn number(num: i64, ty: BtfRef<'_>) -> Result<Vec<u8>, ValueError> {
        let ne = num.to_ne_bytes();
        let scalar = |size: u32| -> Result<Vec<u8>, ValueError> {
            ne.get(..size as usize)
                .map(<[u8]>::to_vec)
                .ok_or(ValueError::OversizedScalar { ty: ty.id(), size })
        };
        match ty.kind() {
            BtfKind::Int(int) => {
                if num.unbounded_shr(int.bits as _) > 0 {
                    return Err(ValueError::NumberOverflow(num, int.bits));
                }
                scalar(int.size)
            }
            BtfKind::Ptr(_) => scalar(8),
            BtfKind::Enum(e) => {
                e.values
                    .iter()
                    .find(|v| v.val == num as i32)
                    .ok_or(ValueError::UnknownEnumVariant(ty.id(), num))?;
                scalar(e.size)
            }
            BtfKind::Enum64(e) => {
                e.values
                    .iter()
                    .find(|v| ((v.val_hi32 as i64) << 32 | v.val_lo32 as i64) == num)
                    .ok_or(ValueError::UnknownEnumVariant(ty.id(), num))?;
                scalar(e.size)
            }
            _ => Err(ValueError::IncompatibleTypes {
                expected: &[
                    BtfKindDiscriminants::Int,
                    BtfKindDiscriminants::Ptr,
                    BtfKindDiscriminants::Enum,
                    BtfKindDiscriminants::Enum64,
                ],
                got: ty.kind().into(),
            }),
        }
    }

    pub(super) fn float(f: f64, ty: BtfRef<'_>) -> Result<Vec<u8>, ValueError> {
        let BtfKind::Float(float) = ty.kind() else {
            return Err(ValueError::IncompatibleTypes {
                expected: &[BtfKindDiscriminants::Float],
                got: ty.kind().into(),
            });
        };
        match float.size {
            4 => Ok((f as f32).to_ne_bytes().to_vec()),
            8 => Ok(f.to_ne_bytes().to_vec()),
            _ => Err(ValueError::UnsupportedFloatSize(float.size)),
        }
    }

    pub(super) fn array(elems: &[Value], ty: BtfRef<'_>) -> Result<Vec<u8>, ValueError> {
        match ty.kind() {
            BtfKind::Array(arr) => {
                if elems.len() > arr.no_elems as usize {
                    return Err(ValueError::ArrayOutOfBounds(
                        elems.len(),
                        arr.no_elems as usize,
                    ));
                }
                let elem_ty = ty.btf().resolve_must(arr.r#type);
                let elem_size = elem_ty.size() as usize;
                let mut buf = Vec::with_capacity(arr.no_elems as usize * elem_size);
                for elem in elems {
                    buf.extend(elem.to_bytes(elem_ty)?);
                }
                buf.resize(arr.no_elems as usize * elem_size, 0);
                Ok(buf)
            }
            BtfKind::Int(_) | BtfKind::Enum(_) | BtfKind::Enum64(_) | BtfKind::Ptr(_) => {
                let size = ty.size() as usize;
                if elems.len() > size {
                    return Err(ValueError::ArrayOutOfBounds(elems.len(), size));
                }

                let mut padded = [0u8; 8];
                for (elem, padded) in elems.iter().zip(&mut padded) {
                    let Value::Number(n) = elem else {
                        return Err(ValueError::Serde(
                            "byte array for scalar must contain Number elements".into(),
                        ));
                    };
                    if !(0..=u8::MAX as i64).contains(n) {
                        return Err(ValueError::NumberOverflow(*n, 8));
                    }
                    *padded = *n as u8;
                }

                number(i64::from_ne_bytes(padded), ty)
            }
            _ => Err(ValueError::IncompatibleTypes {
                expected: &[
                    BtfKindDiscriminants::Array,
                    BtfKindDiscriminants::Int,
                    BtfKindDiscriminants::Enum,
                    BtfKindDiscriminants::Enum64,
                    BtfKindDiscriminants::Ptr,
                ],
                got: ty.kind().into(),
            }),
        }
    }

    pub(super) fn map(
        map: &BTreeMap<String, Value>,
        ty: BtfRef<'_>,
    ) -> Result<Vec<u8>, ValueError> {
        match ty.kind() {
            BtfKind::Struct(_) => strct(map, ty),
            BtfKind::Union(_) => union(map, ty),
            _ => Err(ValueError::IncompatibleTypes {
                expected: &[BtfKindDiscriminants::Struct, BtfKindDiscriminants::Union],
                got: ty.kind().into(),
            }),
        }
    }

    /// For anon types in the struct, we use a placeholder name `_anon_<idx>`
    /// where `idx` is the index in the struct declaration.
    fn strct(map: &BTreeMap<String, Value>, ty: BtfRef<'_>) -> Result<Vec<u8>, ValueError> {
        let BtfKind::Struct(s) = ty.kind() else {
            return Err(ValueError::IncompatibleTypes {
                expected: &[BtfKindDiscriminants::Union],
                got: ty.kind().into(),
            });
        };
        let mut used: Vec<String> = Vec::with_capacity(map.len());
        let mut buf = Vec::with_capacity(ty.size() as usize);
        for (idx, member) in s.members.iter().enumerate() {
            let member_ty = ty.btf().resolve_must(member.r#type);
            let name = ty
                .btf()
                .string(member.name_off)
                .ok_or(ValueError::MissingMemberName {
                    container: ty.id(),
                    name_off: member.name_off,
                })?;
            let member_size = member_ty.size() as usize;
            let byte_offset = (member.offset / 8) as usize;
            buf.resize(byte_offset, 0);

            let key: String = if name.is_empty() {
                format!("_anon_{idx}")
            } else {
                name.into_owned()
            };
            let Some(member_val) = map.get(&key) else {
                buf.resize(buf.len() + member_size, 0);
                continue;
            };

            buf.extend(member_val.to_bytes(member_ty)?);
            used.push(key);
        }

        for field in map.keys() {
            if !used.contains(field) {
                return Err(ValueError::UnknownField(field.clone()));
            }
        }

        Ok(buf)
    }

    /// A union map (should) carry exactly one entry, the active variant. We
    /// select the first map entry that matches the _name_ in the BTF union
    /// declaration.
    ///
    /// For anon types in the union, we use a placeholder name `_anon_<idx>`
    /// where `idx` is the index in the union declaration.
    fn union(map: &BTreeMap<String, Value>, ty: BtfRef<'_>) -> Result<Vec<u8>, ValueError> {
        let BtfKind::Union(u) = ty.kind() else {
            return Err(ValueError::IncompatibleTypes {
                expected: &[BtfKindDiscriminants::Union],
                got: ty.kind().into(),
            });
        };

        let size = ty.size() as usize;
        let Some((key, val)) = map.first_key_value() else {
            return Ok(vec![0; size]);
        };

        let Some((_, member)) = u.members.iter().enumerate().find(|(idx, m)| {
            let nm = ty
                .btf()
                .string(m.name_off)
                .map(|s| s.into_owned())
                .unwrap_or_default();
            if nm.is_empty() {
                key.as_str() == format!("_anon_{idx}")
            } else {
                key.as_str() == nm.as_str()
            }
        }) else {
            return Err(ValueError::UnknownField(key.clone()));
        };

        let member_ty = ty.btf().resolve_must(member.r#type);
        let mut bytes = val.to_bytes(member_ty)?;

        bytes.resize(size, 0);

        Ok(bytes)
    }

    /// Tags the written pointer using [`TaggedPtr`]. Map-tagged
    /// pointers are not addressable as parameters and are rejected.
    pub(super) fn tagged_ptr(tp: TaggedPtr, ty: BtfRef<'_>) -> Result<Vec<u8>, ValueError> {
        if !matches!(ty.kind(), BtfKind::Ptr(_)) {
            return Err(ValueError::IncompatibleTypes {
                expected: &[BtfKindDiscriminants::Ptr],
                got: ty.kind().into(),
            });
        }
        if matches!(tp, TaggedPtr::Map { .. }) {
            return Err(ValueError::UnsupportedMapPtr);
        }
        Ok(tp.to_raw().to_ne_bytes().to_vec())
    }
}

mod from {
    use std::collections::BTreeMap;

    use crate::btf::{Array, BtfRef, Struct};

    use super::{Value, ValueError};

    fn need<'a>(ty: BtfRef<'_>, bytes: &'a [u8], expected: usize) -> Result<&'a [u8], ValueError> {
        bytes.get(..expected).ok_or(ValueError::InsufficientBytes {
            ty: ty.id(),
            expected,
            got: bytes.len(),
        })
    }

    pub(super) fn scalar(size: u32, ty: BtfRef<'_>, bytes: &[u8]) -> Result<i64, ValueError> {
        let n = size as usize;
        let mut buf = [0u8; 8];
        let Some(buf_mut) = buf.get_mut(..n) else {
            return Err(ValueError::OversizedScalar { ty: ty.id(), size });
        };

        let src = need(ty, bytes, n)?;
        buf_mut.copy_from_slice(src);
        Ok(i64::from_ne_bytes(buf))
    }

    pub(super) fn float(size: u32, ty: BtfRef<'_>, bytes: &[u8]) -> Result<Value, ValueError> {
        let f = match size {
            4 => {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(need(ty, bytes, 4)?);
                f32::from_ne_bytes(buf) as f64
            }
            8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(need(ty, bytes, 8)?);
                f64::from_ne_bytes(buf)
            }
            _ => return Err(ValueError::UnsupportedFloatSize(size)),
        };
        Ok(Value::Float(f))
    }

    pub(super) fn array(arr: &Array, ty: BtfRef<'_>, bytes: &[u8]) -> Result<Value, ValueError> {
        let elem_ty = ty.btf().resolve_must(arr.r#type);
        let elem_size = elem_ty.size() as usize;
        let mut elems = Vec::with_capacity(arr.no_elems as usize);
        for i in 0..arr.no_elems as usize {
            let offset = i * elem_size;
            let chunk =
                bytes
                    .get(offset..offset + elem_size)
                    .ok_or(ValueError::InsufficientBytes {
                        ty: ty.id(),
                        expected: offset + elem_size,
                        got: bytes.len(),
                    })?;
            elems.push(Value::from_bytes(elem_ty, chunk)?);
        }
        Ok(Value::Array(elems))
    }

    pub(super) fn strct(s: &Struct, ty: BtfRef<'_>, bytes: &[u8]) -> Result<Value, ValueError> {
        let mut map = BTreeMap::new();
        for member in &s.members {
            let member_ty = ty.btf().resolve_must(member.r#type);
            let name = ty
                .btf()
                .string(member.name_off)
                .ok_or(ValueError::MissingMemberName {
                    container: ty.id(),
                    name_off: member.name_off,
                })?;
            let byte_offset = (member.offset / 8) as usize;
            let member_size = member_ty.size() as usize;
            let chunk = bytes.get(byte_offset..byte_offset + member_size).ok_or(
                ValueError::InsufficientBytes {
                    ty: ty.id(),
                    expected: byte_offset + member_size,
                    got: bytes.len(),
                },
            )?;
            let val = Value::from_bytes(member_ty, chunk)?;
            map.insert(name.to_string(), val);
        }
        Ok(Value::Map(map))
    }
}

mod deser {
    use core::fmt;
    use std::collections::BTreeMap;

    use serde::{Deserialize, Serialize, de, ser};

    use crate::vm::ptr::{TAGGED_PTR_NAME, TaggedPtr, TaggetPtrType};

    use super::{Value, ValueError};

    pub fn to_value<T: Serialize + ?Sized>(value: &T) -> Result<Value, ValueError> {
        value.serialize(Serializer)
    }

    pub fn from_value<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, ValueError> {
        T::deserialize(value)
    }

    impl ser::Error for ValueError {
        fn custom<T: fmt::Display>(msg: T) -> Self {
            ValueError::Serde(msg.to_string())
        }
    }

    impl de::Error for ValueError {
        fn custom<T: fmt::Display>(msg: T) -> Self {
            ValueError::Serde(msg.to_string())
        }
    }

    struct Serializer;

    macro_rules! serialize_int {
        ($($method:ident($ty:ty),)*) => {
            $(
                fn $method(self, v: $ty) -> Result<Value, ValueError> {
                    Ok(Value::Number(v as i64))
                }
            )*
        };
    }

    impl ser::Serializer for Serializer {
        type Ok = Value;
        type Error = ValueError;

        type SerializeSeq = SerializeVec;
        type SerializeTuple = SerializeVec;
        type SerializeTupleStruct = SerializeVec;
        type SerializeTupleVariant = SerializeVec;
        type SerializeMap = SerializeStruct;
        type SerializeStruct = SerializeStruct;
        type SerializeStructVariant = SerializeStruct;

        serialize_int! {
            serialize_bool(bool),
            serialize_i8(i8),
            serialize_i16(i16),
            serialize_i32(i32),
            serialize_i64(i64),
            serialize_u8(u8),
            serialize_u16(u16),
            serialize_u32(u32),
            serialize_u64(u64),
            serialize_char(char),
        }

        fn serialize_f32(self, v: f32) -> Result<Value, ValueError> {
            Ok(Value::Float(v as f64))
        }

        fn serialize_f64(self, v: f64) -> Result<Value, ValueError> {
            Ok(Value::Float(v))
        }

        fn serialize_str(self, _v: &str) -> Result<Value, ValueError> {
            Err(ValueError::Serde("strings are not supported".into()))
        }

        fn serialize_bytes(self, _v: &[u8]) -> Result<Value, ValueError> {
            Err(ValueError::Serde("byte slices are not supported".into()))
        }

        fn serialize_none(self) -> Result<Value, ValueError> {
            Ok(Value::Zeroed)
        }

        fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Value, ValueError> {
            value.serialize(self)
        }

        fn serialize_unit(self) -> Result<Value, ValueError> {
            Ok(Value::Zeroed)
        }

        fn serialize_unit_struct(self, _name: &'static str) -> Result<Value, ValueError> {
            Ok(Value::Zeroed)
        }

        fn serialize_unit_variant(
            self,
            _name: &'static str,
            variant_index: u32,
            _variant: &'static str,
        ) -> Result<Value, ValueError> {
            Ok(Value::Number(variant_index as i64))
        }

        fn serialize_newtype_struct<T: ?Sized + Serialize>(
            self,
            _name: &'static str,
            value: &T,
        ) -> Result<Value, ValueError> {
            value.serialize(self)
        }

        fn serialize_newtype_variant<T: ?Sized + Serialize>(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
            value: &T,
        ) -> Result<Value, ValueError> {
            value.serialize(self)
        }

        fn serialize_seq(self, len: Option<usize>) -> Result<SerializeVec, ValueError> {
            Ok(SerializeVec(Vec::with_capacity(len.unwrap_or(0))))
        }

        fn serialize_tuple(self, len: usize) -> Result<SerializeVec, ValueError> {
            self.serialize_seq(Some(len))
        }

        fn serialize_tuple_struct(
            self,
            _name: &'static str,
            len: usize,
        ) -> Result<SerializeVec, ValueError> {
            self.serialize_seq(Some(len))
        }

        fn serialize_tuple_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
            len: usize,
        ) -> Result<SerializeVec, ValueError> {
            self.serialize_seq(Some(len))
        }

        fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, ValueError> {
            Ok(SerializeStruct::map())
        }

        fn serialize_struct(
            self,
            name: &'static str,
            _len: usize,
        ) -> Result<SerializeStruct, ValueError> {
            // Avoid collapsing into a Value::Map if struct described
            // a tagged ptr
            if name == TAGGED_PTR_NAME {
                Ok(SerializeStruct::TaggedPtr(BTreeMap::new()))
            } else {
                Ok(SerializeStruct::map())
            }
        }

        fn serialize_struct_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
            _len: usize,
        ) -> Result<SerializeStruct, ValueError> {
            Ok(SerializeStruct::map())
        }
    }

    struct KeySerializer;

    fn key_err<T>() -> Result<T, ValueError> {
        Err(ValueError::Serde("key must be a string".into()))
    }

    impl ser::Serializer for KeySerializer {
        type Ok = String;
        type Error = ValueError;
        type SerializeSeq = ser::Impossible<String, ValueError>;
        type SerializeTuple = ser::Impossible<String, ValueError>;
        type SerializeTupleStruct = ser::Impossible<String, ValueError>;
        type SerializeTupleVariant = ser::Impossible<String, ValueError>;
        type SerializeMap = ser::Impossible<String, ValueError>;
        type SerializeStruct = ser::Impossible<String, ValueError>;
        type SerializeStructVariant = ser::Impossible<String, ValueError>;

        fn serialize_str(self, v: &str) -> Result<String, ValueError> {
            Ok(v.to_owned())
        }

        fn serialize_bool(self, _: bool) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_i8(self, _: i8) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_i16(self, _: i16) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_i32(self, _: i32) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_i64(self, _: i64) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_u8(self, _: u8) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_u16(self, _: u16) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_u32(self, _: u32) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_u64(self, _: u64) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_f32(self, _: f32) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_f64(self, _: f64) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_char(self, _: char) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_bytes(self, _: &[u8]) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_none(self) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_unit(self) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_unit_struct(self, _: &'static str) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_unit_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
        ) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_newtype_struct<T: ?Sized + Serialize>(
            self,
            _: &'static str,
            _: &T,
        ) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_newtype_variant<T: ?Sized + Serialize>(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: &T,
        ) -> Result<String, ValueError> {
            key_err()
        }
        fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, ValueError> {
            key_err()
        }
        fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, ValueError> {
            key_err()
        }
        fn serialize_tuple_struct(
            self,
            _: &'static str,
            _: usize,
        ) -> Result<Self::SerializeTupleStruct, ValueError> {
            key_err()
        }
        fn serialize_tuple_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self::SerializeTupleVariant, ValueError> {
            key_err()
        }
        fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, ValueError> {
            key_err()
        }
        fn serialize_struct(
            self,
            _: &'static str,
            _: usize,
        ) -> Result<Self::SerializeStruct, ValueError> {
            key_err()
        }
        fn serialize_struct_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self::SerializeStructVariant, ValueError> {
            key_err()
        }
    }

    struct SerializeVec(Vec<Value>);

    impl ser::SerializeSeq for SerializeVec {
        type Ok = Value;
        type Error = ValueError;

        fn serialize_element<T: ?Sized + Serialize>(
            &mut self,
            value: &T,
        ) -> Result<(), ValueError> {
            self.0.push(to_value(value)?);
            Ok(())
        }

        fn end(self) -> Result<Value, ValueError> {
            Ok(Value::Array(self.0))
        }
    }

    impl ser::SerializeTuple for SerializeVec {
        type Ok = Value;
        type Error = ValueError;

        fn serialize_element<T: ?Sized + Serialize>(
            &mut self,
            value: &T,
        ) -> Result<(), ValueError> {
            ser::SerializeSeq::serialize_element(self, value)
        }

        fn end(self) -> Result<Value, ValueError> {
            ser::SerializeSeq::end(self)
        }
    }

    impl ser::SerializeTupleStruct for SerializeVec {
        type Ok = Value;
        type Error = ValueError;

        fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), ValueError> {
            ser::SerializeSeq::serialize_element(self, value)
        }

        fn end(self) -> Result<Value, ValueError> {
            ser::SerializeSeq::end(self)
        }
    }

    impl ser::SerializeTupleVariant for SerializeVec {
        type Ok = Value;
        type Error = ValueError;

        fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), ValueError> {
            ser::SerializeSeq::serialize_element(self, value)
        }

        fn end(self) -> Result<Value, ValueError> {
            ser::SerializeSeq::end(self)
        }
    }

    /// A struct/map accumulator. `Map` is the default, while`TaggedPtr`
    /// is used when a struct with name [`crate::vm::ptr::TAGGED_PTR_NAME`]
    /// is captured by `serialize_struct`.
    enum SerializeStruct {
        Map(BTreeMap<String, Value>),
        TaggedPtr(BTreeMap<String, Value>),
    }

    impl SerializeStruct {
        fn map() -> Self {
            Self::Map(BTreeMap::new())
        }

        fn fields_mut(&mut self) -> &mut BTreeMap<String, Value> {
            match self {
                SerializeStruct::Map(m) | SerializeStruct::TaggedPtr(m) => m,
            }
        }
    }

    fn finish(this: SerializeStruct) -> Result<Value, ValueError> {
        match this {
            SerializeStruct::Map(m) => Ok(Value::Map(m)),
            SerializeStruct::TaggedPtr(mut m) => {
                let region: TaggetPtrType = m
                    .remove("region")
                    .ok_or_else(|| ValueError::Serde("missing region".into()))
                    .and_then(from_value)?;
                let offset: u32 = m
                    .remove("offset")
                    .ok_or_else(|| ValueError::Serde("missing offset".into()))
                    .and_then(from_value)?;
                let fd: Option<u16> = m.remove("fd").map(from_value).transpose()?;
                let tp = match region {
                    TaggetPtrType::Map => TaggedPtr::Map {
                        fd: fd
                            .ok_or_else(|| ValueError::Serde("missing fd for map region".into()))?,
                        offset,
                    },
                    TaggetPtrType::Local => TaggedPtr::Local { offset },
                    TaggetPtrType::Kernel => TaggedPtr::Kernel { offset },
                    TaggetPtrType::User => TaggedPtr::User { offset },
                };
                Ok(Value::TaggedPtr(tp))
            }
        }
    }

    impl ser::SerializeStruct for SerializeStruct {
        type Ok = Value;
        type Error = ValueError;

        fn serialize_field<T: ?Sized + Serialize>(
            &mut self,
            key: &'static str,
            value: &T,
        ) -> Result<(), ValueError> {
            self.fields_mut().insert(key.to_owned(), to_value(value)?);
            Ok(())
        }

        fn end(self) -> Result<Value, ValueError> {
            finish(self)
        }
    }

    impl ser::SerializeMap for SerializeStruct {
        type Ok = Value;
        type Error = ValueError;

        fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), ValueError> {
            self.fields_mut()
                .insert(key.serialize(KeySerializer)?, Value::Zeroed);
            Ok(())
        }

        fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), ValueError> {
            let val = to_value(value)?;
            if let Some((_, slot)) = self.fields_mut().iter_mut().last() {
                *slot = val;
            }
            Ok(())
        }

        fn serialize_entry<T: ?Sized + Serialize, U: ?Sized + Serialize>(
            &mut self,
            key: &T,
            value: &U,
        ) -> Result<(), ValueError> {
            self.fields_mut()
                .insert(key.serialize(KeySerializer)?, to_value(value)?);
            Ok(())
        }

        fn end(self) -> Result<Value, ValueError> {
            finish(self)
        }
    }

    impl ser::SerializeStructVariant for SerializeStruct {
        type Ok = Value;
        type Error = ValueError;

        fn serialize_field<T: ?Sized + Serialize>(
            &mut self,
            key: &'static str,
            value: &T,
        ) -> Result<(), ValueError> {
            self.fields_mut().insert(key.to_owned(), to_value(value)?);
            Ok(())
        }

        fn end(self) -> Result<Value, ValueError> {
            finish(self)
        }
    }

    impl<'de> de::Deserializer<'de> for Value {
        type Error = ValueError;

        fn deserialize_any<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, ValueError> {
            match self {
                Value::Zeroed => visitor.visit_unit(),
                Value::Number(n) => visitor.visit_i64(n),
                Value::Float(f) => visitor.visit_f64(f),
                Value::Array(arr) => visitor.visit_seq(SeqAccess(arr.into_iter())),
                Value::Map(map) => visitor.visit_map(MapAccess {
                    iter: map.into_iter(),
                    pending_value: None,
                }),
                // Exposed as a struct so that `TaggedPtr`'s own custom
                // `Deserialize` (and any equivalent helper) can rebuild
                // the typed pointer from the field bag.
                Value::TaggedPtr(tp) => {
                    let mut fields: Vec<(&'static str, Value)> = vec![
                        ("region", to_value(&tp.region())?),
                        ("offset", Value::Number(tp.offset() as i64)),
                    ];
                    if let TaggedPtr::Map { fd, .. } = tp {
                        fields.push(("fd", Value::Number(fd as i64)));
                    }
                    visitor.visit_map(MapAccess {
                        iter: fields
                            .into_iter()
                            .map(|(k, v)| (k.to_owned(), v))
                            .collect::<BTreeMap<_, _>>()
                            .into_iter(),
                        pending_value: None,
                    })
                }
            }
        }

        fn deserialize_option<V: de::Visitor<'de>>(
            self,
            visitor: V,
        ) -> Result<V::Value, ValueError> {
            match self {
                Value::Zeroed => visitor.visit_none(),
                other => visitor.visit_some(other),
            }
        }

        fn deserialize_enum<V: de::Visitor<'de>>(
            self,
            _name: &'static str,
            _variants: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, ValueError> {
            match self {
                Value::Number(idx) => visitor.visit_enum(EnumAccess(idx as u32)),
                other => Err(ValueError::Serde(format!(
                    "expected Number for enum, got {other:?}"
                ))),
            }
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
            bytes byte_buf unit unit_struct newtype_struct seq tuple
            tuple_struct map struct identifier ignored_any
        }
    }

    struct SeqAccess(std::vec::IntoIter<Value>);

    impl<'de> de::SeqAccess<'de> for SeqAccess {
        type Error = ValueError;

        fn next_element_seed<T: de::DeserializeSeed<'de>>(
            &mut self,
            seed: T,
        ) -> Result<Option<T::Value>, ValueError> {
            match self.0.next() {
                Some(val) => seed.deserialize(val).map(Some),
                None => Ok(None),
            }
        }
    }

    struct MapAccess {
        iter: std::collections::btree_map::IntoIter<String, Value>,
        pending_value: Option<Value>,
    }

    impl<'de> de::MapAccess<'de> for MapAccess {
        type Error = ValueError;

        fn next_key_seed<K: de::DeserializeSeed<'de>>(
            &mut self,
            seed: K,
        ) -> Result<Option<K::Value>, ValueError> {
            match self.iter.next() {
                Some((key, value)) => {
                    self.pending_value = Some(value);
                    seed.deserialize(de::value::StringDeserializer::new(key))
                        .map(Some)
                }
                None => Ok(None),
            }
        }

        fn next_value_seed<V: de::DeserializeSeed<'de>>(
            &mut self,
            seed: V,
        ) -> Result<V::Value, ValueError> {
            let value = self.pending_value.take().ok_or(ValueError::Serde(
                "next_value_seed called before next_key_seed".to_string(),
            ))?;
            seed.deserialize(value)
        }
    }

    struct EnumAccess(u32);

    impl<'de> de::EnumAccess<'de> for EnumAccess {
        type Error = ValueError;
        type Variant = UnitVariant;

        fn variant_seed<V: de::DeserializeSeed<'de>>(
            self,
            seed: V,
        ) -> Result<(V::Value, Self::Variant), ValueError> {
            let val = seed.deserialize(de::value::U32Deserializer::new(self.0))?;
            Ok((val, UnitVariant))
        }
    }

    struct UnitVariant;

    impl<'de> de::VariantAccess<'de> for UnitVariant {
        type Error = ValueError;

        fn unit_variant(self) -> Result<(), ValueError> {
            Ok(())
        }

        fn newtype_variant_seed<T: de::DeserializeSeed<'de>>(
            self,
            _seed: T,
        ) -> Result<T::Value, ValueError> {
            Err(ValueError::Serde("expected unit variant".into()))
        }

        fn tuple_variant<V: de::Visitor<'de>>(
            self,
            _len: usize,
            _visitor: V,
        ) -> Result<V::Value, ValueError> {
            Err(ValueError::Serde("expected unit variant".into()))
        }

        fn struct_variant<V: de::Visitor<'de>>(
            self,
            _fields: &'static [&'static str],
            _visitor: V,
        ) -> Result<V::Value, ValueError> {
            Err(ValueError::Serde("expected unit variant".into()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Point {
            x: i32,
            y: i32,
        }

        #[test]
        fn roundtrip_struct() {
            let p = Point { x: 10, y: -3 };
            let val = to_value(&p).unwrap();
            let p2: Point = from_value(val).unwrap();
            assert_eq!(p, p2);
        }

        #[test]
        fn roundtrip_float() {
            let val = to_value(&3.14f64).unwrap();
            assert!(matches!(val, Value::Float(f) if (f - 3.14).abs() < f64::EPSILON));
            let f: f64 = from_value(val).unwrap();
            assert!((f - 3.14).abs() < f64::EPSILON);
        }

        #[test]
        fn roundtrip_array() {
            let arr = vec![1i32, 2, 3];
            let val = to_value(&arr).unwrap();
            assert!(matches!(&val, Value::Array(v) if v.len() == 3));
            let arr2: Vec<i32> = from_value(val).unwrap();
            assert_eq!(arr, arr2);
        }

        #[test]
        fn serialize_none() {
            let val = to_value(&Option::<i32>::None).unwrap();
            assert!(matches!(val, Value::Zeroed));
        }

        #[test]
        fn serialize_some() {
            let val = to_value(&Some(42i32)).unwrap();
            assert!(matches!(val, Value::Number(42)));
        }

        #[test]
        fn deserialize_option_none() {
            let val = Value::Zeroed;
            let opt: Option<i32> = from_value(val).unwrap();
            assert_eq!(opt, None);
        }

        #[test]
        fn deserialize_option_some() {
            let val = Value::Number(7);
            let opt: Option<i32> = from_value(val).unwrap();
            assert_eq!(opt, Some(7));
        }

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Color {
            Red,
            Green,
            Blue,
        }

        #[test]
        fn roundtrip_unit_enum() {
            let val = to_value(&Color::Green).unwrap();
            assert!(matches!(val, Value::Number(1)));
            let c: Color = from_value(val).unwrap();
            assert_eq!(c, Color::Green);
        }

        #[test]
        fn bool_serializes_as_number() {
            let val = to_value(&true).unwrap();
            assert!(matches!(val, Value::Number(1)));
            let val = to_value(&false).unwrap();
            assert!(matches!(val, Value::Number(0)));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{btf::BtfBuilder, vm::ptr::TaggedPtr};

    use super::{Value, ValueError};

    #[test]
    fn zeroed_returns_zero_buffer_for_each_kind() {
        let mut b = BtfBuilder::default();
        let u8_ty = b.add_int("u8", 1, 0);
        let u32_ty = b.add_int("u32", 4, 0);
        let arr_ty = b.add_array("", u8_ty, u32_ty, 5);
        let strct_ty = b.make_struct("s", 8, |s| {
            s.field("a", u32_ty, 0);
            s.field("b", u32_ty, 32);
        });
        let btf = b.build();

        for (id, size) in [(u8_ty, 1), (u32_ty, 4), (arr_ty, 5), (strct_ty, 8)] {
            let bytes = Value::Zeroed.to_bytes(btf.resolve_must(id)).unwrap();
            assert_eq!(bytes, vec![0u8; size]);
        }
    }

    #[test]
    fn array_of_bytes_packs_into_int() {
        let mut b = BtfBuilder::default();
        let u64_ty = b.add_int("u64", 8, 0);
        let btf = b.build();

        let val = 0x0123_4567_89AB_CDEFu64;
        let bytes_val = val.to_ne_bytes();
        let array_val = Value::Array(bytes_val.iter().map(|b| Value::Number(*b as i64)).collect());
        let bytes = array_val.to_bytes(btf.resolve_must(u64_ty)).unwrap();
        assert_eq!(bytes, bytes_val);
    }

    #[test]
    fn array_shorter_than_int_zero_extends() {
        let mut b = BtfBuilder::default();
        let u64_ty = b.add_int("u64", 8, 0);
        let btf = b.build();

        let array_val = Value::Array(vec![Value::Number(0xAB), Value::Number(0xCD)]);
        let bytes = array_val.to_bytes(btf.resolve_must(u64_ty)).unwrap();
        assert_eq!(bytes, [0xAB, 0xCD, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn array_longer_than_int_rejected() {
        let mut b = BtfBuilder::default();
        let u32_ty = b.add_int("u32", 4, 0);
        let btf = b.build();

        let array_val = Value::Array(vec![Value::Number(0); 5]);
        let err = array_val.to_bytes(btf.resolve_must(u32_ty)).unwrap_err();
        assert!(matches!(err, ValueError::ArrayOutOfBounds(5, 4)));
    }

    #[test]
    fn array_overflowing_int_bit_width_rejected() {
        use crate::btf::BtfKind;

        let mut b = BtfBuilder::default();
        let u24_ty = b.add_int("u24", 4, 0);
        let mut btf = b.build();
        // The builder always sets `bits = size * 8`; force a narrower
        // logical width so the bit-width check has something to catch.
        if let BtfKind::Int(int) = &mut btf.types.get_mut(&u24_ty).unwrap().kind {
            int.bits = 24;
        }

        let array_val = Value::Array(vec![
            Value::Number(0xFF),
            Value::Number(0xFF),
            Value::Number(0xFF),
            Value::Number(0x01),
        ]);
        let err = array_val.to_bytes(btf.resolve_must(u24_ty)).unwrap_err();
        assert!(matches!(err, ValueError::NumberOverflow(_, 24)));

        let in_bounds = Value::Array(vec![
            Value::Number(0xFF),
            Value::Number(0xFF),
            Value::Number(0xFF),
            Value::Number(0x00),
        ]);
        in_bounds.to_bytes(btf.resolve_must(u24_ty)).unwrap();
    }

    #[test]
    fn array_with_non_byte_element_rejected() {
        let mut b = BtfBuilder::default();
        let u32_ty = b.add_int("u32", 4, 0);
        let btf = b.build();

        let array_val = Value::Array(vec![Value::Number(0x1FF)]);
        let err = array_val.to_bytes(btf.resolve_must(u32_ty)).unwrap_err();
        assert!(matches!(err, ValueError::NumberOverflow(0x1FF, 8)));
    }

    #[test]
    fn number_serializes_to_int_widths() {
        let mut b = BtfBuilder::default();
        let u8_ty = b.add_int("u8", 1, 0);
        let u16_ty = b.add_int("u16", 2, 0);
        let u32_ty = b.add_int("u32", 4, 0);
        let u64_ty = b.add_int("u64", 8, 0);
        let btf = b.build();

        for (id, num, size) in [
            (u8_ty, 0x7Ai64, 1),
            (u16_ty, 0x1234i64, 2),
            (u32_ty, 0x0EAD_BEEFi64, 4),
            (u64_ty, 0x0123_4567_89AB_CDEFi64, 8),
        ] {
            let bytes = Value::Number(num).to_bytes(btf.resolve_must(id)).unwrap();
            assert_eq!(bytes, num.to_ne_bytes()[..size]);
        }
    }

    #[test]
    fn number_serializes_to_ptr_as_eight_bytes() {
        let mut b = BtfBuilder::default();
        let u32_ty = b.add_int("u32", 4, 0);
        let ptr_ty = b.add_ptr(u32_ty);
        let btf = b.build();

        let val = 0x1122_3344_5566_7788i64;
        let bytes = Value::Number(val)
            .to_bytes(btf.resolve_must(ptr_ty))
            .unwrap();
        assert_eq!(bytes, val.to_ne_bytes());
    }

    #[test]
    fn number_serializes_to_enums() {
        let mut b = BtfBuilder::default();
        let color = b.make_enum("color", 4, false, |e| {
            e.value("red", 0);
            e.value("green", 1);
            e.value("blue", 2);
        });
        let big = b.make_enum64("big", 8, false, |e| {
            e.value("low", 0);
            e.value("high", 0x1_0000_0000i64);
        });
        let btf = b.build();

        for (id, num, size) in [
            (color, 0i64, 4),
            (color, 2i64, 4),
            (big, 0i64, 8),
            (big, 0x1_0000_0000i64, 8),
        ] {
            let bytes = Value::Number(num).to_bytes(btf.resolve_must(id)).unwrap();
            assert_eq!(bytes, num.to_ne_bytes()[..size]);
        }
    }

    #[test]
    fn float_serializes_to_four_and_eight_bytes() {
        let mut b = BtfBuilder::default();
        let f32_ty = b.add_float("f32", 4);
        let f64_ty = b.add_float("f64", 8);
        let btf = b.build();

        let bytes = Value::Float(3.14)
            .to_bytes(btf.resolve_must(f32_ty))
            .unwrap();
        assert_eq!(bytes, 3.14_f32.to_ne_bytes());

        let bytes = Value::Float(3.14)
            .to_bytes(btf.resolve_must(f64_ty))
            .unwrap();
        assert_eq!(bytes, 3.14_f64.to_ne_bytes());
    }

    #[test]
    fn array_packs_elements_and_pads_short() {
        let mut b = BtfBuilder::default();
        let u32_ty = b.add_int("u32", 4, 0);
        let arr_ty = b.add_array("", u32_ty, u32_ty, 4);
        let btf = b.build();
        let ty = btf.resolve_must(arr_ty);

        let full = Value::Array(vec![
            Value::Number(1),
            Value::Number(2),
            Value::Number(3),
            Value::Number(4),
        ]);
        let mut expected: Vec<u8> = Vec::new();
        for v in [1i64, 2, 3, 4] {
            expected.extend(&v.to_ne_bytes()[..4]);
        }
        assert_eq!(full.to_bytes(ty).unwrap(), expected);

        let short = Value::Array(vec![Value::Number(7), Value::Number(8)]);
        let mut expected: Vec<u8> = Vec::new();
        for v in [7i64, 8] {
            expected.extend(&v.to_ne_bytes()[..4]);
        }
        expected.resize(16, 0);
        assert_eq!(short.to_bytes(ty).unwrap(), expected);
    }

    #[test]
    fn struct_packs_named_fields_at_offsets() {
        let mut b = BtfBuilder::default();
        let u8_ty = b.add_int("u8", 1, 0);
        let u32_ty = b.add_int("u32", 4, 0);
        let s_ty = b.make_struct("s", 8, |s| {
            s.field("a", u32_ty, 0);
            s.field("b", u8_ty, 32);
            s.field("c", u8_ty, 40);
        });
        let btf = b.build();

        let val = Value::Map(BTreeMap::from([
            ("a".to_string(), Value::Number(0x0EAD_BEEFi64)),
            ("b".to_string(), Value::Number(0x42)),
            ("c".to_string(), Value::Number(0x99)),
        ]));
        let bytes = val.to_bytes(btf.resolve_must(s_ty)).unwrap();
        let mut expected: Vec<u8> = Vec::new();
        expected.extend(&0x0EAD_BEEFi64.to_ne_bytes()[..4]);
        expected.push(0x42);
        expected.push(0x99);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn struct_zeroes_omitted_fields() {
        let mut b = BtfBuilder::default();
        let u32_ty = b.add_int("u32", 4, 0);
        let s_ty = b.make_struct("s", 8, |s| {
            s.field("a", u32_ty, 0);
            s.field("b", u32_ty, 32);
        });
        let btf = b.build();

        let val = Value::Map(BTreeMap::from([("b".to_string(), Value::Number(0x55i64))]));
        let bytes = val.to_bytes(btf.resolve_must(s_ty)).unwrap();
        let mut expected = vec![0u8; 4];
        expected.extend(&0x55i64.to_ne_bytes()[..4]);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn struct_keys_anon_field_by_index() {
        let mut b = BtfBuilder::default();
        let u32_ty = b.add_int("u32", 4, 0);
        let s_ty = b.make_struct("s", 8, |s| {
            s.field("a", u32_ty, 0);
            s.field("", u32_ty, 32);
        });
        let btf = b.build();

        let val = Value::Map(BTreeMap::from([
            ("a".to_string(), Value::Number(0x11)),
            ("_anon_1".to_string(), Value::Number(0x22)),
        ]));
        let bytes = val.to_bytes(btf.resolve_must(s_ty)).unwrap();
        let mut expected: Vec<u8> = Vec::new();
        expected.extend(&0x11i64.to_ne_bytes()[..4]);
        expected.extend(&0x22i64.to_ne_bytes()[..4]);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn union_picks_active_variant() {
        let mut b = BtfBuilder::default();
        let u32_ty = b.add_int("u32", 4, 0);
        let u8_ty = b.add_int("u8", 1, 0);
        let arr_ty = b.add_array("", u8_ty, u32_ty, 4);
        let u_ty = b.make_union("u", 4, |u| {
            u.field("scalar", u32_ty, 0);
            u.field("bytes", arr_ty, 0);
        });
        let btf = b.build();

        let val = Value::Map(BTreeMap::from([(
            "scalar".to_string(),
            Value::Number(0x1234_5678i64),
        )]));
        let bytes = val.to_bytes(btf.resolve_must(u_ty)).unwrap();
        assert_eq!(bytes, &0x1234_5678i64.to_ne_bytes()[..4]);
    }

    #[test]
    fn union_keys_anon_field_by_index() {
        let mut b = BtfBuilder::default();
        let u32_ty = b.add_int("u32", 4, 0);
        let u_ty = b.make_union("u", 4, |u| {
            u.field("scalar", u32_ty, 0);
            u.field("", u32_ty, 0);
        });
        let btf = b.build();

        let val = Value::Map(BTreeMap::from([(
            "_anon_1".to_string(),
            Value::Number(0xBEEFi64),
        )]));
        let bytes = val.to_bytes(btf.resolve_must(u_ty)).unwrap();
        assert_eq!(bytes, &0xBEEFi64.to_ne_bytes()[..4]);
    }

    #[test]
    fn tagged_ptr_serializes_for_each_region() {
        let mut b = BtfBuilder::default();
        let u32_ty = b.add_int("u32", 4, 0);
        let ptr_ty = b.add_ptr(u32_ty);
        let btf = b.build();
        let ty = btf.resolve_must(ptr_ty);

        for tp in [
            TaggedPtr::Kernel { offset: 0x10 },
            TaggedPtr::User { offset: 0x10 },
            TaggedPtr::Local { offset: 0x10 },
        ] {
            let val = Value::TaggedPtr(tp);
            let bytes = val.to_bytes(ty).unwrap();
            assert_eq!(bytes, tp.to_raw().to_ne_bytes());
        }
    }

    #[test]
    fn tagged_ptr_round_trips_through_to_value() {
        let tp = TaggedPtr::Kernel { offset: 0xBEEF };
        let val = Value::TaggedPtr(tp);
        let round = crate::to_value(&val).unwrap();
        match round {
            Value::TaggedPtr(rt) => {
                assert!(matches!(rt, TaggedPtr::Kernel { offset: 0xBEEF }));
            }
            other => panic!("expected TaggedPtr, got {other:?}"),
        }
    }
}
