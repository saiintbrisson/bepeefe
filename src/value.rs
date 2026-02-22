use std::collections::HashMap;

use ::serde::{Deserialize, Serialize};

use crate::btf::{Btf, BtfKind, BtfType};

pub use serde::{Error, from_value, to_value};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum ProgramValue {
    #[default]
    Zeroed,
    Number(i64),
    Float(f64),
    Array(Vec<ProgramValue>),
    Map(HashMap<String, ProgramValue>),
}

impl ProgramValue {
    pub fn to_bytes<'b>(&self, btf: &'b Btf, mut ty: &'b BtfType) -> Vec<u8> {
        let size = ty.kind.size(btf).unwrap() as usize;

        match self {
            ProgramValue::Zeroed => vec![0; size],
            ProgramValue::Number(num) => match &ty.kind {
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
            ProgramValue::Float(f) => match &ty.kind {
                BtfKind::Float(float) => match float.size {
                    4 => (*f as f32).to_ne_bytes().to_vec(),
                    8 => f.to_ne_bytes().to_vec(),
                    _ => todo!("unsupported float size {}", float.size),
                },
                _ => todo!("expected float type"),
            },
            ProgramValue::Array(elems) => {
                let BtfKind::Array(arr) = &ty.kind else {
                    todo!("expected array type");
                };
                assert!(
                    elems.len() <= arr.no_elems as usize,
                    "array has {} elements but BTF type allows at most {}",
                    elems.len(),
                    arr.no_elems,
                );
                let elem_ty = btf.get_type(arr.r#type).unwrap();
                let elem_size = elem_ty.kind.size(btf).unwrap() as usize;
                let mut buf = Vec::with_capacity(arr.no_elems as usize * elem_size);
                for elem in elems {
                    buf.extend(elem.to_bytes(btf, elem_ty));
                }
                buf.resize(arr.no_elems as usize * elem_size, 0);
                buf
            }
            ProgramValue::Map(map) => {
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
                    let byte_offset = (ele.offset / 8) as usize;
                    buf.resize(byte_offset, 0);

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

    pub fn from_bytes(btf: &Btf, ty: &BtfType, bytes: &[u8]) -> ProgramValue {
        match &ty.kind {
            BtfKind::Int(int) => {
                let size = int.size as usize;
                let mut buf = [0u8; 8];
                buf[..size].copy_from_slice(&bytes[..size]);
                ProgramValue::Number(i64::from_ne_bytes(buf))
            }
            BtfKind::Enum(e) => {
                let size = e.size as usize;
                let mut buf = [0u8; 8];
                buf[..size].copy_from_slice(&bytes[..size]);
                ProgramValue::Number(i64::from_ne_bytes(buf))
            }
            BtfKind::Enum64(e) => {
                let size = e.size as usize;
                let mut buf = [0u8; 8];
                buf[..size].copy_from_slice(&bytes[..size]);
                ProgramValue::Number(i64::from_ne_bytes(buf))
            }
            BtfKind::Float(float) => {
                let f = match float.size {
                    4 => {
                        let mut buf = [0u8; 4];
                        buf.copy_from_slice(&bytes[..4]);
                        f32::from_ne_bytes(buf) as f64
                    }
                    8 => {
                        let mut buf = [0u8; 8];
                        buf.copy_from_slice(&bytes[..8]);
                        f64::from_ne_bytes(buf)
                    }
                    _ => todo!("unsupported float size {}", float.size),
                };
                ProgramValue::Float(f)
            }
            BtfKind::Array(arr) => {
                let elem_ty = btf.get_type(arr.r#type).unwrap();
                let elem_size = elem_ty.kind.size(btf).unwrap() as usize;
                let mut elems = Vec::with_capacity(arr.no_elems as usize);
                for i in 0..arr.no_elems as usize {
                    let offset = i * elem_size;
                    elems.push(ProgramValue::from_bytes(
                        btf,
                        elem_ty,
                        &bytes[offset..offset + elem_size],
                    ));
                }
                ProgramValue::Array(elems)
            }
            BtfKind::Struct(s) => {
                let mut map = HashMap::new();
                for member in &s.members {
                    let member_ty = btf.get_type(member.r#type).unwrap();
                    let name = btf.string(member.name_off).unwrap();
                    let byte_offset = (member.offset / 8) as usize;
                    let member_size = member_ty.kind.size(btf).unwrap() as usize;
                    let val = ProgramValue::from_bytes(
                        btf,
                        member_ty,
                        &bytes[byte_offset..byte_offset + member_size],
                    );
                    map.insert(name.to_string(), val);
                }
                ProgramValue::Map(map)
            }
            _ => todo!("from_bytes: unsupported BTF kind"),
        }
    }
}

impl<const N: usize> From<[(&str, ProgramValue); N]> for ProgramValue {
    fn from(value: [(&str, ProgramValue); N]) -> Self {
        Self::Map(value.map(|(key, val)| (key.to_owned(), val)).into())
    }
}

mod serde {
    use core::fmt;
    use std::collections::HashMap;

    use serde::{Deserialize, Serialize, de, ser};

    use super::ProgramValue;

    pub fn to_value<T: Serialize + ?Sized>(value: &T) -> Result<ProgramValue, Error> {
        value.serialize(Serializer)
    }

    pub fn from_value<T: for<'de> Deserialize<'de>>(value: ProgramValue) -> Result<T, Error> {
        T::deserialize(value)
    }

    #[derive(Debug)]
    pub struct Error(String);

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for Error {}

    impl ser::Error for Error {
        fn custom<T: fmt::Display>(msg: T) -> Self {
            Error(msg.to_string())
        }
    }

    impl de::Error for Error {
        fn custom<T: fmt::Display>(msg: T) -> Self {
            Error(msg.to_string())
        }
    }

    struct Serializer;

    macro_rules! serialize_int {
    ($($method:ident($ty:ty),)*) => {
        $(
            fn $method(self, v: $ty) -> Result<ProgramValue, Error> {
                Ok(ProgramValue::Number(v as i64))
            }
        )*
    };
}

    impl ser::Serializer for Serializer {
        type Ok = ProgramValue;
        type Error = Error;

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

        fn serialize_f32(self, v: f32) -> Result<ProgramValue, Error> {
            Ok(ProgramValue::Float(v as f64))
        }

        fn serialize_f64(self, v: f64) -> Result<ProgramValue, Error> {
            Ok(ProgramValue::Float(v))
        }

        fn serialize_str(self, _v: &str) -> Result<ProgramValue, Error> {
            Err(Error("strings are not supported".into()))
        }

        fn serialize_bytes(self, _v: &[u8]) -> Result<ProgramValue, Error> {
            Err(Error("byte slices are not supported".into()))
        }

        fn serialize_none(self) -> Result<ProgramValue, Error> {
            Ok(ProgramValue::Zeroed)
        }

        fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<ProgramValue, Error> {
            value.serialize(self)
        }

        fn serialize_unit(self) -> Result<ProgramValue, Error> {
            Ok(ProgramValue::Zeroed)
        }

        fn serialize_unit_struct(self, _name: &'static str) -> Result<ProgramValue, Error> {
            Ok(ProgramValue::Zeroed)
        }

        fn serialize_unit_variant(
            self,
            _name: &'static str,
            variant_index: u32,
            _variant: &'static str,
        ) -> Result<ProgramValue, Error> {
            Ok(ProgramValue::Number(variant_index as i64))
        }

        fn serialize_newtype_struct<T: ?Sized + Serialize>(
            self,
            _name: &'static str,
            value: &T,
        ) -> Result<ProgramValue, Error> {
            value.serialize(self)
        }

        fn serialize_newtype_variant<T: ?Sized + Serialize>(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
            value: &T,
        ) -> Result<ProgramValue, Error> {
            value.serialize(self)
        }

        fn serialize_seq(self, len: Option<usize>) -> Result<SerializeVec, Error> {
            Ok(SerializeVec(Vec::with_capacity(len.unwrap_or(0))))
        }

        fn serialize_tuple(self, len: usize) -> Result<SerializeVec, Error> {
            self.serialize_seq(Some(len))
        }

        fn serialize_tuple_struct(
            self,
            _name: &'static str,
            len: usize,
        ) -> Result<SerializeVec, Error> {
            self.serialize_seq(Some(len))
        }

        fn serialize_tuple_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
            len: usize,
        ) -> Result<SerializeVec, Error> {
            self.serialize_seq(Some(len))
        }

        fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Error> {
            Ok(SerializeStruct(HashMap::with_capacity(len.unwrap_or(0))))
        }

        fn serialize_struct(
            self,
            _name: &'static str,
            len: usize,
        ) -> Result<SerializeStruct, Error> {
            Ok(SerializeStruct(HashMap::with_capacity(len)))
        }

        fn serialize_struct_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
            len: usize,
        ) -> Result<SerializeStruct, Error> {
            Ok(SerializeStruct(HashMap::with_capacity(len)))
        }
    }

    struct KeySerializer;

    fn key_err<T>() -> Result<T, Error> {
        Err(Error("key must be a string".into()))
    }

    impl ser::Serializer for KeySerializer {
        type Ok = String;
        type Error = Error;
        type SerializeSeq = ser::Impossible<String, Error>;
        type SerializeTuple = ser::Impossible<String, Error>;
        type SerializeTupleStruct = ser::Impossible<String, Error>;
        type SerializeTupleVariant = ser::Impossible<String, Error>;
        type SerializeMap = ser::Impossible<String, Error>;
        type SerializeStruct = ser::Impossible<String, Error>;
        type SerializeStructVariant = ser::Impossible<String, Error>;

        fn serialize_str(self, v: &str) -> Result<String, Error> {
            Ok(v.to_owned())
        }

        fn serialize_bool(self, _: bool) -> Result<String, Error> {
            key_err()
        }
        fn serialize_i8(self, _: i8) -> Result<String, Error> {
            key_err()
        }
        fn serialize_i16(self, _: i16) -> Result<String, Error> {
            key_err()
        }
        fn serialize_i32(self, _: i32) -> Result<String, Error> {
            key_err()
        }
        fn serialize_i64(self, _: i64) -> Result<String, Error> {
            key_err()
        }
        fn serialize_u8(self, _: u8) -> Result<String, Error> {
            key_err()
        }
        fn serialize_u16(self, _: u16) -> Result<String, Error> {
            key_err()
        }
        fn serialize_u32(self, _: u32) -> Result<String, Error> {
            key_err()
        }
        fn serialize_u64(self, _: u64) -> Result<String, Error> {
            key_err()
        }
        fn serialize_f32(self, _: f32) -> Result<String, Error> {
            key_err()
        }
        fn serialize_f64(self, _: f64) -> Result<String, Error> {
            key_err()
        }
        fn serialize_char(self, _: char) -> Result<String, Error> {
            key_err()
        }
        fn serialize_bytes(self, _: &[u8]) -> Result<String, Error> {
            key_err()
        }
        fn serialize_none(self) -> Result<String, Error> {
            key_err()
        }
        fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<String, Error> {
            key_err()
        }
        fn serialize_unit(self) -> Result<String, Error> {
            key_err()
        }
        fn serialize_unit_struct(self, _: &'static str) -> Result<String, Error> {
            key_err()
        }
        fn serialize_unit_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
        ) -> Result<String, Error> {
            key_err()
        }
        fn serialize_newtype_struct<T: ?Sized + Serialize>(
            self,
            _: &'static str,
            _: &T,
        ) -> Result<String, Error> {
            key_err()
        }
        fn serialize_newtype_variant<T: ?Sized + Serialize>(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: &T,
        ) -> Result<String, Error> {
            key_err()
        }
        fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Error> {
            key_err()
        }
        fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Error> {
            key_err()
        }
        fn serialize_tuple_struct(
            self,
            _: &'static str,
            _: usize,
        ) -> Result<Self::SerializeTupleStruct, Error> {
            key_err()
        }
        fn serialize_tuple_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self::SerializeTupleVariant, Error> {
            key_err()
        }
        fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Error> {
            key_err()
        }
        fn serialize_struct(
            self,
            _: &'static str,
            _: usize,
        ) -> Result<Self::SerializeStruct, Error> {
            key_err()
        }
        fn serialize_struct_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self::SerializeStructVariant, Error> {
            key_err()
        }
    }

    struct SerializeVec(Vec<ProgramValue>);

    impl ser::SerializeSeq for SerializeVec {
        type Ok = ProgramValue;
        type Error = Error;

        fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
            self.0.push(to_value(value)?);
            Ok(())
        }

        fn end(self) -> Result<ProgramValue, Error> {
            Ok(ProgramValue::Array(self.0))
        }
    }

    impl ser::SerializeTuple for SerializeVec {
        type Ok = ProgramValue;
        type Error = Error;

        fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
            ser::SerializeSeq::serialize_element(self, value)
        }

        fn end(self) -> Result<ProgramValue, Error> {
            ser::SerializeSeq::end(self)
        }
    }

    impl ser::SerializeTupleStruct for SerializeVec {
        type Ok = ProgramValue;
        type Error = Error;

        fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
            ser::SerializeSeq::serialize_element(self, value)
        }

        fn end(self) -> Result<ProgramValue, Error> {
            ser::SerializeSeq::end(self)
        }
    }

    impl ser::SerializeTupleVariant for SerializeVec {
        type Ok = ProgramValue;
        type Error = Error;

        fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
            ser::SerializeSeq::serialize_element(self, value)
        }

        fn end(self) -> Result<ProgramValue, Error> {
            ser::SerializeSeq::end(self)
        }
    }

    struct SerializeStruct(HashMap<String, ProgramValue>);

    impl ser::SerializeStruct for SerializeStruct {
        type Ok = ProgramValue;
        type Error = Error;

        fn serialize_field<T: ?Sized + Serialize>(
            &mut self,
            key: &'static str,
            value: &T,
        ) -> Result<(), Error> {
            self.0.insert(key.to_owned(), to_value(value)?);
            Ok(())
        }

        fn end(self) -> Result<ProgramValue, Error> {
            Ok(ProgramValue::Map(self.0))
        }
    }

    impl ser::SerializeMap for SerializeStruct {
        type Ok = ProgramValue;
        type Error = Error;

        fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Error> {
            self.0
                .insert(key.serialize(KeySerializer)?, ProgramValue::Zeroed);
            Ok(())
        }

        fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
            let val = to_value(value)?;
            if let Some((_, slot)) = self.0.iter_mut().last() {
                *slot = val;
            }
            Ok(())
        }

        fn serialize_entry<T: ?Sized + Serialize, U: ?Sized + Serialize>(
            &mut self,
            key: &T,
            value: &U,
        ) -> Result<(), Error> {
            self.0
                .insert(key.serialize(KeySerializer)?, to_value(value)?);
            Ok(())
        }

        fn end(self) -> Result<ProgramValue, Error> {
            Ok(ProgramValue::Map(self.0))
        }
    }

    impl ser::SerializeStructVariant for SerializeStruct {
        type Ok = ProgramValue;
        type Error = Error;

        fn serialize_field<T: ?Sized + Serialize>(
            &mut self,
            key: &'static str,
            value: &T,
        ) -> Result<(), Error> {
            self.0.insert(key.to_owned(), to_value(value)?);
            Ok(())
        }

        fn end(self) -> Result<ProgramValue, Error> {
            Ok(ProgramValue::Map(self.0))
        }
    }

    impl<'de> de::Deserializer<'de> for ProgramValue {
        type Error = Error;

        fn deserialize_any<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            match self {
                ProgramValue::Zeroed => visitor.visit_unit(),
                ProgramValue::Number(n) => visitor.visit_i64(n),
                ProgramValue::Float(f) => visitor.visit_f64(f),
                ProgramValue::Array(arr) => visitor.visit_seq(SeqAccess(arr.into_iter())),
                ProgramValue::Map(map) => visitor.visit_map(MapAccess {
                    iter: map.into_iter(),
                    pending_value: None,
                }),
            }
        }

        fn deserialize_option<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            match self {
                ProgramValue::Zeroed => visitor.visit_none(),
                other => visitor.visit_some(other),
            }
        }

        fn deserialize_enum<V: de::Visitor<'de>>(
            self,
            _name: &'static str,
            _variants: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, Error> {
            match self {
                ProgramValue::Number(idx) => visitor.visit_enum(EnumAccess(idx as u32)),
                other => Err(Error(format!("expected Number for enum, got {other:?}"))),
            }
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
            bytes byte_buf unit unit_struct newtype_struct seq tuple
            tuple_struct map struct identifier ignored_any
        }
    }

    struct SeqAccess(std::vec::IntoIter<ProgramValue>);

    impl<'de> de::SeqAccess<'de> for SeqAccess {
        type Error = Error;

        fn next_element_seed<T: de::DeserializeSeed<'de>>(
            &mut self,
            seed: T,
        ) -> Result<Option<T::Value>, Error> {
            match self.0.next() {
                Some(val) => seed.deserialize(val).map(Some),
                None => Ok(None),
            }
        }
    }

    struct MapAccess {
        iter: std::collections::hash_map::IntoIter<String, ProgramValue>,
        pending_value: Option<ProgramValue>,
    }

    impl<'de> de::MapAccess<'de> for MapAccess {
        type Error = Error;

        fn next_key_seed<K: de::DeserializeSeed<'de>>(
            &mut self,
            seed: K,
        ) -> Result<Option<K::Value>, Error> {
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
        ) -> Result<V::Value, Error> {
            let value = self
                .pending_value
                .take()
                .expect("next_value_seed called before next_key_seed");
            seed.deserialize(value)
        }
    }

    struct EnumAccess(u32);

    impl<'de> de::EnumAccess<'de> for EnumAccess {
        type Error = Error;
        type Variant = UnitVariant;

        fn variant_seed<V: de::DeserializeSeed<'de>>(
            self,
            seed: V,
        ) -> Result<(V::Value, Self::Variant), Error> {
            let val = seed.deserialize(de::value::U32Deserializer::new(self.0))?;
            Ok((val, UnitVariant))
        }
    }

    struct UnitVariant;

    impl<'de> de::VariantAccess<'de> for UnitVariant {
        type Error = Error;

        fn unit_variant(self) -> Result<(), Error> {
            Ok(())
        }

        fn newtype_variant_seed<T: de::DeserializeSeed<'de>>(
            self,
            _seed: T,
        ) -> Result<T::Value, Error> {
            Err(Error("expected unit variant".into()))
        }

        fn tuple_variant<V: de::Visitor<'de>>(
            self,
            _len: usize,
            _visitor: V,
        ) -> Result<V::Value, Error> {
            Err(Error("expected unit variant".into()))
        }

        fn struct_variant<V: de::Visitor<'de>>(
            self,
            _fields: &'static [&'static str],
            _visitor: V,
        ) -> Result<V::Value, Error> {
            Err(Error("expected unit variant".into()))
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
            assert!(matches!(val, ProgramValue::Float(f) if (f - 3.14).abs() < f64::EPSILON));
            let f: f64 = from_value(val).unwrap();
            assert!((f - 3.14).abs() < f64::EPSILON);
        }

        #[test]
        fn roundtrip_array() {
            let arr = vec![1i32, 2, 3];
            let val = to_value(&arr).unwrap();
            assert!(matches!(&val, ProgramValue::Array(v) if v.len() == 3));
            let arr2: Vec<i32> = from_value(val).unwrap();
            assert_eq!(arr, arr2);
        }

        #[test]
        fn serialize_none() {
            let val = to_value(&Option::<i32>::None).unwrap();
            assert!(matches!(val, ProgramValue::Zeroed));
        }

        #[test]
        fn serialize_some() {
            let val = to_value(&Some(42i32)).unwrap();
            assert!(matches!(val, ProgramValue::Number(42)));
        }

        #[test]
        fn deserialize_option_none() {
            let val = ProgramValue::Zeroed;
            let opt: Option<i32> = from_value(val).unwrap();
            assert_eq!(opt, None);
        }

        #[test]
        fn deserialize_option_some() {
            let val = ProgramValue::Number(7);
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
            assert!(matches!(val, ProgramValue::Number(1)));
            let c: Color = from_value(val).unwrap();
            assert_eq!(c, Color::Green);
        }

        #[test]
        fn bool_serializes_as_number() {
            let val = to_value(&true).unwrap();
            assert!(matches!(val, ProgramValue::Number(1)));
            let val = to_value(&false).unwrap();
            assert!(matches!(val, ProgramValue::Number(0)));
        }
    }
}
