use serde::{Deserialize, Serialize, de, ser::SerializeStruct};

const PTR_OFFSET_MASK: u64 = u32::MAX as u64;
const TAG_MAP_FD_MASK: u64 = (u16::MAX as u64) << 40;

const TAG_MASK: u64 = 0b1111 << 60;
const TAG_MAP: u64 = 1 << 60;
const TAG_LOCAL: u64 = 2 << 60;
const TAG_KERNEL: u64 = 3 << 60;
const TAG_USER: u64 = 4 << 60;

/// Used in Value's serde Deserializer to avoid folding all structs into
/// `Value::Map`s.
pub(crate) const TAGGED_PTR_NAME: &str = "$bepeefe::TaggedPtr";

/// Tagged pointers for runtime identification.
///
/// Our memory is not flat. Program stack and maps have different memory buffers
/// and in order to identify which one a program is accessing, we tag them.
#[derive(Clone, Copy, Debug, strum::EnumDiscriminants)]
#[strum_discriminants(name(TaggetPtrType))]
#[strum_discriminants(vis(pub))]
#[strum_discriminants(derive(serde::Deserialize, serde::Serialize))]
#[strum_discriminants(serde(rename_all = "lowercase"))]
pub enum TaggedPtr {
    Map { fd: u16, offset: u32 },
    Local { offset: u32 },
    Kernel { offset: u32 },
    User { offset: u32 },
}

impl TaggedPtr {
    pub fn try_decode(raw: u64) -> Option<Self> {
        let offset = (raw & PTR_OFFSET_MASK) as u32;
        match raw & TAG_MASK {
            TAG_MAP => {
                let fd = ((raw & TAG_MAP_FD_MASK) >> TAG_MAP_FD_MASK.trailing_zeros()) as u16;
                Some(TaggedPtr::Map { fd, offset })
            }
            TAG_LOCAL => Some(TaggedPtr::Local { offset }),
            TAG_KERNEL => Some(TaggedPtr::Kernel { offset }),
            TAG_USER => Some(TaggedPtr::User { offset }),
            _ => None,
        }
    }

    /// Decodes a pointer into a tagged variant.
    ///
    /// # Panics
    ///
    /// Panics if the pointer does not follow the required structure for tags.
    #[expect(
        clippy::panic,
        reason = "caller is expected to run verifier, use try_decode for unverified input"
    )]
    pub fn decode(raw: u64) -> Self {
        Self::try_decode(raw).unwrap_or_else(|| panic!("illegal pointer tag for {raw:X}"))
    }

    pub fn region(&self) -> TaggetPtrType {
        TaggetPtrType::from(self)
    }

    pub fn offset(&self) -> u32 {
        match *self {
            TaggedPtr::Map { offset, .. }
            | TaggedPtr::Local { offset }
            | TaggedPtr::Kernel { offset }
            | TaggedPtr::User { offset } => offset,
        }
    }

    pub fn to_raw(self) -> u64 {
        match self {
            TaggedPtr::Map { fd, offset } => Self::map(fd, offset),
            TaggedPtr::Local { offset } => Self::local(offset),
            TaggedPtr::Kernel { offset } => Self::kernel(offset),
            TaggedPtr::User { offset } => Self::user(offset),
        }
    }

    pub fn map(fd: u16, offset: u32) -> u64 {
        TAG_MAP | ((fd as u64) << 40) | offset as u64
    }
    pub fn local(offset: u32) -> u64 {
        TAG_LOCAL | offset as u64
    }
    pub fn kernel(offset: u32) -> u64 {
        TAG_KERNEL | offset as u64
    }
    pub fn user(offset: u32) -> u64 {
        TAG_USER | offset as u64
    }
}

impl Serialize for TaggedPtr {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let len = if matches!(self, TaggedPtr::Map { .. }) {
            3
        } else {
            2
        };
        let mut s = ser.serialize_struct(TAGGED_PTR_NAME, len)?;
        s.serialize_field("region", &self.region())?;
        s.serialize_field("offset", &self.offset())?;
        if let TaggedPtr::Map { fd, .. } = self {
            s.serialize_field("fd", fd)?;
        }
        s.end()
    }
}

impl<'de> Deserialize<'de> for TaggedPtr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            region: TaggetPtrType,
            offset: u32,
            #[serde(default)]
            fd: Option<u16>,
        }
        let h = Helper::deserialize(d)?;
        Ok(match h.region {
            TaggetPtrType::Map => TaggedPtr::Map {
                fd: h.fd.ok_or_else(|| de::Error::missing_field("fd"))?,
                offset: h.offset,
            },
            TaggetPtrType::Local => TaggedPtr::Local { offset: h.offset },
            TaggetPtrType::Kernel => TaggedPtr::Kernel { offset: h.offset },
            TaggetPtrType::User => TaggedPtr::User { offset: h.offset },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_map() {
        let raw = TaggedPtr::map(0xABCD, 0xDEADBEEF);
        match TaggedPtr::decode(raw) {
            TaggedPtr::Map { fd, offset } => {
                assert_eq!(fd, 0xABCD);
                assert_eq!(offset, 0xDEADBEEF);
            }
            other => panic!("expected Map, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_local() {
        let raw = TaggedPtr::local(0x1234_5678);
        match TaggedPtr::decode(raw) {
            TaggedPtr::Local { offset } => assert_eq!(offset, 0x1234_5678),
            other => panic!("expected Local, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_kernel() {
        let raw = TaggedPtr::kernel(0xDEADBEEF);
        match TaggedPtr::decode(raw) {
            TaggedPtr::Kernel { offset } => assert_eq!(offset, 0xDEADBEEF),
            other => panic!("expected Kernel, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_user() {
        let raw = TaggedPtr::user(0xDEADBEEF);
        match TaggedPtr::decode(raw) {
            TaggedPtr::User { offset } => assert_eq!(offset, 0xDEADBEEF),
            other => panic!("expected User, got {other:?}"),
        }
    }

    #[test]
    fn try_decode_invalid_tag() {
        assert!(TaggedPtr::try_decode(0).is_none());
        assert!(TaggedPtr::try_decode(0xF000_0000_0000_0000).is_none());
    }
}
