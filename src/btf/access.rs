use std::{borrow::Cow, fmt};

use super::{Btf, BtfKind, BtfTypeId, Struct, StructMember, Union};

/// Error resolving a member path or CO-RE access spec against a BTF type.
#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("access spec {0:?} is not a colon-separated index list")]
    Malformed(String),
    #[error("index {index} is out of range in type {container:?}")]
    OutOfRange { container: BtfTypeId, index: usize },
    #[error("cannot index into type {0:?}: not a struct, union, or array")]
    NotIndexable(BtfTypeId),
    #[error("unknown BTF type {0:?}")]
    UnknownType(BtfTypeId),
}

/// A single step of an [`Access`] path.
#[derive(Debug)]
pub enum Hop<'a> {
    /// Selection of a struct or union member.
    Member {
        container: BtfTypeId,
        index: usize,
        member: &'a StructMember,
        /// Addressable name, `_anon_<index>` for anonymous members.
        name: Cow<'a, str>,
    },
    /// Selection of an array element.
    Element {
        array: BtfTypeId,
        index: usize,
        elem: BtfTypeId,
    },
}

impl Hop<'_> {
    /// Type reached by taking this step.
    pub fn type_id(&self) -> BtfTypeId {
        match self {
            Hop::Member { member, .. } => member.r#type,
            Hop::Element { elem, .. } => *elem,
        }
    }
}

/// A path walked from a root BTF type through nested members and array
/// elements, as encoded by a CO-RE access spec like `0:1:2`.
///
/// The spec's leading index is an array index applied to the root (0 for a
/// plain field access), kept as [`Access::root_index`]. Every later index
/// becomes a [`Hop`], so callers see the whole chain rather than just the leaf.
#[derive(Debug)]
pub struct Access<'a> {
    root: BtfTypeId,
    root_index: usize,
    bit_offset: u32,
    hops: Vec<Hop<'a>>,
}

impl<'a> Access<'a> {
    pub fn root(&self) -> BtfTypeId {
        self.root
    }

    pub fn root_index(&self) -> usize {
        self.root_index
    }

    pub fn hops(&self) -> &[Hop<'a>] {
        &self.hops
    }

    /// Type the path ends at, the root itself when there are no hops.
    pub fn leaf(&self) -> BtfTypeId {
        self.hops.last().map_or(self.root, Hop::type_id)
    }

    /// Bit offset of the leaf from the start of the root.
    pub fn bit_offset(&self) -> u32 {
        self.bit_offset
    }

    pub fn byte_offset(&self) -> u32 {
        self.bit_offset / u8::BITS
    }

    /// Whether the path selects nothing beyond the root.
    pub fn is_empty(&self) -> bool {
        self.root_index == 0 && self.hops.is_empty()
    }
}

impl fmt::Display for Access<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.root_index != 0 {
            write!(f, "[{}]", self.root_index)?;
        }
        for hop in &self.hops {
            match hop {
                Hop::Member { name, .. } => write!(f, ".{name}")?,
                Hop::Element { index, .. } => write!(f, "[{index}]")?,
            }
        }
        Ok(())
    }
}

impl Btf {
    /// Addressable name of the `idx`-th member of a struct or union. Anonymous
    /// members, which carry no name in BTF, take the `_anon_<idx>` placeholder
    /// that [`Value`](super::value::Value) keys them by.
    pub fn member_name(&self, member: &StructMember, idx: usize) -> Cow<'_, str> {
        match self.string(member.name_off) {
            Some(name) if !name.is_empty() => name,
            _ => Cow::Owned(format!("_anon_{idx}")),
        }
    }

    /// Members of the struct or union at `id`, after stripping modifiers.
    /// `None` if the type is not a composite.
    pub fn members(&self, id: BtfTypeId) -> Option<&[StructMember]> {
        match &self.get_type(id)?.kind {
            BtfKind::Struct(Struct { members, .. }) | BtfKind::Union(Union { members, .. }) => {
                Some(members)
            }
            _ => None,
        }
    }

    /// Finds a member of `id` by its addressable name (see
    /// [`Self::member_name`]).
    pub fn member_by_name(&self, id: BtfTypeId, name: &str) -> Option<(usize, &StructMember)> {
        self.members(id)?
            .iter()
            .enumerate()
            .find(|(idx, m)| self.member_name(m, *idx) == name)
    }

    /// Name of the `idx`-th variant of an enum or enum64.
    pub fn enum_variant_name(&self, id: BtfTypeId, idx: usize) -> Option<Cow<'_, str>> {
        match &self.get_type(id)?.kind {
            BtfKind::Enum(e) => self.string(e.values.get(idx)?.name_off),
            BtfKind::Enum64(e) => self.string(e.values.get(idx)?.name_off),
            _ => None,
        }
    }

    /// Parses a CO-RE access spec (`0:1:2`) and resolves it against `root`.
    pub fn parse_access(&self, root: BtfTypeId, spec: &str) -> Result<Access<'_>, AccessError> {
        let parse = |s: &str| {
            s.parse::<usize>()
                .map_err(|_| AccessError::Malformed(spec.to_owned()))
        };
        let mut it = spec.split(':');
        let head = it
            .next()
            .ok_or_else(|| AccessError::Malformed(spec.to_owned()))?;
        let root_index = parse(head)?;
        let indices = it.map(parse).collect::<Result<Vec<_>, _>>()?;
        self.resolve_access(root, root_index, &indices)
    }

    /// Resolves an access-index list against `root`, following struct and union
    /// members and array elements. `root_index` is the CO-RE leading array
    /// index, usually 0.
    pub fn resolve_access(
        &self,
        root: BtfTypeId,
        root_index: usize,
        indices: &[usize],
    ) -> Result<Access<'_>, AccessError> {
        let mut hops = Vec::with_capacity(indices.len());
        let mut bit_offset = 0;
        let mut cur = root;
        for &index in indices {
            let ty = self.get_type(cur).ok_or(AccessError::UnknownType(cur))?;
            match &ty.kind {
                BtfKind::Struct(Struct { members, .. }) | BtfKind::Union(Union { members, .. }) => {
                    let member = members.get(index).ok_or(AccessError::OutOfRange {
                        container: ty.btf_id,
                        index,
                    })?;
                    bit_offset += member.offset;
                    hops.push(Hop::Member {
                        container: ty.btf_id,
                        index,
                        member,
                        name: self.member_name(member, index),
                    });
                    cur = member.r#type;
                }
                BtfKind::Array(array) => {
                    bit_offset += index as u32 * self.type_size(array.r#type) * u8::BITS;
                    hops.push(Hop::Element {
                        array: ty.btf_id,
                        index,
                        elem: array.r#type,
                    });
                    cur = array.r#type;
                }
                _ => return Err(AccessError::NotIndexable(cur)),
            }
        }
        Ok(Access {
            root,
            root_index,
            bit_offset,
            hops,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btf::BtfBuilder;

    fn sk_btf() -> (Btf, BtfTypeId) {
        let mut b = BtfBuilder::default();
        let u32t = b.add_int("u32", 4, 0);
        let inner = b.make_struct("inner", 8, |s| {
            s.field("a", u32t, 0);
            s.field("b", u32t, 32);
        });
        let anon = b.make_union("", 8, |u| {
            u.field("pair", u32t, 0);
            u.field("nested", inner, 0);
        });
        let sk = b.make_struct("sk", 12, |s| {
            s.field("family", u32t, 0);
            s.field("", anon, 32);
        });
        (b.build(), sk)
    }

    #[test]
    fn parse_access_walks_named_members() {
        let (btf, sk) = sk_btf();
        let access = btf.parse_access(sk, "0:0").unwrap();
        assert_eq!(access.to_string(), ".family");
        assert_eq!(access.hops().len(), 1);
        assert_eq!(access.byte_offset(), 0);
    }

    #[test]
    fn parse_access_names_anonymous_members_and_returns_every_hop() {
        let (btf, sk) = sk_btf();
        let access = btf.parse_access(sk, "0:1:1:1").unwrap();
        assert_eq!(access.to_string(), "._anon_1.nested.b");

        let names: Vec<_> = access
            .hops()
            .iter()
            .map(|h| match h {
                Hop::Member { name, .. } => name.to_string(),
                Hop::Element { index, .. } => format!("[{index}]"),
            })
            .collect();
        assert_eq!(names, ["_anon_1", "nested", "b"]);
        assert_eq!(access.byte_offset(), 8);
    }

    #[test]
    fn empty_access_selects_the_root() {
        let (btf, sk) = sk_btf();
        let access = btf.parse_access(sk, "0").unwrap();
        assert!(access.is_empty());
        assert_eq!(access.leaf(), sk);
        assert_eq!(access.to_string(), "");
    }

    #[test]
    fn member_by_name_round_trips_the_naming() {
        let (btf, sk) = sk_btf();
        let (idx, _) = btf.member_by_name(sk, "_anon_1").unwrap();
        assert_eq!(idx, 1);
        assert!(btf.member_by_name(sk, "missing").is_none());
    }

    #[test]
    fn out_of_range_index_errors() {
        let (btf, sk) = sk_btf();
        assert!(matches!(
            btf.parse_access(sk, "0:9"),
            Err(AccessError::OutOfRange { index: 9, .. })
        ));
    }
}
