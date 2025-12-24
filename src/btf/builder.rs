use super::*;

#[derive(Default)]
pub struct BtfBuilder {
    inner: Btf,
}

impl BtfBuilder {
    pub fn build(self) -> Btf {
        self.inner
    }

    fn next_type_id(&self) -> BtfTypeId {
        BtfTypeId(self.inner.types.len() as u32 + 1)
    }

    fn add_string(&mut self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }

        if let Some(off) = self.inner.find_name(s) {
            return off;
        }

        let offset = self.inner.strings.len() as u32;
        self.inner.strings.extend(s.as_bytes());
        self.inner.strings.push(0);
        offset
    }

    fn insert_type(&mut self, name_off: u32, kind: BtfKind) -> BtfTypeId {
        debug_assert!(
            name_off == 0 || self.inner.name(name_off).is_some(),
            "name_off {name_off} not in string table"
        );

        let btf_id = self.next_type_id();
        self.inner.types.insert(
            btf_id,
            BtfType {
                btf_id,
                name_off,
                kind,
            },
        );
        btf_id
    }

    pub fn add_int(&mut self, name: &str, size: u32, encoding: u8) -> BtfTypeId {
        let name_off = self.add_string(name);
        self.insert_type(
            name_off,
            BtfKind::Int(Int {
                size,
                encoding,
                offset: 0,
                bits: (size * 8) as u8,
            }),
        )
    }

    pub fn add_ptr(&mut self, pointee: BtfTypeId) -> BtfTypeId {
        self.insert_type(0, BtfKind::Ptr(pointee))
    }

    pub fn add_array(&mut self, elem: BtfTypeId, index: BtfTypeId, len: u32) -> BtfTypeId {
        self.insert_type(
            0,
            BtfKind::Array(Array {
                r#type: elem,
                index_type: index,
                no_elems: len,
            }),
        )
    }

    pub fn add_typedef(&mut self, name: &str, target: BtfTypeId) -> BtfTypeId {
        let name_off = self.add_string(name);
        self.insert_type(name_off, BtfKind::Typedef(target))
    }

    pub fn add_const(&mut self, target: BtfTypeId) -> BtfTypeId {
        self.insert_type(0, BtfKind::Const(target))
    }

    pub fn add_volatile(&mut self, target: BtfTypeId) -> BtfTypeId {
        self.insert_type(0, BtfKind::Volatile(target))
    }

    pub fn add_restrict(&mut self, target: BtfTypeId) -> BtfTypeId {
        self.insert_type(0, BtfKind::Restrict(target))
    }

    pub fn add_float(&mut self, name: &str, size: u32) -> BtfTypeId {
        let name_off = self.add_string(name);
        self.insert_type(name_off, BtfKind::Float(Float { size }))
    }

    pub fn add_fwd(&mut self, name: &str, is_union: bool) -> BtfTypeId {
        let name_off = self.add_string(name);
        self.insert_type(
            name_off,
            BtfKind::Fwd(Fwd {
                kind_flag: is_union,
            }),
        )
    }

    pub fn add_func(&mut self, name: &str, proto: BtfTypeId, linkage: FuncLinkage) -> BtfTypeId {
        let name_off = self.add_string(name);
        self.insert_type(
            name_off,
            BtfKind::Func(Func {
                func_proto: proto,
                linkage,
            }),
        )
    }

    pub fn add_var(&mut self, name: &str, ty: BtfTypeId, linkage: VariableLinkage) -> BtfTypeId {
        let name_off = self.add_string(name);
        self.insert_type(
            name_off,
            BtfKind::Var(Var {
                ty,
                variable: Variable { linkage },
            }),
        )
    }

    pub fn make_struct<F>(&mut self, name: &str, size: u32, f: F) -> BtfTypeId
    where
        F: FnOnce(&mut StructBuilder),
    {
        let mut builder = StructBuilder::default();
        f(&mut builder);

        let members = builder
            .fields
            .into_iter()
            .map(|(name, ty, offset)| StructMember {
                name_off: self.add_string(&name),
                r#type: ty,
                bitfield_size: None,
                offset,
            })
            .collect();

        let name_off = self.add_string(name);
        self.insert_type(name_off, BtfKind::Struct(Struct { members, size }))
    }

    pub fn make_union<F>(&mut self, name: &str, size: u32, f: F) -> BtfTypeId
    where
        F: FnOnce(&mut StructBuilder),
    {
        let mut builder = StructBuilder::default();
        f(&mut builder);

        let members = builder
            .fields
            .into_iter()
            .map(|(name, ty, offset)| StructMember {
                name_off: self.add_string(&name),
                r#type: ty,
                bitfield_size: None,
                offset,
            })
            .collect();

        let name_off = self.add_string(name);
        self.insert_type(name_off, BtfKind::Union(Union { members, size }))
    }

    pub fn make_enum<F>(&mut self, name: &str, size: u32, signed: bool, f: F) -> BtfTypeId
    where
        F: FnOnce(&mut EnumBuilder),
    {
        let mut builder = EnumBuilder::default();
        f(&mut builder);

        let values = builder
            .values
            .into_iter()
            .map(|(name, val)| EnumValue {
                name_off: self.add_string(&name),
                val,
            })
            .collect();

        let name_off = self.add_string(name);
        self.insert_type(
            name_off,
            BtfKind::Enum(Enum {
                signed,
                size,
                values,
            }),
        )
    }

    pub fn make_enum64<F>(&mut self, name: &str, size: u32, signed: bool, f: F) -> BtfTypeId
    where
        F: FnOnce(&mut Enum64Builder),
    {
        let mut builder = Enum64Builder::default();
        f(&mut builder);

        let values = builder
            .values
            .into_iter()
            .map(|(name, val)| Enum64Value {
                name_off: self.add_string(&name),
                val_lo32: val as u32,
                val_hi32: (val >> 32) as u32,
            })
            .collect();

        let name_off = self.add_string(name);
        self.insert_type(
            name_off,
            BtfKind::Enum64(Enum64 {
                signed,
                size,
                values,
            }),
        )
    }

    pub fn make_func_proto<F>(&mut self, return_type: BtfTypeId, f: F) -> BtfTypeId
    where
        F: FnOnce(&mut FuncProtoBuilder),
    {
        let mut builder = FuncProtoBuilder::default();
        f(&mut builder);

        let params = builder
            .params
            .into_iter()
            .map(|(name, ty)| Param {
                name_off: self.add_string(&name),
                r#type: ty,
            })
            .collect();

        self.insert_type(
            0,
            BtfKind::FuncProto(FuncProto {
                params,
                return_type,
            }),
        )
    }

    pub fn make_datasec<F>(&mut self, name: &str, size: u32, f: F) -> BtfTypeId
    where
        F: FnOnce(&mut DatasecBuilder),
    {
        let mut builder = DatasecBuilder::default();
        f(&mut builder);

        let secinfos = builder
            .vars
            .into_iter()
            .map(|(ty, offset, size)| VarSecInfo {
                r#type: ty,
                offset,
                size,
            })
            .collect();

        let name_off = self.add_string(name);
        self.insert_type(name_off, BtfKind::Datasec(Datasec { secinfos, size }))
    }
}

impl From<Btf> for BtfBuilder {
    fn from(btf: Btf) -> Self {
        Self { inner: btf }
    }
}

#[derive(Default)]
pub struct StructBuilder {
    fields: Vec<(String, BtfTypeId, u32)>,
}

impl StructBuilder {
    pub fn field(&mut self, name: &str, ty: BtfTypeId, offset: u32) -> &mut Self {
        self.fields.push((name.to_owned(), ty, offset));
        self
    }
}

#[derive(Default)]
pub struct EnumBuilder {
    values: Vec<(String, i32)>,
}

impl EnumBuilder {
    pub fn value(&mut self, name: &str, val: i32) -> &mut Self {
        self.values.push((name.to_owned(), val));
        self
    }
}

#[derive(Default)]
pub struct Enum64Builder {
    values: Vec<(String, i64)>,
}

impl Enum64Builder {
    pub fn value(&mut self, name: &str, val: i64) -> &mut Self {
        self.values.push((name.to_owned(), val));
        self
    }
}

#[derive(Default)]
pub struct FuncProtoBuilder {
    params: Vec<(String, BtfTypeId)>,
}

impl FuncProtoBuilder {
    pub fn param(&mut self, name: &str, ty: BtfTypeId) -> &mut Self {
        self.params.push((name.to_owned(), ty));
        self
    }
}

#[derive(Default)]
pub struct DatasecBuilder {
    vars: Vec<(BtfTypeId, u32, u32)>,
}

impl DatasecBuilder {
    pub fn var(&mut self, ty: BtfTypeId, offset: u32, size: u32) -> &mut Self {
        self.vars.push((ty, offset, size));
        self
    }
}
