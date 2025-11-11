#![allow(dead_code)]

use std::io::{Error, ErrorKind};

use byteorder::{LittleEndian, ReadBytesExt};
use object::{ObjectSection, Section};

use crate::loader::btf::BTF_MAGIC;

#[derive(Debug)]
struct BtfExtHeader {
    version: u8,
    flags: u8,
    hdr_len: u32,

    /* All offsets are in bytes relative to the end of this header */
    func_info_off: u32,
    func_info_len: u32,
    line_info_off: u32,
    line_info_len: u32,

    /* optional part of .BTF.ext header */
    core_relo_off: u32,
    core_relo_len: u32,
}

#[derive(Debug, Default)]
pub struct BtfExt {
    pub func_info: Vec<BtfExtInfoSec<BpfFuncInfo>>,
    pub line_info: Vec<BtfExtInfoSec<BpfLineInfo>>,
    pub core_relo: Vec<BtfExtInfoSec<BpfCoreRelo>>,
}

pub fn load_btf_ext(section: &Section<'_, '_>) -> Option<BtfExt> {
    let data = section.data().unwrap();
    assert_eq!(data[..2], BTF_MAGIC);

    let header_data = &mut &data[2..];
    let header = BtfExtHeader {
        version: header_data.read_u8().unwrap(),
        flags: header_data.read_u8().unwrap(),
        hdr_len: header_data.read_u32::<LittleEndian>().unwrap(),
        func_info_off: header_data.read_u32::<LittleEndian>().unwrap(),
        func_info_len: header_data.read_u32::<LittleEndian>().unwrap(),
        line_info_off: header_data.read_u32::<LittleEndian>().unwrap(),
        line_info_len: header_data.read_u32::<LittleEndian>().unwrap(),
        core_relo_off: header_data.read_u32::<LittleEndian>().unwrap(),
        core_relo_len: header_data.read_u32::<LittleEndian>().unwrap(),
    };

    let mut btf_ext = BtfExt::default();

    let func_info_off = (header.hdr_len + header.func_info_off) as usize;
    let mut func_info_data = &data[func_info_off..func_info_off + header.func_info_len as usize];
    btf_ext.func_info = read_sec_info(&mut func_info_data);

    let line_info_off = (header.hdr_len + header.line_info_off) as usize;
    let mut line_info_data = &data[line_info_off..line_info_off + header.line_info_len as usize];
    btf_ext.line_info = read_sec_info(&mut line_info_data);

    let core_relo_off = (header.hdr_len + header.core_relo_off) as usize;
    let mut core_relo_data = &data[core_relo_off..core_relo_off + header.core_relo_len as usize];
    btf_ext.core_relo = read_sec_info(&mut core_relo_data);

    Some(btf_ext)
}

fn read_sec_info<R: ReadRecord>(data: &mut &[u8]) -> Vec<BtfExtInfoSec<R>> {
    if data.is_empty() {
        return vec![];
    }

    let mut info_vec = Vec::new();
    let record_size = data.read_u32::<LittleEndian>().unwrap() as usize;

    while !data.is_empty() {
        let sec_name_off = data.read_u32::<LittleEndian>().unwrap();
        let num_info = data.read_u32::<LittleEndian>().unwrap() as usize;

        let len = record_size * num_info;
        let mut rec_data = &mut &data[..len];

        let mut records = Vec::with_capacity(num_info as usize);
        for _ in 0..num_info {
            records.push(R::read_record(&mut rec_data).unwrap());
        }

        info_vec.push(BtfExtInfoSec {
            sec_name_off,
            data: records,
        });

        *data = &data[len..];
    }

    info_vec
}

#[derive(Debug)]
pub struct BtfExtInfoSec<R> {
    pub sec_name_off: u32,
    pub data: Vec<R>,
}

trait ReadRecord: Sized {
    fn read_record(buf: &mut &[u8]) -> Result<Self, Error>;
}

#[derive(Debug)]
pub struct BpfFuncInfo {
    pub insn_off: u32, /* [0, insn_cnt - 1] */
    pub type_id: u32,  /* pointing to a BTF_KIND_FUNC type */
}

impl ReadRecord for BpfFuncInfo {
    fn read_record(value: &mut &[u8]) -> Result<Self, Error> {
        Ok(Self {
            insn_off: value.read_u32::<LittleEndian>()?,
            type_id: value.read_u32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
pub struct BpfLineInfo {
    pub insn_off: u32,      /* [0, insn_cnt - 1] */
    pub file_name_off: u32, /* offset to string table for the filename */
    pub line_off: u32,      /* offset to string table for the source line */

    /// File line number
    pub line_no: u32,
    pub column_no: u32,
}

impl ReadRecord for BpfLineInfo {
    fn read_record(value: &mut &[u8]) -> Result<Self, Error> {
        let insn_off = value.read_u32::<LittleEndian>()?;
        let file_name_off = value.read_u32::<LittleEndian>()?;
        let line_off = value.read_u32::<LittleEndian>()?;
        let line_col = value.read_u32::<LittleEndian>()?;
        Ok(Self {
            insn_off,
            file_name_off,
            line_off,

            line_no: line_col >> 10,
            column_no: line_col & 0x3FF,
        })
    }
}

#[derive(Debug)]
pub struct BpfCoreRelo {
    pub insn_off: u32,
    pub type_id: u32,
    pub access_str_off: u32,
    pub kind: BpfCoreReloKind,
}

impl ReadRecord for BpfCoreRelo {
    fn read_record(value: &mut &[u8]) -> Result<Self, Error> {
        Ok(Self {
            insn_off: value.read_u32::<LittleEndian>()?,
            type_id: value.read_u32::<LittleEndian>()?,
            access_str_off: value.read_u32::<LittleEndian>()?,
            kind: match value.read_u32::<LittleEndian>()? {
                0 => BpfCoreReloKind::FieldByteOffset,
                1 => BpfCoreReloKind::FieldByteSize,
                2 => BpfCoreReloKind::FieldExists,
                3 => BpfCoreReloKind::FieldSigned,
                4 => BpfCoreReloKind::FieldLShiftU64,
                5 => BpfCoreReloKind::FieldRShiftU64,
                6 => BpfCoreReloKind::TypeIdLocal,
                7 => BpfCoreReloKind::TypeIdTarget,
                8 => BpfCoreReloKind::TypeExists,
                9 => BpfCoreReloKind::TypeSize,
                10 => BpfCoreReloKind::EnumvalExists,
                11 => BpfCoreReloKind::EnumvalValue,
                12 => BpfCoreReloKind::TypeMatches,
                _ => return Err(Error::from(ErrorKind::InvalidData)),
            },
        })
    }
}

#[repr(C)]
#[derive(Debug)]
pub enum BpfCoreReloKind {
    FieldByteOffset = 0, /* field byte offset */
    FieldByteSize = 1,   /* field size in bytes */
    FieldExists = 2,     /* field existence in target kernel */
    FieldSigned = 3,     /* field signedness (0 - unsigned, 1 - signed) */
    FieldLShiftU64 = 4,  /* bitfield-specific left bitshift */
    FieldRShiftU64 = 5,  /* bitfield-specific right bitshift */
    TypeIdLocal = 6,     /* type ID in local BPF object */
    TypeIdTarget = 7,    /* type ID in target kernel */
    TypeExists = 8,      /* type existence in target kernel */
    TypeSize = 9,        /* type size in bytes */
    EnumvalExists = 10,  /* enum value existence in target kernel */
    EnumvalValue = 11,   /* enum value integer value */
    TypeMatches = 12,    /* type match in target kernel */
}
