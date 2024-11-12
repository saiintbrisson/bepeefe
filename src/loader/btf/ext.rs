#![allow(dead_code)]

use std::io::Read;

use byteorder::{LittleEndian, ReadBytesExt};
use object::{Object, ObjectSection};

use crate::loader::{btf::BTF_MAGIC, Loader};

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
    pub func_info: Vec<BtfExtInfoSec>,
    pub line_info: Vec<BtfExtInfoSec>,
    pub core_relo: Vec<BtfExtInfoSec>,
}

impl<'data> Loader<'data> {
    pub fn load_btf_ext(&self) -> Option<BtfExt> {
        let section = self.file.section_by_name(".BTF.ext")?;

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
        let mut func_info_data =
            &data[func_info_off..func_info_off + header.func_info_len as usize];
        btf_ext.func_info = read_sec_info(&mut func_info_data);

        let line_info_off = (header.hdr_len + header.line_info_off) as usize;
        let mut line_info_data =
            &data[line_info_off..line_info_off + header.line_info_len as usize];
        btf_ext.line_info = read_sec_info(&mut line_info_data);

        let core_relo_off = (header.hdr_len + header.core_relo_off) as usize;
        let mut core_relo_data =
            &data[core_relo_off..core_relo_off + header.core_relo_len as usize];
        btf_ext.core_relo = read_sec_info(&mut core_relo_data);

        Some(btf_ext)
    }
}

fn read_sec_info(data: &mut &[u8]) -> Vec<BtfExtInfoSec> {
    if data.is_empty() {
        return vec![];
    }

    let mut info_vec = Vec::new();
    let record_size = data.read_u32::<LittleEndian>().unwrap();
    while !data.is_empty() {
        let sec_name_off = data.read_u32::<LittleEndian>().unwrap();
        let num_info = data.read_u32::<LittleEndian>().unwrap();
        let mut sec_info_data = vec![0; record_size as usize * num_info as usize];
        data.read_exact(&mut sec_info_data).unwrap();
        info_vec.push(BtfExtInfoSec {
            sec_name_off,
            num_info,
            data: sec_info_data,
        })
    }

    info_vec
}

#[derive(Debug)]
pub struct BtfExtInfoSec {
    pub sec_name_off: u32, /* offset to section name */
    pub num_info: u32,
    /* Followed by num_info * record_size number of bytes */
    pub data: Vec<u8>,
}

pub struct BpfCoreRelo {
    pub insn_off: u32,
    pub type_id: u32,
    pub access_str_off: u32,
    pub kind: BpfCoreReloKind,
}

#[repr(C)]
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
