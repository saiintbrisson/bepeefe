//! The `maps` subcommand.

use bepeefe::{EbpfObject, maps::*};
use tabled::{
    Tabled,
    settings::{Alignment, Modify, object::Columns},
};

use crate::{render::render_type, table};

#[derive(Tabled)]
struct MapRow {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "TYPE")]
    ty: &'static str,
    #[tabled(rename = "ENTRIES")]
    entries: String,
    #[tabled(rename = "KEY -> VALUE")]
    kv: String,
}

pub fn list(obj: &EbpfObject) {
    let maps = obj.maps();
    if maps.is_empty() {
        println!("(no maps)");
        return;
    }
    let rows: Vec<MapRow> = maps
        .iter()
        .map(|m| {
            let key = m.key.map(|k| render_type(obj.btf(), k)).unwrap_or_else(|| {
                m.key_size
                    .map(|s| format!("[{s} bytes]"))
                    .unwrap_or_else(|| "?".into())
            });
            let val = m
                .value
                .map(|v| render_type(obj.btf(), v))
                .unwrap_or_else(|| {
                    m.value_size
                        .map(|s| format!("[{s} bytes]"))
                        .unwrap_or_else(|| "?".into())
                });
            let key_id = m
                .key
                .map(|k| format!("#{}", k.0))
                .unwrap_or_else(|| "?".into());
            let val_id = m
                .value
                .map(|v| format!("#{}", v.0))
                .unwrap_or_else(|| "?".into());
            MapRow {
                name: m.name.clone(),
                ty: m.r#type.map(map_type_name).unwrap_or("UNKNOWN"),
                entries: m
                    .max_entries
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "?".into()),
                kv: format!("{key} -> {val}  /* {key_id} -> {val_id} */"),
            }
        })
        .collect();

    let mut t = table(rows);
    t.with(Modify::new(Columns::one(2)).with(Alignment::right()));
    println!("{t}");
    crate::hint("next:  maps <name>   inspect one");
}

pub fn show(obj: &EbpfObject, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let map = obj
        .maps()
        .iter()
        .find(|m| m.name == name)
        .ok_or_else(|| format!("map {name:?} not found"))?;

    println!("name:        {}", map.name);
    println!(
        "type:        {}",
        map.r#type.map(map_type_name).unwrap_or("UNKNOWN")
    );
    if let Some(n) = map.max_entries {
        println!("max_entries: {n}");
    }
    if let Some(s) = map.key_size {
        println!("key_size:    {s}");
    }
    if let Some(s) = map.value_size {
        println!("value_size:  {s}");
    }
    if let Some(id) = map.key {
        println!("key:         {}  (#{})", render_type(obj.btf(), id), id.0);
    }
    if let Some(id) = map.value {
        println!("value:       {}  (#{})", render_type(obj.btf(), id), id.0);
    }
    if matches!(map.pinning, MapPinning::ByName) {
        println!("pinning:     by_name");
    }
    if let Some(data) = &map.initial_data {
        println!("initial:     {} bytes", data.len());
    }
    Ok(())
}

fn map_type_name(t: u32) -> &'static str {
    match t {
        BPF_MAP_TYPE_UNSPEC => "UNSPEC",
        BPF_MAP_TYPE_HASH => "HASH",
        BPF_MAP_TYPE_ARRAY => "ARRAY",
        BPF_MAP_TYPE_PROG_ARRAY => "PROG_ARRAY",
        BPF_MAP_TYPE_PERF_EVENT_ARRAY => "PERF_EVENT_ARRAY",
        BPF_MAP_TYPE_PERCPU_HASH => "PERCPU_HASH",
        BPF_MAP_TYPE_PERCPU_ARRAY => "PERCPU_ARRAY",
        BPF_MAP_TYPE_STACK_TRACE => "STACK_TRACE",
        BPF_MAP_TYPE_CGROUP_ARRAY => "CGROUP_ARRAY",
        BPF_MAP_TYPE_LRU_HASH => "LRU_HASH",
        BPF_MAP_TYPE_LRU_PERCPU_HASH => "LRU_PERCPU_HASH",
        BPF_MAP_TYPE_LPM_TRIE => "LPM_TRIE",
        BPF_MAP_TYPE_ARRAY_OF_MAPS => "ARRAY_OF_MAPS",
        BPF_MAP_TYPE_HASH_OF_MAPS => "HASH_OF_MAPS",
        BPF_MAP_TYPE_DEVMAP => "DEVMAP",
        BPF_MAP_TYPE_SOCKMAP => "SOCKMAP",
        BPF_MAP_TYPE_CPUMAP => "CPUMAP",
        BPF_MAP_TYPE_XSKMAP => "XSKMAP",
        BPF_MAP_TYPE_SOCKHASH => "SOCKHASH",
        BPF_MAP_TYPE_CGROUP_STORAGE => "CGROUP_STORAGE",
        BPF_MAP_TYPE_REUSEPORT_SOCKARRAY => "REUSEPORT_SOCKARRAY",
        BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE => "PERCPU_CGROUP_STORAGE",
        BPF_MAP_TYPE_QUEUE => "QUEUE",
        BPF_MAP_TYPE_STACK => "STACK",
        BPF_MAP_TYPE_SK_STORAGE => "SK_STORAGE",
        BPF_MAP_TYPE_DEVMAP_HASH => "DEVMAP_HASH",
        BPF_MAP_TYPE_STRUCT_OPS => "STRUCT_OPS",
        BPF_MAP_TYPE_RINGBUF => "RINGBUF",
        BPF_MAP_TYPE_INODE_STORAGE => "INODE_STORAGE",
        BPF_MAP_TYPE_TASK_STORAGE => "TASK_STORAGE",
        BPF_MAP_TYPE_BLOOM_FILTER => "BLOOM_FILTER",
        BPF_MAP_TYPE_USER_RINGBUF => "USER_RINGBUF",
        BPF_MAP_TYPE_CGRP_STORAGE => "CGRP_STORAGE",
        _ => "UNKNOWN",
    }
}
