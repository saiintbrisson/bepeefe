use std::alloc::Layout;

use bepeefe::{isa, program, vm};

fn main() {
    let file = std::fs::read("./examples/bpf/map_array.o").unwrap();
    let program = program::load_object(file, "entry");

    let mut vm = vm::Vm::new(program);

    for (idx, insn) in vm.code.code().iter().enumerate() {
        eprintln!(
            "{idx:>2}: {name:<14} ({op:02X?}), src: {src:>2}, dst: {dst:>2}, offset: {offset:>5}, imm: {imm:08X?} ({imm:>5}) ({insn:016X?})",
            name = isa::INSTRUCTION_NAME_TABLE[insn.opcode() as usize],
            op = insn.opcode(),
            dst = insn.dst_reg(),
            src = insn.src_reg(),
            imm = insn.imm(),
            offset = insn.offset(),
            insn = insn.0
        );
    }

    let init_kbs = 3072u64;
    let local_port = 3000u32;

    let val = vm.mem.alloc_layout(Layout::new::<u64>()).unwrap();
    vm.mem
        .write(val.guest_addr(), &init_kbs.to_ne_bytes())
        .unwrap();

    vm.map_by_name("port_map")
        .unwrap()
        .repr
        .update_elem(&local_port.to_ne_bytes(), val.as_ptr().as_ptr())
        .unwrap();

    let sk_buff = __sk_buff {
        len: 2,
        local_port,
        ..Default::default()
    };
    let sk_buff_mem = vm.mem.alloc_layout(Layout::for_value(&sk_buff)).unwrap();
    vm.mem
        .write(sk_buff_mem.guest_addr(), &unsafe {
            std::mem::transmute::<_, [u8; size_of::<__sk_buff>()]>(sk_buff)
        })
        .unwrap();

    vm.registers[1] = sk_buff_mem.guest_addr().0 as u64;

    while !vm.exit {
        let Some(insn) = vm.code.next() else {
            panic!();
        };

        eprintln!(
            "insn @ {pc:>2}: {name:<14} ({op:02X?}), src: {src:>2}, dst: {dst:>2}, offset: {offset:>5}, imm: {imm:08X?} ({imm:>5}) ({insn:016X?})",
            pc = vm.code.pc(),
            name = isa::INSTRUCTION_NAME_TABLE[insn.opcode() as usize],
            op = insn.opcode(),
            dst = insn.dst_reg(),
            src = insn.src_reg(),
            imm = insn.imm(),
            offset = insn.offset(),
            insn = insn.0
        );

        isa::INSTRUCTION_TABLE[insn.opcode() as usize](&mut vm, insn);
    }

    eprintln!("result = {}", vm.registers[0] as i32);
}

#[derive(Default)]
#[repr(C)]
struct __sk_buff {
    len: u32,
    pkt_type: u32,
    mark: u32,
    queue_mapping: u32,
    protocol: u32,
    vlan_present: u32,
    vlan_tci: u32,
    vlan_proto: u32,
    priority: u32,
    ingress_ifindex: u32,
    ifindex: u32,
    tc_index: u32,
    cb: [u32; 5],
    hash: u32,
    tc_classid: u32,
    data: u32,
    data_end: u32,
    napi_id: u32,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [u32; 4],
    local_ip6: [u32; 4],
    remote_port: u32,
    local_port: u32,
    data_meta: u32,
}
