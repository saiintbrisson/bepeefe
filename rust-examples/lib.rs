#![cfg_attr(target_arch = "bpf", no_std)]
#![allow(clippy::missing_safety_doc)]

use core::ffi::c_void;

pub const BPF_MAP_TYPE_HASH: usize = 1;
pub const BPF_MAP_TYPE_ARRAY: usize = 2;
pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: usize = 4;
pub const BPF_MAP_TYPE_STACK: usize = 23;

pub const BPF_F_CURRENT_CPU: u64 = 0xFFFFFFFF;

#[macro_export]
macro_rules! decl_map {
    ($name:ident { $($field:ident: $val:tt,)+ }) => {
        #[repr(C)]
        pub struct $name {
            $($field: *const decl_map!(field $field: $val)),+
        }
        unsafe impl Sync for $name {}

        #[unsafe(export_name = stringify!($name))]
        #[unsafe(link_section = ".maps")]
        #[allow(non_upper_case_globals)]
        pub static $name: $name = unsafe { core::mem::zeroed() };
    };
    (field key: $ty:ident) => {
        $ty
    };
    (field value: $ty:ident) => {
        $ty
    };
    (field values: $ty:ident) => {
        $ty
    };
    (field $field:ident: $val:expr) => {
        [u8; $val]
    };
}

macro_rules! bpf_helper {
    ($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty = $imm:expr) => {
        #[inline(always)]
        pub unsafe fn $name($($arg: $ty),*) -> $ret {
            let f: extern "C" fn($($ty),*) -> $ret =
                unsafe { core::mem::transmute($imm as usize) };
            f($($arg),*)
        }
    };
}

bpf_helper!(bpf_map_lookup_elem(map: *const c_void, key: *const c_void) -> *mut c_void = 1);
bpf_helper!(bpf_map_update_elem(map: *const c_void, key: *const c_void, value: *const c_void, flags: u64) -> i64 = 2);
bpf_helper!(bpf_map_delete_elem(map: *const c_void, key: *const c_void) -> i64 = 3);
bpf_helper!(bpf_ktime_get_ns() -> u64 = 5);
bpf_helper!(bpf_get_prandom_u32() -> u32 = 7);
bpf_helper!(bpf_get_current_pid_tgid() -> u64 = 14);
bpf_helper!(bpf_get_current_comm(buf: *mut c_void, size: u32) -> i64 = 16);
bpf_helper!(bpf_perf_event_output(ctx: *const c_void, map: *const c_void, flags: u64, data: *const c_void, size: u64) -> i64 = 25);
bpf_helper!(bpf_map_push_elem(map: *const c_void, value: *const c_void, flags: u64) -> i64 = 87);
bpf_helper!(bpf_map_pop_elem(map: *const c_void, value: *mut c_void) -> i64 = 88);
bpf_helper!(bpf_map_peek_elem(map: *const c_void, value: *mut c_void) -> i64 = 89);
bpf_helper!(bpf_probe_read_user(dst: *mut c_void, size: u32, src: *const c_void) -> i64 = 112);
bpf_helper!(bpf_probe_read_kernel(dst: *mut c_void, size: u32, src: *const c_void) -> i64 = 113);
bpf_helper!(bpf_probe_read_user_str(dst: *mut c_void, size: u32, src: *const c_void) -> i64 = 114);
bpf_helper!(bpf_probe_read_kernel_str(dst: *mut c_void, size: u32, src: *const c_void) -> i64 = 115);

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
