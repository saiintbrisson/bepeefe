use crate::vm::ptr::TaggetPtrType;

use super::args::{Any, Call, Out};
use super::{BpfHelper, probe_ops};

/// R3 is `ARG_ANYTHING` in Linux: any source value is accepted, with faults
/// surfaced at runtime as `-EFAULT`.
type ProbeArgs = (Out, Any);

pub struct ProbeReadUser;
impl ProbeReadUser {
    pub const ID: i32 = 112;
}
impl BpfHelper for ProbeReadUser {
    type Args = ProbeArgs;

    fn name(&self) -> &'static str {
        "bpf_probe_read_user"
    }

    fn exec(&self, cx: &mut Call<'_>, (dst, src): Self::Args) -> u64 {
        probe_ops::probe_read(cx, TaggetPtrType::User, &dst, src.0) as u64
    }
}

pub struct ProbeReadKernel;
impl ProbeReadKernel {
    pub const ID: i32 = 113;
}
impl BpfHelper for ProbeReadKernel {
    type Args = ProbeArgs;

    fn name(&self) -> &'static str {
        "bpf_probe_read_kernel"
    }

    fn exec(&self, cx: &mut Call<'_>, (dst, src): Self::Args) -> u64 {
        probe_ops::probe_read(cx, TaggetPtrType::Kernel, &dst, src.0) as u64
    }
}

pub struct ProbeReadUserStr;
impl ProbeReadUserStr {
    pub const ID: i32 = 114;
}
impl BpfHelper for ProbeReadUserStr {
    type Args = ProbeArgs;

    fn name(&self) -> &'static str {
        "bpf_probe_read_user_str"
    }

    fn exec(&self, cx: &mut Call<'_>, (dst, src): Self::Args) -> u64 {
        probe_ops::probe_read_str(cx, TaggetPtrType::User, &dst, src.0) as u64
    }
}

pub struct ProbeReadKernelStr;
impl ProbeReadKernelStr {
    pub const ID: i32 = 115;
}
impl BpfHelper for ProbeReadKernelStr {
    type Args = ProbeArgs;

    fn name(&self) -> &'static str {
        "bpf_probe_read_kernel_str"
    }

    fn exec(&self, cx: &mut Call<'_>, (dst, src): Self::Args) -> u64 {
        probe_ops::probe_read_str(cx, TaggetPtrType::Kernel, &dst, src.0) as u64
    }
}
