use super::BpfHelper;
use super::args::{Call, Out};

pub struct KtimeGetNs;
impl KtimeGetNs {
    pub const ID: i32 = 5;
}
impl BpfHelper for KtimeGetNs {
    type Args = ();

    fn name(&self) -> &'static str {
        "bpf_ktime_get_ns"
    }

    fn exec(&self, cx: &mut Call<'_>, (): Self::Args) -> u64 {
        cx.ktime_ns()
    }
}

pub struct GetPrandomU32;
impl GetPrandomU32 {
    pub const ID: i32 = 7;
}
impl BpfHelper for GetPrandomU32 {
    type Args = ();

    fn name(&self) -> &'static str {
        "bpf_get_prandom_u32"
    }

    fn exec(&self, cx: &mut Call<'_>, (): Self::Args) -> u64 {
        cx.prandom_u32() as u64
    }
}

pub struct GetSmpProcessorId;
impl GetSmpProcessorId {
    pub const ID: i32 = 8;
}
impl BpfHelper for GetSmpProcessorId {
    type Args = ();

    fn name(&self) -> &'static str {
        "bpf_get_smp_processor_id"
    }

    fn exec(&self, cx: &mut Call<'_>, (): Self::Args) -> u64 {
        cx.cpu() as u64
    }
}

pub struct GetCurrentPidTgid;
impl GetCurrentPidTgid {
    pub const ID: i32 = 14;
}
impl BpfHelper for GetCurrentPidTgid {
    type Args = ();

    fn name(&self) -> &'static str {
        "bpf_get_current_pid_tgid"
    }

    fn exec(&self, cx: &mut Call<'_>, (): Self::Args) -> u64 {
        cx.task().pid_tgid()
    }
}

/// Writes up to size-1 comm bytes followed by a NUL terminator, unused
/// bytes are zeroed. Returns 0 on success, -EINVAL when size is 0.
pub struct GetCurrentComm;
impl GetCurrentComm {
    pub const ID: i32 = 16;
}
impl BpfHelper for GetCurrentComm {
    type Args = (Out,);

    fn name(&self) -> &'static str {
        "bpf_get_current_comm"
    }

    fn exec(&self, cx: &mut Call<'_>, (buf,): Self::Args) -> u64 {
        let size = buf.size();
        if size == 0 {
            return -22i64 as u64; // EINVAL
        }
        let mut out = Vec::with_capacity(size);
        out.extend(cx.task().comm().iter().copied().take(size - 1));
        out.resize(size, 0);
        cx.write(&buf, &out);
        0
    }
}
