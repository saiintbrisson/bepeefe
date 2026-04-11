#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum ProgType {
    CgroupDevice,
    CgroupSkb,
    CgroupSockopt,
    CgroupSockAddr,
    CgroupSock,
    CgroupSysctl,
    /// freplace
    Ext,
    FlowDissector,
    Kprobe,
    LircMode2,
    Lsm,
    LwtIn,
    LwtOut,
    LwtSeg6local,
    LwtXmit,
    Netfilter,
    PerfEvent,
    RawTracepointWritable,
    RawTracepoint,
    /// action
    SchedAct,
    SchedCls,
    SkLookup,
    SkMsg,
    SkReuseport,
    SkSkb,
    /// socket
    SocketFilter,
    /// sockops
    SockOps,
    StructOps,
    /// syscall, sleepable
    Syscall,
    Tracepoint,
    Tracing,
    Xdp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum CgroupSkb {
    /// cgroup/skb
    Skb,
    /// cgroup_skb/egress
    InetEgress,
    /// cgroup_skb/ingress
    InetIngress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum CgroupSockopt {
    /// cgroup/getsockopt
    Getsockopt,
    /// cgroup/setsockopt
    Setsockopt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum CgroupSockAddr {
    /// cgroup/bind4
    Inet4Bind,
    /// cgroup/connect4
    Inet4Connect,
    /// cgroup/getpeername4
    Inet4Getpeername,
    /// cgroup/getsockname4
    Inet4Getsockname,
    /// cgroup/bind6
    Inet6Bind,
    /// cgroup/connect6
    Inet6Connect,
    /// cgroup/getpeername6
    Inet6Getpeername,
    /// cgroup/getsockname6
    Inet6Getsockname,
    /// cgroup/recvmsg4
    Udp4Recvmsg,
    /// cgroup/sendmsg4
    Udp4Sendmsg,
    /// cgroup/recvmsg6
    Udp6Recvmsg,
    /// cgroup/sendmsg6
    Udp6Sendmsg,
    /// cgroup/connect_unix
    UnixConnect,
    /// cgroup/sendmsg_unix
    UnixSendmsg,
    /// cgroup/recvmsg_unix
    UnixRecvmsg,
    /// cgroup/getpeername_unix
    UnixGetpeername,
    /// cgroup/getsockname_unix
    UnixGetsockname,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum CgroupSock {
    /// cgroup/sock
    Sock,
    /// cgroup/post_bind4
    Inet4PostBind,
    /// cgroup/post_bind6
    Inet6PostBind,
    /// cgroup/sock_create
    InetSockCreate,
    /// cgroup/sock_release
    InetSockRelease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Kprobe {
    /// kprobe/<func>
    Kprobe,
    /// kretprobe/<func>
    Kretprobe,
    /// ksyscall/<name>
    Ksyscall,
    /// kretsyscall/<name>
    Kretsyscall,
    /// uprobe/<binary>:<func>
    Uprobe,
    /// uprobe.s/<binary>:<func>, sleepable
    UprobeS,
    /// uretprobe/<binary>:<func>
    Uretprobe,
    /// uretprobe.s/<binary>:<func>, sleepable
    UretprobeS,
    /// usdt/<binary>:<provider>:<name>
    Usdt,
    /// kprobe.multi/<pattern>
    KprobeMulti,
    /// kretprobe.multi/<pattern>
    KretprobeMulti,
}

/// Linux Security Module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Lsm {
    /// lsm_cgroup/<hook>
    Cgroup,
    /// lsm/<hook>
    Mac,
    /// lsm.s/<hook>, sleepable
    MacS,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum RawTracepointWritable {
    /// raw_tp.w/<name>
    RawTpW,
    /// raw_tracepoint.w/<name>
    RawTracepointW,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum RawTracepoint {
    /// raw_tp/<name>
    RawTp,
    /// raw_tracepoint/<name>
    RawTracepoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum SchedCls {
    /// classifier
    Classifier,
    /// tc
    Tc,
    /// netkit/primary
    NetkitPrimary,
    /// netkit/peer
    NetkitPeer,
    /// tc/ingress
    TcIngress,
    /// tc/egress
    TcEgress,
    /// tcx/ingress
    TcxIngress,
    /// tcx/egress
    TcxEgress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Tracing {
    /// fentry/<func>
    Fentry,
    /// fexit/<func>
    Fexit,
    /// fmod_ret/<func>
    FmodRet,
    /// iter/<iter_type>
    Iter,
    /// tp_btf/<tracepoint>
    TpBtf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Xdp {
    /// xdp
    Xdp,
    /// xdp/cpumap
    Cpumap,
    /// xdp/devmap
    Devmap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum SkSkb {
    /// sk_skb
    SkSkb,
    /// sk_skb/stream_parser
    StreamParser,
    /// sk_skb/stream_verdict
    StreamVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum SkReuseport {
    /// sk_reuseport
    Select,
    /// sk_reuseport/migrate
    SelectOrMigrate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Attach {
    None,
    CgroupSkb(CgroupSkb),
    CgroupSockopt(CgroupSockopt),
    CgroupSockAddr(CgroupSockAddr),
    CgroupSock(CgroupSock),
    Kprobe(Kprobe),
    Lsm(Lsm),
    RawTracepoint(RawTracepoint),
    RawTracepointWritable(RawTracepointWritable),
    SchedCls(SchedCls),
    Tracing(Tracing),
    Xdp(Xdp),
    SkSkb(SkSkb),
    SkReuseport(SkReuseport),
}

/// A parsed `SEC(...)` annotation: the kernel program type, the refined
/// attach point (when the SEC format encodes one), the free-form target
/// that follows a `/` (e.g. the kernel function for a kprobe), plus the
/// original string for UI display.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Hook {
    pub prog_type: ProgType,
    pub attach: Attach,
    pub target: Option<String>,
    pub sleepable: bool,
    pub frags: bool,
    pub raw: String,
}

impl Hook {
    pub fn parse(raw: &str) -> Option<Hook> {
        if let Some((prog_type, attach, sleepable, frags)) = match_exact(raw) {
            return Some(Hook {
                prog_type,
                attach,
                target: None,
                sleepable,
                frags,
                raw: raw.to_string(),
            });
        }

        let (prefix, target) = match raw.split_once('/') {
            Some((p, t)) => (p, Some(t.to_string())),
            None => (raw, None),
        };
        let (prog_type, attach, sleepable, frags) = match_prefix(prefix)?;
        Some(Hook {
            prog_type,
            attach,
            target,
            sleepable,
            frags,
            raw: raw.to_string(),
        })
    }

    /// What the program is attached to, for display. Falls back to
    /// the raw SEC string when there's no explicit target.
    pub fn hooked_to(&self) -> &str {
        self.target.as_deref().unwrap_or(&self.raw)
    }
}

impl std::fmt::Display for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

type Matched = (ProgType, Attach, bool, bool);

fn match_exact(raw: &str) -> Option<Matched> {
    use ProgType as P;

    fn cgroup_sock_addr(a: CgroupSockAddr) -> (P, Attach) {
        (ProgType::CgroupSockAddr, Attach::CgroupSockAddr(a))
    }

    fn cgroup_sock(a: CgroupSock) -> (P, Attach) {
        (ProgType::CgroupSock, Attach::CgroupSock(a))
    }

    let (prog, attach) = match raw {
        "cgroup/dev" => (P::CgroupDevice, Attach::None),

        "cgroup/skb" => (P::CgroupSkb, Attach::CgroupSkb(CgroupSkb::Skb)),
        "cgroup_skb/ingress" => (P::CgroupSkb, Attach::CgroupSkb(CgroupSkb::InetIngress)),
        "cgroup_skb/egress" => (P::CgroupSkb, Attach::CgroupSkb(CgroupSkb::InetEgress)),

        "cgroup/getsockopt" => (
            P::CgroupSockopt,
            Attach::CgroupSockopt(CgroupSockopt::Getsockopt),
        ),
        "cgroup/setsockopt" => (
            P::CgroupSockopt,
            Attach::CgroupSockopt(CgroupSockopt::Setsockopt),
        ),

        "cgroup/bind4" => cgroup_sock_addr(CgroupSockAddr::Inet4Bind),
        "cgroup/bind6" => cgroup_sock_addr(CgroupSockAddr::Inet6Bind),
        "cgroup/connect4" => cgroup_sock_addr(CgroupSockAddr::Inet4Connect),
        "cgroup/connect6" => cgroup_sock_addr(CgroupSockAddr::Inet6Connect),
        "cgroup/getpeername4" => cgroup_sock_addr(CgroupSockAddr::Inet4Getpeername),
        "cgroup/getpeername6" => cgroup_sock_addr(CgroupSockAddr::Inet6Getpeername),
        "cgroup/getsockname4" => cgroup_sock_addr(CgroupSockAddr::Inet4Getsockname),
        "cgroup/getsockname6" => cgroup_sock_addr(CgroupSockAddr::Inet6Getsockname),
        "cgroup/sendmsg4" => cgroup_sock_addr(CgroupSockAddr::Udp4Sendmsg),
        "cgroup/sendmsg6" => cgroup_sock_addr(CgroupSockAddr::Udp6Sendmsg),
        "cgroup/recvmsg4" => cgroup_sock_addr(CgroupSockAddr::Udp4Recvmsg),
        "cgroup/recvmsg6" => cgroup_sock_addr(CgroupSockAddr::Udp6Recvmsg),
        "cgroup/connect_unix" => cgroup_sock_addr(CgroupSockAddr::UnixConnect),
        "cgroup/sendmsg_unix" => cgroup_sock_addr(CgroupSockAddr::UnixSendmsg),
        "cgroup/recvmsg_unix" => cgroup_sock_addr(CgroupSockAddr::UnixRecvmsg),
        "cgroup/getpeername_unix" => cgroup_sock_addr(CgroupSockAddr::UnixGetpeername),
        "cgroup/getsockname_unix" => cgroup_sock_addr(CgroupSockAddr::UnixGetsockname),

        "cgroup/sock" => cgroup_sock(CgroupSock::Sock),
        "cgroup/post_bind4" => cgroup_sock(CgroupSock::Inet4PostBind),
        "cgroup/post_bind6" => cgroup_sock(CgroupSock::Inet6PostBind),
        "cgroup/sock_create" => cgroup_sock(CgroupSock::InetSockCreate),
        "cgroup/sock_release" => cgroup_sock(CgroupSock::InetSockRelease),

        "cgroup/sysctl" => (P::CgroupSysctl, Attach::None),

        "flow_dissector" => (P::FlowDissector, Attach::None),
        "lirc_mode2" => (P::LircMode2, Attach::None),

        "lwt_in" => (P::LwtIn, Attach::None),
        "lwt_out" => (P::LwtOut, Attach::None),
        "lwt_seg6local" => (P::LwtSeg6local, Attach::None),
        "lwt_xmit" => (P::LwtXmit, Attach::None),

        "netfilter" => (P::Netfilter, Attach::None),
        "perf_event" => (P::PerfEvent, Attach::None),
        "action" => (P::SchedAct, Attach::None),

        "classifier" => (P::SchedCls, Attach::SchedCls(SchedCls::Classifier)),
        "tc" => (P::SchedCls, Attach::SchedCls(SchedCls::Tc)),
        "tc/ingress" => (P::SchedCls, Attach::SchedCls(SchedCls::TcIngress)),
        "tc/egress" => (P::SchedCls, Attach::SchedCls(SchedCls::TcEgress)),
        "tcx/ingress" => (P::SchedCls, Attach::SchedCls(SchedCls::TcxIngress)),
        "tcx/egress" => (P::SchedCls, Attach::SchedCls(SchedCls::TcxEgress)),
        "netkit/primary" => (P::SchedCls, Attach::SchedCls(SchedCls::NetkitPrimary)),
        "netkit/peer" => (P::SchedCls, Attach::SchedCls(SchedCls::NetkitPeer)),

        "sk_lookup" => (P::SkLookup, Attach::None),
        "sk_msg" => (P::SkMsg, Attach::None),

        "sk_reuseport" => (P::SkReuseport, Attach::SkReuseport(SkReuseport::Select)),
        "sk_reuseport/migrate" => (
            P::SkReuseport,
            Attach::SkReuseport(SkReuseport::SelectOrMigrate),
        ),

        "sk_skb" => (P::SkSkb, Attach::SkSkb(SkSkb::SkSkb)),
        "sk_skb/stream_parser" => (P::SkSkb, Attach::SkSkb(SkSkb::StreamParser)),
        "sk_skb/stream_verdict" => (P::SkSkb, Attach::SkSkb(SkSkb::StreamVerdict)),

        "socket" => (P::SocketFilter, Attach::None),
        "sockops" => (P::SockOps, Attach::None),
        "syscall" => (P::Syscall, Attach::None),

        "xdp" => (P::Xdp, Attach::Xdp(Xdp::Xdp)),
        "xdp.frags" => (P::Xdp, Attach::Xdp(Xdp::Xdp)),
        "xdp/cpumap" => (P::Xdp, Attach::Xdp(Xdp::Cpumap)),
        "xdp.frags/cpumap" => (P::Xdp, Attach::Xdp(Xdp::Cpumap)),
        "xdp/devmap" => (P::Xdp, Attach::Xdp(Xdp::Devmap)),
        "xdp.frags/devmap" => (P::Xdp, Attach::Xdp(Xdp::Devmap)),

        _ => return None,
    };

    let frags = raw.contains(".frags");

    Some((prog, attach, false, frags))
}

fn match_prefix(prefix: &str) -> Option<Matched> {
    use ProgType as P;

    let (prog, attach) = match prefix {
        "freplace" => (P::Ext, Attach::None),

        "kprobe" => (P::Kprobe, Attach::Kprobe(Kprobe::Kprobe)),
        "kretprobe" => (P::Kprobe, Attach::Kprobe(Kprobe::Kretprobe)),
        "ksyscall" => (P::Kprobe, Attach::Kprobe(Kprobe::Ksyscall)),
        "kretsyscall" => (P::Kprobe, Attach::Kprobe(Kprobe::Kretsyscall)),
        "uprobe" => (P::Kprobe, Attach::Kprobe(Kprobe::Uprobe)),
        "uprobe.s" => (P::Kprobe, Attach::Kprobe(Kprobe::UprobeS)),
        "uretprobe" => (P::Kprobe, Attach::Kprobe(Kprobe::Uretprobe)),
        "uretprobe.s" => (P::Kprobe, Attach::Kprobe(Kprobe::UretprobeS)),
        "usdt" => (P::Kprobe, Attach::Kprobe(Kprobe::Usdt)),
        "kprobe.multi" => (P::Kprobe, Attach::Kprobe(Kprobe::KprobeMulti)),
        "kretprobe.multi" => (P::Kprobe, Attach::Kprobe(Kprobe::KretprobeMulti)),

        "lsm" => (P::Lsm, Attach::Lsm(Lsm::Mac)),
        "lsm.s" => (P::Lsm, Attach::Lsm(Lsm::MacS)),
        "lsm_cgroup" => (P::Lsm, Attach::Lsm(Lsm::Cgroup)),

        "raw_tp" => (
            P::RawTracepoint,
            Attach::RawTracepoint(RawTracepoint::RawTp),
        ),
        "raw_tracepoint" => (
            P::RawTracepoint,
            Attach::RawTracepoint(RawTracepoint::RawTracepoint),
        ),
        "raw_tp.w" => (
            P::RawTracepointWritable,
            Attach::RawTracepointWritable(RawTracepointWritable::RawTpW),
        ),
        "raw_tracepoint.w" => (
            P::RawTracepointWritable,
            Attach::RawTracepointWritable(RawTracepointWritable::RawTracepointW),
        ),

        "struct_ops" => (P::StructOps, Attach::None),
        "struct_ops.s" => (P::StructOps, Attach::None),

        "tp" | "tracepoint" => (P::Tracepoint, Attach::None),

        "fentry" => (P::Tracing, Attach::Tracing(Tracing::Fentry)),
        "fentry.s" => (P::Tracing, Attach::Tracing(Tracing::Fentry)),
        "fexit" => (P::Tracing, Attach::Tracing(Tracing::Fexit)),
        "fexit.s" => (P::Tracing, Attach::Tracing(Tracing::Fexit)),
        "fmod_ret" => (P::Tracing, Attach::Tracing(Tracing::FmodRet)),
        "fmod_ret.s" => (P::Tracing, Attach::Tracing(Tracing::FmodRet)),
        "iter" => (P::Tracing, Attach::Tracing(Tracing::Iter)),
        "iter.s" => (P::Tracing, Attach::Tracing(Tracing::Iter)),
        "tp_btf" => (P::Tracing, Attach::Tracing(Tracing::TpBtf)),

        _ => return None,
    };

    let sleepable = prefix.ends_with(".s");

    Some((prog, attach, sleepable, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_match_no_target() {
        let h = Hook::parse("cgroup/dev").unwrap();
        assert_eq!(h.prog_type, ProgType::CgroupDevice);
        assert_eq!(h.attach, Attach::None);
        assert_eq!(h.target, None);
    }

    #[test]
    fn kprobe_with_target() {
        let h = Hook::parse("kprobe/__x64_sys_openat").unwrap();
        assert_eq!(h.prog_type, ProgType::Kprobe);
        assert_eq!(h.attach, Attach::Kprobe(Kprobe::Kprobe));
        assert_eq!(h.target.as_deref(), Some("__x64_sys_openat"));
        assert!(!h.sleepable);
        assert_eq!(h.hooked_to(), "__x64_sys_openat");
    }

    #[test]
    fn uprobe_sleepable_with_colon_target() {
        let h = Hook::parse("uprobe.s/libc:malloc").unwrap();
        assert_eq!(h.prog_type, ProgType::Kprobe);
        assert_eq!(h.attach, Attach::Kprobe(Kprobe::UprobeS));
        assert!(h.sleepable);
        assert_eq!(h.target.as_deref(), Some("libc:malloc"));
    }

    #[test]
    fn tc_ingress_is_exact_not_prefix() {
        let h = Hook::parse("tc/ingress").unwrap();
        assert_eq!(h.attach, Attach::SchedCls(SchedCls::TcIngress));
        assert_eq!(h.target, None);
    }

    #[test]
    fn tracepoint_target_contains_slash() {
        let h = Hook::parse("tracepoint/syscalls/sys_enter_openat").unwrap();
        assert_eq!(h.prog_type, ProgType::Tracepoint);
        assert_eq!(h.target.as_deref(), Some("syscalls/sys_enter_openat"));
    }

    #[test]
    fn tp_alias_works() {
        let h = Hook::parse("tp/sched/sched_switch").unwrap();
        assert_eq!(h.prog_type, ProgType::Tracepoint);
        assert_eq!(h.target.as_deref(), Some("sched/sched_switch"));
    }

    #[test]
    fn xdp_frags_devmap() {
        let h = Hook::parse("xdp.frags/devmap").unwrap();
        assert_eq!(h.prog_type, ProgType::Xdp);
        assert_eq!(h.attach, Attach::Xdp(Xdp::Devmap));
        assert!(h.frags);
        assert_eq!(h.target, None);
    }

    #[test]
    fn fentry_sleepable() {
        let h = Hook::parse("fentry.s/vfs_read").unwrap();
        assert_eq!(h.prog_type, ProgType::Tracing);
        assert_eq!(h.attach, Attach::Tracing(Tracing::Fentry));
        assert!(h.sleepable);
        assert_eq!(h.target.as_deref(), Some("vfs_read"));
    }

    #[test]
    fn lsm_vs_lsm_cgroup() {
        let a = Hook::parse("lsm/file_open").unwrap();
        let b = Hook::parse("lsm_cgroup/file_open").unwrap();
        assert_eq!(a.attach, Attach::Lsm(Lsm::Mac));
        assert_eq!(b.attach, Attach::Lsm(Lsm::Cgroup));
    }

    #[test]
    fn unknown_returns_none() {
        assert!(Hook::parse("bogus/thing").is_none());
        assert!(Hook::parse("").is_none());
    }

    #[test]
    fn raw_preserved_for_display() {
        let h = Hook::parse("kprobe/do_sys_open").unwrap();
        assert_eq!(h.raw, "kprobe/do_sys_open");
        assert_eq!(h.to_string(), "kprobe/do_sys_open");
    }
}
