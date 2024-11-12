pub enum ProgType {
    /// cgroup/dev
    CGROUP_DEVICE,
    CGROUP_SKB,
    CGROUP_SOCKOPT,
    CGROUP_SOCK_ADDR,
    CGROUP_SOCK,
    /// cgroup/sysctl
    CGROUP_SYSCTL,
    /// freplace+ [#fentry]_
    EXT,
    /// flow_dissector
    FLOW_DISSECTOR,
    KPROBE,
    /// lirc_mode2
    LIRC_MODE2,
    LSM,
    /// lwt_in
    LWT_IN,
    /// lwt_out
    LWT_OUT,
    /// lwt_seg6local
    LWT_SEG6LOCAL,
    /// lwt_xmit
    LWT_XMIT,
    /// netfilter
    NETFILTER,
    /// perf_event
    PERF_EVENT,
    RAW_TRACEPOINT_WRITABLE,
    RAW_TRACEPOINT,
    /// action [#tc_legacy]_
    SCHED_ACT,
    SCHED_CLS,
    /// sk_lookup
    SK_LOOKUP,
    /// sk_msg / BPF_SK_MSG_VERDICT
    SK_MSG,
    SK_REUSEPORT, /* | BPF_SK_REUSEPORT_SELECT_OR_MIGRATE, | sk_reuseport/migrate, | |
                  | | BPF_SK_REUSEPORT_SELECT, | sk_reuseport, | | */
    SK_SKB,        /* | | sk_skb, | |
                   | | BPF_SK_SKB_STREAM_PARSER, | sk_skb/stream_parser, | |
                   | | BPF_SK_SKB_STREAM_VERDICT, | sk_skb/stream_verdict, | | */
    SOCKET_FILTER, /* | | socket, | | */
    SOCK_OPS,      /* | BPF_CGROUP_SOCK_OPS, | sockops, | | */
    STRUCT_OPS,    /* | | struct_ops+ [#struct_ops]_   | |
                   | | | struct_ops.s+ [#struct_ops]_ | Yes       | */
    /// syscall, sleepable
    SYSCALL,
    TRACEPOINT, /* | | tp+ [#tp]_                   | |
                | | | tracepoint+ [#tp]_           | | */
    TRACING, /* | BPF_MODIFY_RETURN, | fmod_ret+ [#fentry]_         | |
             | | | fmod_ret.s+ [#fentry]_       | Yes       |
             | | BPF_TRACE_FENTRY, | fentry+ [#fentry]_           | |
             | | | fentry.s+ [#fentry]_         | Yes       |
             | | BPF_TRACE_FEXIT, | fexit+ [#fentry]_            | |
             | | | fexit.s+ [#fentry]_          | Yes       |
             | | BPF_TRACE_ITER, | iter+ [#iter]_               | |
             | | | iter.s+ [#iter]_             | Yes       |
             | | BPF_TRACE_RAW_TP, | tp_btf+ [#fentry]_           | | */
    XDP, /* | BPF_XDP_CPUMAP, | xdp.frags/cpumap, | |
         | | | xdp/cpumap, | |
         | | BPF_XDP_DEVMAP, | xdp.frags/devmap, | |
         | | | xdp/devmap, | |
         | | BPF_XDP, | xdp.frags, | |
         | | | xdp, | | */
}

/// Socket buffer oeprations
pub enum CgroupSkb {
    /// cgroup/skb
    SKB,
    /// cgroup_skb/egress
    INET_EGRESS,
    /// cgroup_skb/ingress
    INET_INGRESS,
}

pub enum CgroupSockOpt {
    /// cgroup/getsockopt
    GETSOCKOPT,
    /// cgroup/setsockopt
    SETSOCKOPT,
}

pub enum CgroupSockAddr {
    /// cgroup/bind4
    INET4_BIND,
    /// cgroup/connect4
    INET4_CONNECT,
    /// cgroup/getpeername4
    INET4_GETPEERNAME,
    /// cgroup/getsockname4
    INET4_GETSOCKNAME,
    /// cgroup/bind6
    INET6_BIND,
    /// cgroup/connect6
    INET6_CONNECT,
    /// cgroup/getpeername6
    INET6_GETPEERNAME,
    /// cgroup/getsockname6
    INET6_GETSOCKNAME,
    /// cgroup/recvmsg4
    UDP4_RECVMSG,
    /// cgroup/sendmsg4
    UDP4_SENDMSG,
    /// cgroup/recvmsg6
    UDP6_RECVMSG,
    /// cgroup/sendmsg6
    UDP6_SENDMSG,
    /// cgroup/connect_unix
    UNIX_CONNECT,
    /// cgroup/sendmsg_unix
    UNIX_SENDMSG,
    /// cgroup/recvmsg_unix
    UNIX_RECVMSG,
    /// cgroup/getpeername_unix
    UNIX_GETPEERNAME,
    /// cgroup/getsockname_unix
    UNIX_GETSOCKNAME,
}

pub enum CgroupSock {
    /// cgroup/sock
    SOCK,
    /// cgroup/post_bind4
    INET4_POST_BIND,
    /// cgroup/post_bind6
    INET6_POST_BIND,
    /// cgroup/sock_create
    INET_SOCK_CREATE,
    /// cgroup/sock_release
    INET_SOCK_RELEASE,
}

pub enum Kprobe {
    /// kprobe+ [#kprobe]_
    kprobe,
    /// kretprobe+ [#kprobe]_
    kretprobe,
    /// ksyscall+ [#ksyscall]_    
    ksyscall,
    /// kretsyscall+ [#ksyscall]_
    kretsyscall,
    /// uprobe+ [#uprobe]_
    uprobe,
    /// uprobe.s+ [#uprobe]_
    uprobe_s,
    /// uretprobe+ [#uprobe]_
    uretprobe,
    /// uretprobe.s+ [#uprobe]_
    uretprobe_s,
    /// usdt+ [#usdt]_
    usdt,
    /// kprobe.multi+ [#kpmulti]_
    kprobe_multi,
    /// kretprobe.multi+ [#kpmulti]_
    kretprobe_multi,
}

/// Linux Security Module
pub enum Lsm {
    /// lsm_cgroup+
    CGROUP,
    /// lsm+ [#lsm]_
    MAC,
    /// lsm.s+ [#lsm]_, sleepable
    lsm_s,
}

pub enum RawTracepointWritable {
    /// raw_tp.w+ [#rawtp]_
    raw_tp_w,
    /// raw_tracepoint.w+
    raw_tracepoint_w,
}

pub enum RawTracepoint {
    /// raw_tp+ [#rawtp]_
    raw_tp,
    /// raw_tracepoint+
    raw_tracepoint,
}

pub enum SchedCls {
    /// classifier, [#tc_legacy]_
    classifier,
    /// tc, [#tc_legacy]_
    tc,
    /// netkit/primary
    NETKIT_PRIMARY,
    /// netkit/peer
    NETKIT_PEER,
    /// tc/ingress
    TC_INGRESS,
    /// tc/egress
    TC_EGRESS,
    /// tcx/ingress
    TCX_INGRESS,
    /// tcx/egress
    TCX_EGRESS,
}
