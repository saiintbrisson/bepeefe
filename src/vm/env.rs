use std::sync::Arc;

/// Per-run host environment exposed to BPF helpers.
///
/// Values that in a real kernel would come from the running task or the
/// clock (pid/tgid, ktime, cpu...) are passed in here instead. The VM
/// reads from this copy and never mutates it. An emulator built on top
/// of the VM owns the canonical `HostEnv` and updates it between runs.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct HostEnv {
    pub ktime_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub cpu: u32,
    /// Task comm, without a trailing NUL. The comm attribute contains the
    /// executable's name, excluding path.
    pub comm: Arc<str>,
    /// Kernel-space memory region accessible by probe reads.
    pub kernel: Arc<[u8]>,
    /// User-space memory region accessible by probe reads.
    pub user: Arc<[u8]>,
}

impl Default for HostEnv {
    fn default() -> Self {
        Self {
            ktime_ns: 0,
            pid: 0,
            tgid: 0,
            cpu: 0,
            comm: Arc::from(""),
            kernel: Arc::default(),
            user: Arc::default(),
        }
    }
}

impl HostEnv {
    /// Packed `tgid << 32 | pid`.
    pub fn pid_tgid(&self) -> u64 {
        ((self.tgid as u64) << 32) | self.pid as u64
    }

    pub fn with_kernel(mut self, bytes: impl Into<Arc<[u8]>>) -> Self {
        self.kernel = bytes.into();
        self
    }

    pub fn with_user(mut self, bytes: impl Into<Arc<[u8]>>) -> Self {
        self.user = bytes.into();
        self
    }
}
