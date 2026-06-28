pub const TASK_COMM_LEN: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum TaskError {
    #[error("comm is longer than 15 bytes")]
    CommTooLong,
}

/// Identity of the task that triggered an invocation, read by the
/// `bpf_get_current_*` helpers.
#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Task {
    pid: u32,
    tgid: u32,
    comm: [u8; TASK_COMM_LEN],
}

impl Task {
    pub fn new(pid: u32, tgid: u32, comm: &str) -> Result<Self, TaskError> {
        let src = comm.as_bytes();
        if src.len() > TASK_COMM_LEN - 1 {
            return Err(TaskError::CommTooLong);
        }
        let mut comm = [0u8; TASK_COMM_LEN];
        for (dst, &b) in comm.iter_mut().zip(src) {
            *dst = b;
        }
        Ok(Self { pid, tgid, comm })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn tgid(&self) -> u32 {
        self.tgid
    }

    /// Packed `tgid << 32 | pid`.
    pub fn pid_tgid(&self) -> u64 {
        ((self.tgid as u64) << 32) | self.pid as u64
    }

    pub fn comm(&self) -> &[u8] {
        &self.comm
    }
}
