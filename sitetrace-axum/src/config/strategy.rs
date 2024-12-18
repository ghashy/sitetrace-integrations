#[derive(Debug, Clone)]
pub enum SendRequestStrategy {
    /// Send requests every `u32` seconds.
    TimeInterval(u64),
    /// Send requests when their cached count exceeds `u32`.
    RequestCountExceed(usize),
    /// Send requests when one of (time_interval_sec, count)
    /// condition is true.
    Both(u64, usize),
}

impl SendRequestStrategy {
    pub(crate) fn should_send(&self, elapsed: u64, count: usize) -> bool {
        if count < 1 {
            return false;
        }
        match self {
            SendRequestStrategy::TimeInterval(i) => elapsed >= *i,
            SendRequestStrategy::RequestCountExceed(c) => count >= *c,
            SendRequestStrategy::Both(i, c) => elapsed >= *i || count >= *c,
        }
    }
}

impl Default for SendRequestStrategy {
    fn default() -> Self {
        Self::Both(60, 1000)
    }
}
