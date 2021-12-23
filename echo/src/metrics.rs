use std::sync::atomic::{AtomicU64, Ordering};

pub struct Metrics {
    open_missed: AtomicU64,
    open_handled: AtomicU64,
}

impl Metrics {
    pub fn new() -> Metrics {
        return Metrics {
            open_missed: AtomicU64::new(0),
            open_handled: AtomicU64::new(0),
        };
    }
    pub fn add_missing(&self, lost: usize) {
        self.open_missed.fetch_add(lost as u64, Ordering::Relaxed);
    }
    pub fn get_missing(&self) -> u64 {
        return self.open_missed.load(Ordering::Relaxed);
    }
    pub fn add_handled(&self, handled: usize) {
        self.open_handled.fetch_add(handled as u64, Ordering::Relaxed);
    }
    pub fn get_handled(&self) -> u64 {
        return self.open_handled.load(Ordering::Relaxed);
    }
}
