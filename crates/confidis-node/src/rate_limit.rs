//! Simple fixed-window rate limiter for the node HTTP server.
//!
//! Uses a `Mutex`-protected counter rather than external crates so there
//! are no new dependency constraints. The node API is not a high-throughput
//! public endpoint, so Mutex overhead is negligible.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Fixed-window rate limiter: allows `max_per_second` requests per second
/// with a burst allowance of `burst` additional requests at the start of
/// each window.
#[derive(Debug)]
pub(crate) struct RateLimiter {
    inner: Mutex<Inner>,
    max_per_window: u32,
    window_ms: u64,
}

#[derive(Debug)]
struct Inner {
    /// Number of requests in the current window.
    count: u32,
    /// Start of the current window (Unix ms).
    window_start_ms: u64,
}

impl RateLimiter {
    /// `per_second` — sustained requests per second.
    /// `burst`      — extra requests allowed at the start of a fresh window.
    pub(crate) fn new(per_second: u32, burst: u32) -> Self {
        Self {
            inner: Mutex::new(Inner {
                count: 0,
                window_start_ms: now_ms(),
            }),
            max_per_window: per_second + burst,
            window_ms: 1_000,
        }
    }

    /// Returns `true` if the request is permitted; `false` if the rate limit
    /// is exceeded (caller should respond with HTTP 429).
    pub(crate) fn try_acquire(&self) -> bool {
        let now = now_ms();
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let elapsed = now.saturating_sub(g.window_start_ms);
        if elapsed >= self.window_ms {
            g.count = 0;
            g.window_start_ms = now;
        }
        if g.count >= self.max_per_window {
            return false;
        }
        g.count += 1;
        true
    }

    #[cfg(test)]
    fn reset_window_for_test(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.window_start_ms = 0;
        g.count = 0;
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permits_up_to_burst_requests() {
        let rl = RateLimiter::new(10, 5); // 15 per window
        for i in 0..15 {
            assert!(rl.try_acquire(), "request {i} should be permitted");
        }
    }

    #[test]
    fn rejects_beyond_burst() {
        let rl = RateLimiter::new(10, 5); // 15 per window
        for _ in 0..15 {
            rl.try_acquire();
        }
        assert!(!rl.try_acquire(), "16th request should be rejected");
    }

    #[test]
    fn resets_after_window() {
        let rl = RateLimiter::new(3, 0);
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        assert!(!rl.try_acquire()); // window full

        // Simulate window expiry by forcing the start timestamp to epoch.
        rl.reset_window_for_test();
        // First request of the new window should succeed.
        assert!(rl.try_acquire());
    }
}
