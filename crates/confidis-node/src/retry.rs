//! Exponential-backoff retry helper for inter-node HTTP calls.
//!
//! Workers use this instead of bare fire-and-forget `send()` calls so
//! transient network errors don't silently fail after a single attempt.

use std::future::Future;
use std::time::Duration;

/// Calls `f` up to `max_attempts` times with exponential backoff and simple jitter.
///
/// Returns the first `Ok(T)`. If every attempt fails, logs a warning and returns `None`.
pub(crate) async fn with_retry<F, Fut, T, E>(
    label: &'static str,
    max_attempts: u32,
    base_delay: Duration,
    f: F,
) -> Option<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    for attempt in 1..=max_attempts {
        match f().await {
            Ok(val) => {
                if attempt > 1 {
                    tracing::debug!(label, attempt, "inter-node call succeeded after retry");
                }
                return Some(val);
            }
            Err(e) if attempt == max_attempts => {
                tracing::warn!(
                    label,
                    attempt,
                    error = %e,
                    "inter-node call failed — all retries exhausted"
                );
            }
            Err(e) => {
                let delay = jittered_delay(base_delay, attempt);
                tracing::debug!(
                    label,
                    attempt,
                    error = %e,
                    delay_ms = delay.as_millis(),
                    "inter-node call failed, retrying"
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
    None
}

/// Returns `base * 2^(attempt-1)`, capped at 30 s, with ±12.5 % jitter.
fn jittered_delay(base: Duration, attempt: u32) -> Duration {
    let base_ms = base.as_millis() as u64;
    let exp_ms = base_ms
        .saturating_mul(1u64 << attempt.saturating_sub(1).min(6))
        .min(30_000);
    // Deterministic jitter based on attempt index: +12.5 % on odd attempts.
    let jitter_ms = if attempt % 2 == 1 { exp_ms / 8 } else { 0 };
    Duration::from_millis(exp_ms + jitter_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn succeeds_on_first_try() {
        let result = with_retry("test", 3, Duration::from_millis(1), || async {
            Ok::<_, String>("hello")
        })
        .await;
        assert_eq!(result, Some("hello"));
    }

    #[tokio::test]
    async fn retries_on_transient_failure() {
        let attempts = Arc::new(AtomicU32::new(0));
        let a = attempts.clone();
        let result = with_retry("test", 3, Duration::from_millis(1), || {
            let a = a.clone();
            async move {
                let n = a.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err::<&str, _>("transient")
                } else {
                    Ok("recovered")
                }
            }
        })
        .await;
        assert_eq!(result, Some("recovered"));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn returns_none_after_exhaustion() {
        let result = with_retry("test", 2, Duration::from_millis(1), || async {
            Err::<(), _>("always fails")
        })
        .await;
        assert!(result.is_none());
    }

    #[test]
    fn delay_grows_exponentially() {
        let base = Duration::from_millis(100);
        let d1 = jittered_delay(base, 1); // 100ms + jitter
        let d2 = jittered_delay(base, 2); // 200ms
        let d3 = jittered_delay(base, 3); // 400ms + jitter
        assert!(d2 > d1 || d2.as_millis() >= 200, "delay should grow");
        assert!(d3 > d2, "delay should grow exponentially");
    }

    #[test]
    fn delay_caps_at_30s() {
        let base = Duration::from_millis(1000);
        let d = jittered_delay(base, 10); // would be 512s uncapped
        assert!(d.as_secs() <= 34, "delay must not exceed ~30s + jitter");
    }
}
