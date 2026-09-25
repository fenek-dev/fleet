//! Scheduled daily restarts with RCON warnings (design §9.6), as pure
//! time arithmetic: which warnings and restarts fall in `(prev, now]`.

const DAY_MS: u64 = 86_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Due {
    /// Warn that the restart is this many seconds away.
    Warn(u32),
    Restart,
}

/// Events of a daily restart at `minute` (after midnight UTC) with
/// `warnings` (seconds before it) whose time lies in `(prev, now]`, in
/// time order. A clock step backwards yields nothing; a long gap (sleep)
/// yields at most the last day's events.
pub fn due(prev: u64, now: u64, minute: u32, warnings: &[u32]) -> Vec<(u64, Due)> {
    if now <= prev {
        return Vec::new();
    }
    let prev = prev.max(now.saturating_sub(DAY_MS));
    let mut out = Vec::new();
    let first = (prev / DAY_MS).saturating_sub(1);
    for day in first..=now / DAY_MS + 1 {
        let t = day * DAY_MS + u64::from(minute) * 60_000;
        let mut push = |at: u64, d| {
            if prev < at && at <= now {
                out.push((at, d));
            }
        };
        for w in warnings {
            push(t.saturating_sub(u64::from(*w) * 1000), Due::Warn(*w));
        }
        push(t, Due::Restart);
    }
    out.sort_by_key(|(t, _)| *t);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: u64 = 20_000 * DAY_MS; // some midnight
    const FIVE: u32 = 5 * 60; // 05:00

    fn at(h: u64, m: u64, s: u64) -> u64 {
        D + (h * 3600 + m * 60 + s) * 1000
    }

    #[test]
    fn warnings_then_restart() {
        let w = [600, 60, 10];
        assert!(due(at(4, 0, 0), at(4, 49, 59), FIVE, &w).is_empty());
        assert_eq!(
            due(at(4, 49, 59), at(4, 50, 0), FIVE, &w),
            vec![(at(4, 50, 0), Due::Warn(600))]
        );
        assert_eq!(
            due(at(4, 58, 30), at(5, 0, 0), FIVE, &w),
            vec![
                (at(4, 59, 0), Due::Warn(60)),
                (at(4, 59, 50), Due::Warn(10)),
                (at(5, 0, 0), Due::Restart)
            ]
        );
        // Exactly once: the next window starts after it.
        assert!(due(at(5, 0, 0), at(5, 0, 30), FIVE, &w).is_empty());
        // Next day again.
        let next = due(at(5, 0, 0), at(5, 0, 0) + DAY_MS, FIVE, &w);
        assert_eq!(next.last(), Some(&(at(5, 0, 0) + DAY_MS, Due::Restart)));
        assert_eq!(next.len(), 4);
    }

    #[test]
    fn midnight_warning_and_clock_steps() {
        // 00:05 restart, 10-minute warning falls on the previous day.
        let r = due(D - 400_000, D - 200_000, 5, &[600]);
        assert_eq!(r, vec![(D - 300_000, Due::Warn(600))]);
        // Clock went backwards: nothing.
        assert!(due(at(6, 0, 0), at(5, 0, 0), FIVE, &[]).is_empty());
        // Days asleep: only the last day's events.
        let r = due(D - 10 * DAY_MS, at(6, 0, 0), FIVE, &[]);
        assert_eq!(r, vec![(at(5, 0, 0), Due::Restart)]);
    }
}
