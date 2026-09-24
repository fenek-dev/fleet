//! Minimal `sd_notify` (READY=1, WATCHDOG=1) over `$NOTIFY_SOCKET` with a
//! std `UnixDatagram`; no libsystemd, no `unsafe`. A no-op when the
//! variable is unset (development, tests).

use std::os::unix::net::UnixDatagram;

/// Sends `state` (e.g. `"READY=1"`). Errors are ignored: systemd restarts
/// exec if the watchdog stops hearing from it, which is the right outcome.
pub fn notify(state: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let Ok(sock) = UnixDatagram::unbound() else {
        return;
    };
    let bytes = path.as_encoded_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        send_abstract(&sock, name, state);
    } else {
        let _ = sock.send_to(state.as_bytes(), &path);
    }
}

#[cfg(target_os = "linux")]
fn send_abstract(sock: &UnixDatagram, name: &[u8], state: &str) {
    use std::os::linux::net::SocketAddrExt;
    if let Ok(addr) = std::os::unix::net::SocketAddr::from_abstract_name(name) {
        let _ = sock.send_to_addr(state.as_bytes(), &addr);
    }
}

#[cfg(not(target_os = "linux"))]
fn send_abstract(_: &UnixDatagram, _: &[u8], _: &str) {}

/// How often to send `WATCHDOG=1`: half of `WATCHDOG_USEC` (sd_watchdog_enabled
/// convention), or `None` when systemd asked for no watchdog.
pub fn watchdog_interval() -> Option<std::time::Duration> {
    parse_watchdog_usec(&std::env::var("WATCHDOG_USEC").ok()?)
}

fn parse_watchdog_usec(v: &str) -> Option<std::time::Duration> {
    let usec: u64 = v.trim().parse().ok()?;
    (usec > 0).then(|| std::time::Duration::from_micros(usec / 2).max(MIN_PING))
}

/// Floor so a tiny `WATCHDOG_USEC` can't turn into a busy loop.
const MIN_PING: std::time::Duration = std::time::Duration::from_millis(100);

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[test]
    fn watchdog_half_interval() {
        assert_eq!(
            super::parse_watchdog_usec("30000000"),
            Some(Duration::from_secs(15))
        );
        assert_eq!(super::parse_watchdog_usec("0"), None);
        assert_eq!(super::parse_watchdog_usec("x"), None);
        assert_eq!(
            super::parse_watchdog_usec("10"),
            Some(Duration::from_millis(100))
        );
    }
}
