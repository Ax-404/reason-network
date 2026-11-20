//! Tailscale tailnet helpers for `tailnet_only`: address ranges, bind selection, and clear errors
//! when no Tailscale interface is present.
//!
//! Example addresses only (never a real MagicDNS name or production tailnet IP):
//! `100.64.1.10`, `fd7a:115c:a1e0::1`, `https://relay.example.ts.net:10443`.
//!
//! On Windows, set `tailnet_bind` in config: this module does not enumerate adapters there.

use anyhow::{Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Tailscale CGNAT: `100.64.0.0/10`.
pub fn is_tailscale_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

/// Tailscale IPv6 ULA: `fd7a:115c:a1e0::/48`.
pub fn is_tailscale_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
}

pub fn is_tailscale_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_tailscale_v4(v4),
        IpAddr::V6(v6) => is_tailscale_v6(v6),
    }
}

/// Parse a configured bind address; it must be a Tailscale address.
pub fn parse_bind_ip(raw: &str) -> Result<IpAddr> {
    let ip: IpAddr = raw.parse().map_err(|_| anyhow::anyhow!("not an IP address: {raw}"))?;
    if !is_tailscale_ip(ip) {
        bail!("tailnet_only: {raw} is not a Tailscale address (expected 100.64.0.0/10 or fd7a:115c:a1e0::/48)");
    }
    Ok(ip)
}

/// Local interface addresses that look like Tailscale.
pub fn detected_tailnet_ips() -> Vec<IpAddr> {
    local_ips().into_iter().filter(|ip| is_tailscale_ip(*ip)).collect()
}

/// Addresses to bind when `tailnet_only` is on: the configured one, else every detected Tailscale
/// address. Fails clearly when none are found.
pub fn bind_ips(configured: Option<&str>) -> Result<Vec<IpAddr>> {
    if let Some(raw) = configured.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(vec![parse_bind_ip(raw)?]);
    }
    let found = detected_tailnet_ips();
    if found.is_empty() {
        bail!(
            "tailnet_only is on, but no Tailscale interface was found \
             (looked for 100.64.0.0/10 and fd7a:115c:a1e0::/48). \
             Connect Tailscale, or set tailnet_bind to that interface's address \
             (example: tailnet_bind = \"100.64.1.10\")"
        );
    }
    Ok(found)
}

#[cfg(unix)]
fn local_ips() -> Vec<IpAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    // SAFETY: getifaddrs allocates a list we free with freeifaddrs; each `ifa_addr` is either null
    // or a sockaddr of the family we match before reading.
    unsafe {
        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut list) != 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut cur = list;
        while !cur.is_null() {
            let entry = &*cur;
            if !entry.ifa_addr.is_null() {
                match (*entry.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sin = &*(entry.ifa_addr as *const libc::sockaddr_in);
                        out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                        out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = entry.ifa_next;
        }
        libc::freeifaddrs(list);
        out
    }
}

#[cfg(windows)]
fn local_ips() -> Vec<IpAddr> {
    // Best-effort: without IP Helper wiring, require `tailnet_bind` on Windows if detection fails.
    // Prefer configured bind; detection may be empty.
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn cgnat_and_ula_ranges() {
        assert!(is_tailscale_v4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_tailscale_v4(Ipv4Addr::new(100, 127, 255, 254)));
        assert!(!is_tailscale_v4(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_tailscale_v4(Ipv4Addr::new(100, 128, 0, 1)));
        assert!(!is_tailscale_v4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_tailscale_v6("fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(is_tailscale_v6("fd7a:115c:a1e0:abcd::2".parse::<Ipv6Addr>().unwrap()));
        assert!(!is_tailscale_v6("fd7a:115c:a1e1::1".parse().unwrap()));
        assert!(!is_tailscale_v6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn configured_bind_must_be_tailscale() {
        assert_eq!(parse_bind_ip("100.64.1.10").unwrap(), "100.64.1.10".parse::<IpAddr>().unwrap());
        assert!(parse_bind_ip("127.0.0.1").unwrap_err().to_string().contains("not a Tailscale"));
        assert!(parse_bind_ip("not-an-ip").is_err());
    }

    #[test]
    fn missing_interface_fails_clearly() {
        // Empty detection path: no configured bind and no IPs passed through bind_ips' detection
        // when none exist. We exercise the error text via a direct empty-configured call only when
        // the machine has no Tailscale; otherwise skip the empty case by checking the message shape.
        let err = match bind_ips(None) {
            Err(e) => e.to_string(),
            Ok(ips) => {
                assert!(ips.iter().all(|ip| is_tailscale_ip(*ip)));
                return;
            }
        };
        assert!(err.contains("tailnet_only is on"), "{err}");
        assert!(err.contains("no Tailscale interface"), "{err}");
        assert!(err.contains("tailnet_bind"), "{err}");
    }
}
