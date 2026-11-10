//! Conservative read-only kernel TCP peer witness for S18-6.
//! A remote TCP peer may be an SSH or other control channel. The kernel table
//! alone cannot identify the authenticated administrator, UDP control paths,
//! reachability, per-socket marks/overlays, or local recovery. It only
//! provides a separate loss-of-session/drift veto. It never grants a toggle.
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{Duration, Instant};

use linura_provider_sdk::ProviderError;

const MAX_BYTES: u64 = 512 * 1024;
const MAX_ROWS: usize = 4096;

fn deny(reason: &str) -> ProviderError {
    ProviderError::InvalidState(format!("native remote-session {reason}"))
}

/// An original kernel socket identity is not an authenticated administrator
/// identity. It is a separate, never-replayed connection-generation witness.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct SocketIdentity {
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
    uid: u32,
    inode: u64,
}

impl SocketIdentity {
    #[cfg(test)]
    pub(super) fn fixture() -> Self {
        Self {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            source_port: 22,
            destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            destination_port: 8080,
            uid: 1000,
            inode: 42,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RemoteTcpSnapshot {
    conversations: BTreeSet<(IpAddr, u16)>,
    sockets: BTreeSet<SocketIdentity>,
}

impl RemoteTcpSnapshot {
    /// Unknown or lost remote sockets are never a positive settlement signal.
    pub(super) fn require_continuity(&self, next: &Self) -> Result<(), ProviderError> {
        if self.conversations != next.conversations || self.sockets != next.sockets {
            return Err(deny(
                "remote TCP peer, owner or socket generation changed during radio effect",
            ));
        }
        Ok(())
    }

    /// The original kernel socket's source and owning UID are supplied to
    /// the Linux FIB. Socket marks, original application and remote path
    /// survival are NOT attested by this diagnostic.
    pub(super) fn destination_routes(
        &self,
    ) -> Result<std::collections::BTreeMap<SocketIdentity, u32>, ProviderError> {
        let unique = &self.sockets;
        // One kernel request has its own deadline. Also bound the *whole*
        // inventory: many legitimate peers must not turn a Control safety
        // preflight into seconds of chained netlink timeouts.
        if unique.len() > 4 {
            return Err(deny("too many remote endpoints for bounded FIB lookup"));
        }
        let started = Instant::now();
        let mut result = std::collections::BTreeMap::new();
        for socket in unique {
            // These fields are also retained in the generation key: a new
            // socket on the same remote IP is not an administration survivor.
            if socket.source_port == 0 || socket.destination_port == 0 || socket.inode == 0 {
                return Err(deny("original remote socket lost its kernel generation"));
            }
            if started.elapsed() >= Duration::from_millis(350) {
                return Err(deny("aggregate remote FIB lookup deadline exceeded"));
            }
            let ifindex = super::radio_netlink::source_uid_selected_oif(
                socket.destination,
                socket.source,
                socket.uid,
            )?;
            if started.elapsed() >= Duration::from_millis(350) {
                return Err(deny("aggregate remote FIB lookup deadline exceeded"));
            }
            result.insert(socket.clone(), ifindex);
        }
        Ok(result)
    }

    /// This socket table does not identify SSH, UDP, admin identity, selected
    /// policy routes or remote reachability; therefore it cannot attest safety.
    #[must_use]
    pub(super) const fn proves_remote_administration_survival(&self) -> bool {
        false
    }

    #[cfg(test)]
    pub(super) fn fixture() -> Self {
        Self {
            conversations: BTreeSet::new(),
            sockets: BTreeSet::new(),
        }
    }
}

fn address_port(text: &str, family: u8) -> Result<(IpAddr, u16), ProviderError> {
    let (address, port) = text
        .split_once(':')
        .ok_or_else(|| deny("kernel TCP address has no port"))?;
    let port = u16::from_str_radix(port, 16).map_err(|_| deny("invalid remote port"))?;
    let ip = match family {
        4 if address.len() == 8 => {
            let value =
                u32::from_str_radix(address, 16).map_err(|_| deny("invalid IPv4 address"))?;
            IpAddr::V4(Ipv4Addr::from(value.to_le_bytes()))
        }
        6 if address.len() == 32 => {
            let mut octets = [0_u8; 16];
            for index in 0..4 {
                let group = &address[index * 8..index * 8 + 8];
                let value =
                    u32::from_str_radix(group, 16).map_err(|_| deny("invalid IPv6 address"))?;
                octets[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Err(deny("TCP address family or width is invalid")),
    };
    Ok((ip, port))
}

fn not_remote(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_loopback() || v4.is_multicast(),
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_unspecified() || v4.is_loopback())
        }
    }
}

fn parse(
    text: &str,
    family: u8,
    destinations: &mut BTreeSet<(IpAddr, u16)>,
    sockets: &mut BTreeSet<SocketIdentity>,
) -> Result<(), ProviderError> {
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| deny("missing TCP table header"))?;
    if !header.contains("local_address")
        || !header.contains("rem_address")
        || !header.contains("st")
    {
        return Err(deny("unexpected TCP table schema"));
    }
    for (index, line) in lines.enumerate() {
        if index >= MAX_ROWS {
            return Err(deny("TCP rows exceeded fixed bound"));
        }
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() < 11 {
            return Err(deny("truncated TCP row"));
        }
        let (source, source_port) = address_port(fields[1], family)?;
        let (remote, port) = address_port(fields[2], family)?;
        let state = u8::from_str_radix(fields[3], 16).map_err(|_| deny("invalid TCP state"))?;
        if !(1..=12).contains(&state) {
            return Err(deny("unexpected TCP state"));
        }
        // LISTEN, TIME_WAIT, CLOSED have no maintained active application
        // channel. Everything else is treated as possibly administrative.
        if !matches!(state, 6 | 7 | 10) && !not_remote(remote) {
            let uid: u32 = fields[7].parse().map_err(|_| deny("invalid socket UID"))?;
            let inode: u64 = fields[9]
                .parse()
                .map_err(|_| deny("invalid socket inode"))?;
            if source_port == 0 || port == 0 || inode == 0 || source.is_unspecified() {
                return Err(deny(
                    "active remote TCP peer has no source, port or generation",
                ));
            }
            if sockets.len() >= MAX_ROWS * 2 {
                return Err(deny("aggregate remote TCP peer budget exceeded"));
            }
            if !sockets.insert(SocketIdentity {
                source,
                source_port,
                destination: remote,
                destination_port: port,
                uid,
                inode,
            }) {
                return Err(deny("duplicate kernel remote socket identity"));
            }
            destinations.insert((remote, port));
        }
    }
    Ok(())
}

fn bounded(path: &Path) -> Result<String, ProviderError> {
    let file = File::open(path).map_err(|_| deny("kernel TCP table unavailable"))?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| deny("kernel TCP read failed"))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(deny("kernel TCP table byte limit exceeded"));
    }
    String::from_utf8(bytes).map_err(|_| deny("kernel TCP table encoding invalid"))
}

pub(super) fn sample() -> Result<RemoteTcpSnapshot, ProviderError> {
    let ipv4 = bounded(Path::new("/proc/net/tcp"))?;
    let ipv6 = bounded(Path::new("/proc/net/tcp6"))?;
    let mut conversations = BTreeSet::new();
    let mut sockets = BTreeSet::new();
    parse(&ipv4, 4, &mut conversations, &mut sockets)?;
    parse(&ipv6, 6, &mut conversations, &mut sockets)?;
    Ok(RemoteTcpSnapshot {
        conversations,
        sockets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str =
        "  sl  local_address rem_address   st tx_queue tr tm->when retrnsmt uid timeout inode\n";

    #[test]
    fn native_tcp_remote_control_ambiguity_is_never_elevated_to_authority() {
        let mut peers = BTreeSet::new();
        let value = format!(
            "{HEADER}  0: 0100007F:1600 0100007F:0123 01 0 0 0 0 0 0 0\n  1: 0100000A:0016 0200000A:1F90 01 0 0 0 1000 0 42 0\n"
        );
        let mut sockets = BTreeSet::new();
        assert!(parse(&value, 4, &mut peers, &mut sockets).is_ok());
        assert_eq!(peers.len(), 1);
        assert_eq!(sockets.len(), 1);
        assert!(peers.contains(&(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8080)));
        let before = RemoteTcpSnapshot {
            conversations: peers,
            sockets,
        };
        let mut replaced = before.clone();
        let mut changed = replaced
            .sockets
            .iter()
            .next()
            .unwrap_or_else(|| unreachable!("known socket fixture"))
            .clone();
        replaced.sockets.clear();
        changed.inode += 1;
        replaced.sockets.insert(changed);
        assert!(before.require_continuity(&replaced).is_err());
        let mut changed_uid = before.clone();
        let original = changed_uid
            .sockets
            .iter()
            .next()
            .unwrap_or_else(|| unreachable!("socket fixture"))
            .clone();
        changed_uid.sockets.clear();
        let mut altered = original;
        altered.uid += 1;
        changed_uid.sockets.insert(altered);
        assert!(before.require_continuity(&changed_uid).is_err());
        assert!(!before.proves_remote_administration_survival());
        assert!(before.require_continuity(&before).is_ok());
        assert!(
            before
                .require_continuity(&RemoteTcpSnapshot::fixture())
                .is_err()
        );
    }

    #[test]
    fn tcp6_mapping_and_malformed_kernel_rows_fail_closed() {
        let mut peers = BTreeSet::new();
        let sample = format!(
            "{HEADER} 0: 00000000000000000000000001000000:1600 00000000000000000000000002000000:01BB 01 0 0 0 1000 0 42 0\n"
        );
        assert!(parse(&sample, 6, &mut peers, &mut BTreeSet::new()).is_ok());
        assert!(!peers.contains(&(IpAddr::V6(Ipv6Addr::LOCALHOST), 443)));
        assert_eq!(peers.len(), 1);
        for malformed in [
            "not a table\n",
            "local_address rem_address st\n 1: bad bad ZZ\n",
            "local_address rem_address st\n 1: 00000000:0000 00000000:0000 90 0 0 0 0 0 0 0\n",
        ] {
            assert!(parse(malformed, 4, &mut BTreeSet::new(), &mut BTreeSet::new()).is_err());
        }
    }
}
