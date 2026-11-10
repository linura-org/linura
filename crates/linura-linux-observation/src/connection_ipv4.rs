//! Bounded, read-only RTM_GETADDR IPv4 witness for S18-7.
//! It can reject a mismatched NetworkManager address claim; it never grants
//! routing, DNS, reachability, recovery or native mutation authority.

use linura_provider_sdk::ProviderError;
use rustix::io::Errno;
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{self, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

const NL_HEADER: usize = 16;
const IFADDR_HEADER: usize = 8;
const MAX_PACKET: usize = 64 * 1024;
const MAX_TOTAL: usize = 256 * 1024;
const MAX_ROWS: usize = 4096;
const MAX_ATTRIBUTES: usize = 64;
const DEADLINE: Duration = Duration::from_millis(350);
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;

fn deny(detail: &str) -> ProviderError {
    ProviderError::InvalidState(format!("kernel IPv4 witness {detail}"))
}
fn read16(data: &[u8]) -> Result<u16, ProviderError> {
    let bytes: [u8; 2] = data
        .get(..2)
        .ok_or_else(|| deny("short u16"))?
        .try_into()
        .map_err(|_| deny("bad u16"))?;
    Ok(u16::from_ne_bytes(bytes))
}
fn read32(data: &[u8]) -> Result<u32, ProviderError> {
    let bytes: [u8; 4] = data
        .get(..4)
        .ok_or_else(|| deny("short u32"))?
        .try_into()
        .map_err(|_| deny("bad u32"))?;
    Ok(u32::from_ne_bytes(bytes))
}
fn aligned(n: usize) -> Result<usize, ProviderError> {
    n.checked_add(3)
        .map(|v| v & !3)
        .ok_or_else(|| deny("alignment overflow"))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Ipv4KernelAddress {
    pub(super) ifindex: u32,
    pub(super) address: Ipv4Addr,
    pub(super) prefix: u8,
}

fn parse_address(row: &[u8]) -> Result<Ipv4KernelAddress, ProviderError> {
    if row.len() < IFADDR_HEADER || row[0] != 2 || row[1] > 32 {
        return Err(deny("incorrect family, prefix or address header"));
    }
    let ifindex = read32(&row[4..])?;
    if ifindex == 0 {
        return Err(deny("missing kernel ifindex"));
    }
    let mut local = None;
    let mut flags = u32::from(row[2]);
    let mut seen = BTreeSet::new();
    let mut attrs = &row[IFADDR_HEADER..];
    while !attrs.is_empty() {
        if attrs.len() < 4 || seen.len() >= MAX_ATTRIBUTES {
            return Err(deny("truncated or oversized address attributes"));
        }
        let len = usize::from(read16(attrs)?);
        let kind = read16(&attrs[2..])?;
        if len < 4 || len > attrs.len() || !seen.insert(kind) {
            return Err(deny("duplicate or invalid address attribute"));
        }
        let pad = aligned(len)?;
        if pad > attrs.len() {
            return Err(deny("truncated address padding"));
        }
        let value = &attrs[4..len];
        match kind {
            IFA_LOCAL => {
                let octets: [u8; 4] = value.try_into().map_err(|_| deny("bad local address"))?;
                local = Some(Ipv4Addr::from(octets));
            }
            IFA_FLAGS => {
                flags = read32(value)?;
                if value.len() != 4 {
                    return Err(deny("invalid IPv4 flags width"));
                }
            }
            _ => {}
        }
        attrs = &attrs[pad..];
    }
    if flags & (0x04 | 0x08 | 0x20 | 0x40) != 0 {
        return Err(deny("tentative, failed or deprecated address"));
    }
    let address = local.ok_or_else(|| deny("missing IFA_LOCAL"))?;
    if address.is_unspecified()
        || address.is_multicast()
        || address.octets() == [255, 255, 255, 255]
    {
        return Err(deny("unusable local IPv4 address"));
    }
    Ok(Ipv4KernelAddress {
        ifindex,
        address,
        prefix: row[1],
    })
}

fn consume(
    mut packet: &[u8],
    seq: u32,
    own_port: u32,
    rows: &mut BTreeSet<Ipv4KernelAddress>,
) -> Result<bool, ProviderError> {
    while !packet.is_empty() {
        if packet.len() < NL_HEADER {
            return Err(deny("short netlink header"));
        }
        let size = usize::try_from(read32(packet)?).map_err(|_| deny("size overflow"))?;
        if size < NL_HEADER || size > packet.len() {
            return Err(deny("invalid netlink record width"));
        }
        let kind = read16(&packet[4..])?;
        if read32(&packet[8..])? != seq
            || (read32(&packet[12..])? != 0 && read32(&packet[12..])? != own_port)
            || read16(&packet[6..])? & 0x10 != 0
        {
            return Err(deny("foreign or interrupted dump"));
        }
        let data = &packet[NL_HEADER..size];
        if kind == 2 {
            return Err(deny("kernel rejected address query"));
        }
        if kind == 3 {
            if !(data.is_empty() || (data.len() == 4 && read32(data)? == 0))
                || (aligned(size)? != packet.len() && size != packet.len())
            {
                return Err(deny("malformed dump terminator"));
            }
            return Ok(true);
        }
        if kind != RTM_NEWADDR || rows.len() >= MAX_ROWS {
            return Err(deny("unexpected or excessive address record"));
        }
        if !rows.insert(parse_address(data)?) {
            return Err(deny("duplicate kernel IPv4 record"));
        }
        let pad = aligned(size)?;
        if pad > packet.len() {
            return Err(deny("truncated record padding"));
        }
        packet = &packet[pad..];
    }
    Ok(false)
}

/// The kernel is the only accepted sender. The dump is bounded by both
/// a monotonic deadline and a byte/row budget and must end with NLMSG_DONE.
pub(super) fn sample() -> Result<BTreeSet<Ipv4KernelAddress>, ProviderError> {
    let fd = net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| deny("netlink socket unavailable"))?;
    net::bind(&fd, &SocketAddrNetlink::new(0, 0)).map_err(|_| deny("netlink bind failed"))?;
    let own = net::getsockname(&fd)
        .map_err(|_| deny("netlink local address unavailable"))
        .and_then(|address| {
            SocketAddrNetlink::try_from(address).map_err(|_| deny("wrong local netlink family"))
        })?;
    if own.pid() == 0 {
        return Err(deny("kernel netlink port unavailable"));
    }
    let mut query = [0_u8; NL_HEADER + IFADDR_HEADER];
    query[..4].copy_from_slice(&24_u32.to_ne_bytes());
    query[4..6].copy_from_slice(&RTM_GETADDR.to_ne_bytes());
    query[6..8].copy_from_slice(&0x301_u16.to_ne_bytes());
    query[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    query[NL_HEADER] = 2;
    if net::sendto(
        &fd,
        &query,
        SendFlags::empty(),
        &SocketAddrNetlink::new(0, 0),
    )
    .map_err(|_| deny("query send failed"))?
        != query.len()
    {
        return Err(deny("partial query transmission"));
    }
    let start = Instant::now();
    let mut rows = BTreeSet::new();
    let mut total = 0_usize;
    loop {
        if start.elapsed() > DEADLINE {
            return Err(deny("dump deadline expired"));
        }
        let mut buffer = [0_u8; MAX_PACKET];
        match net::recvfrom(&fd, &mut buffer, RecvFlags::TRUNC) {
            Ok((received, length, sender)) => {
                if received == 0 || received != length || length > MAX_PACKET {
                    return Err(deny("short or truncated kernel packet"));
                }
                total = total
                    .checked_add(length)
                    .ok_or_else(|| deny("total overflow"))?;
                if total > MAX_TOTAL {
                    return Err(deny("kernel dump exceeded byte budget"));
                }
                let peer = sender
                    .ok_or_else(|| deny("missing sender"))
                    .and_then(|value| {
                        SocketAddrNetlink::try_from(value)
                            .map_err(|_| deny("foreign sender family"))
                    })?;
                if peer.pid() != 0 || peer.groups() != 0 {
                    return Err(deny("non-kernel netlink sender"));
                }
                if consume(&buffer[..received], 1, own.pid(), &mut rows)? {
                    return Ok(rows);
                }
            }
            Err(Errno::AGAIN) => thread::sleep(Duration::from_millis(2)),
            Err(_) => return Err(deny("netlink receive failed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut row = vec![0_u8; 32];
        row[..4].copy_from_slice(&32_u32.to_ne_bytes());
        row[4..6].copy_from_slice(&RTM_NEWADDR.to_ne_bytes());
        row[8..12].copy_from_slice(&1_u32.to_ne_bytes());
        row[16] = 2;
        row[17] = 24;
        row[20..24].copy_from_slice(&7_u32.to_ne_bytes());
        row[24..26].copy_from_slice(&8_u16.to_ne_bytes());
        row[26..28].copy_from_slice(&IFA_LOCAL.to_ne_bytes());
        row[28..32].copy_from_slice(&[192, 0, 2, 5]);
        row
    }
    #[test]
    fn typed_ipv4_identity_and_foreign_kernel_replies() {
        let row = fixture();
        let mut set = BTreeSet::new();
        assert!(!consume(&row, 1, 31, &mut set).unwrap_or(true));
        assert_eq!(
            set.iter().next().map(|r| (r.ifindex, r.address, r.prefix)),
            Some((7, Ipv4Addr::new(192, 0, 2, 5), 24))
        );
        assert!(consume(&row, 1, 31, &mut set).is_err());
        let mut foreign = row.clone();
        foreign[8..12].copy_from_slice(&2_u32.to_ne_bytes());
        assert!(consume(&foreign, 1, 31, &mut BTreeSet::new()).is_err());
        foreign = row.clone();
        foreign[12..16].copy_from_slice(&32_u32.to_ne_bytes());
        assert!(consume(&foreign, 1, 31, &mut BTreeSet::new()).is_err());
        foreign = row;
        foreign[6..8].copy_from_slice(&0x10_u16.to_ne_bytes());
        assert!(consume(&foreign, 1, 31, &mut BTreeSet::new()).is_err());
    }
    #[test]
    fn malformed_address_failures_are_strict() {
        let row = fixture();
        // An empty datagram is not a completed dump; the bounded socket
        // must continue until an authenticated NLMSG_DONE terminator.
        assert!(!consume(&[], 1, 31, &mut BTreeSet::new()).unwrap_or(true));
        for cut in [1, 15, 16, 23, 24, 28, 31] {
            assert!(consume(&row[..cut], 1, 31, &mut BTreeSet::new()).is_err());
        }
        let mut wrong = row.clone();
        wrong[17] = 33;
        assert!(consume(&wrong, 1, 31, &mut BTreeSet::new()).is_err());
        wrong = row.clone();
        wrong[28..32].copy_from_slice(&[0, 0, 0, 0]);
        assert!(consume(&wrong, 1, 31, &mut BTreeSet::new()).is_err());
        wrong = row;
        wrong[24..26].copy_from_slice(&9_u16.to_ne_bytes());
        assert!(consume(&wrong, 1, 31, &mut BTreeSet::new()).is_err());
    }
}
