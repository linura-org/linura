//! Bounded read-only rtnetlink policy routing witness for S18-6.
//!
//! This is NOT route reachability, DNS, Polkit consent or an execution grant.
//! Query all IPv4/IPv6 policy rules and route tables, not just /proc main.
//! A stable digest is only a drift witness, and can never authorize a toggle.

use std::collections::{BTreeMap, BTreeSet};
use std::thread;
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{self, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};
use sha2::{Digest, Sha256};

use linura_provider_sdk::ProviderError;

const MAX_PACKET: usize = 64 * 1024;
const MAX_TOTAL: usize = 256 * 1024;
const MAX_RECORDS: usize = 2048;
const MAX_ATTRIBUTES: usize = 256;
const PROBE_BUDGET: Duration = Duration::from_millis(350);
const NL_HEADER: usize = 16;
const RT_HEADER: usize = 12;
const DUMP_INTERRUPTED: u16 = 0x10;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWRULE: u16 = 32;
const RTM_GETRULE: u16 = 34;

fn deny(detail: &str) -> ProviderError {
    ProviderError::InvalidState(format!("native rtnetlink {detail}"))
}

fn u16_native(bytes: &[u8]) -> Result<u16, ProviderError> {
    let data: [u8; 2] = bytes
        .get(..2)
        .ok_or_else(|| deny("short u16"))?
        .try_into()
        .map_err(|_| deny("u16 conversion"))?;
    Ok(u16::from_ne_bytes(data))
}

fn u32_native(bytes: &[u8]) -> Result<u32, ProviderError> {
    let data: [u8; 4] = bytes
        .get(..4)
        .ok_or_else(|| deny("short u32"))?
        .try_into()
        .map_err(|_| deny("u32 conversion"))?;
    Ok(u32::from_ne_bytes(data))
}

fn aligned(n: usize) -> Result<usize, ProviderError> {
    n.checked_add(3)
        .map(|next| next & !3)
        .ok_or_else(|| deny("alignment overflow"))
}

fn validate_attributes(mut data: &[u8]) -> Result<(), ProviderError> {
    let mut count = 0_usize;
    while !data.is_empty() {
        if count >= MAX_ATTRIBUTES || data.len() < 4 {
            return Err(deny("attribute inventory incomplete"));
        }
        let length = usize::from(u16_native(data)?);
        if length < 4 || length > data.len() {
            return Err(deny("invalid attribute length"));
        }
        let next = aligned(length)?;
        if next > data.len() {
            return Err(deny("truncated attribute padding"));
        }
        data = &data[next..];
        count += 1;
    }
    Ok(())
}

/// Consume a bounded kernel-origin datagram, rejecting foreign sequence/port,
/// incomplete fragments, dump interruption and unexpected message families.
fn consume(
    mut datagram: &[u8],
    seq: u32,
    local_port: u32,
    expected: u16,
    family: u8,
    rows: &mut Vec<Vec<u8>>,
) -> Result<bool, ProviderError> {
    while !datagram.is_empty() {
        if datagram.len() < NL_HEADER {
            return Err(deny("truncated netlink header"));
        }
        let length =
            usize::try_from(u32_native(datagram)?).map_err(|_| deny("oversized message"))?;
        if length < NL_HEADER || length > datagram.len() {
            return Err(deny("invalid message length"));
        }
        let kind = u16_native(&datagram[4..])?;
        let flags = u16_native(&datagram[6..])?;
        let reply_seq = u32_native(&datagram[8..])?;
        let reply_port = u32_native(&datagram[12..])?;
        if reply_seq != seq || (reply_port != 0 && reply_port != local_port) {
            return Err(deny("reply belongs to another port or sequence"));
        }
        if flags & DUMP_INTERRUPTED != 0 {
            return Err(deny("kernel dump interrupted"));
        }
        let payload = &datagram[NL_HEADER..length];
        if kind == 2 {
            return Err(deny("kernel reported an error"));
        }
        if kind == 3 {
            if !(payload.is_empty() || (payload.len() == 4 && u32_native(payload)? == 0)) {
                return Err(deny("malformed completion status"));
            }
            if aligned(length)? != datagram.len() && length != datagram.len() {
                return Err(deny("trailing records after completion"));
            }
            return Ok(true);
        }
        if kind != expected || payload.len() < RT_HEADER || payload[0] != family {
            return Err(deny("unexpected route/rule record"));
        }
        validate_attributes(&payload[RT_HEADER..])?;
        if rows.len() >= MAX_RECORDS {
            return Err(deny("record limit exceeded"));
        }
        rows.push(payload.to_vec());
        let padded = aligned(length)?;
        if padded > datagram.len() {
            return Err(deny("truncated message alignment"));
        }
        datagram = &datagram[padded..];
    }
    Ok(false)
}

fn make_query(family: u8, kind: u16, seq: u32) -> [u8; 28] {
    let mut out = [0_u8; 28];
    out[..4].copy_from_slice(&28_u32.to_ne_bytes());
    out[4..6].copy_from_slice(&kind.to_ne_bytes());
    out[6..8].copy_from_slice(&0x301_u16.to_ne_bytes());
    out[8..12].copy_from_slice(&seq.to_ne_bytes());
    out[16] = family;
    out
}

/// An isolated nonblocking NETLINK_ROUTE socket; no arbitrary family, method,
/// destination or shell command is selectable by a client.
fn dump(family: u8, query: u16, expected: u16, seq: u32) -> Result<Vec<Vec<u8>>, ProviderError> {
    let fd = net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| deny("socket unavailable"))?;
    net::bind(&fd, &SocketAddrNetlink::new(0, 0)).map_err(|_| deny("socket bind failed"))?;
    let own = net::getsockname(&fd)
        .map_err(|_| deny("socket name unavailable"))
        .and_then(|addr| {
            SocketAddrNetlink::try_from(addr).map_err(|_| deny("incorrect socket family"))
        })?;
    if own.pid() == 0 {
        return Err(deny("unallocated port"));
    }
    let query_bytes = make_query(family, query, seq);
    if net::sendto(
        &fd,
        &query_bytes,
        SendFlags::empty(),
        &SocketAddrNetlink::new(0, 0),
    )
    .map_err(|_| deny("kernel query failed"))?
        != query_bytes.len()
    {
        return Err(deny("partial kernel query"));
    }
    let start = Instant::now();
    let mut rows = Vec::new();
    let mut total = 0_usize;
    loop {
        if start.elapsed() > PROBE_BUDGET {
            return Err(deny("kernel query deadline exceeded"));
        }
        let mut buffer = [0_u8; MAX_PACKET];
        match net::recvfrom(&fd, &mut buffer[..], RecvFlags::TRUNC) {
            Ok((received, length, address)) => {
                if length == 0 || length > MAX_PACKET || received != length {
                    return Err(deny("truncated or empty datagram"));
                }
                total = total
                    .checked_add(length)
                    .ok_or_else(|| deny("byte count overflow"))?;
                if total > MAX_TOTAL {
                    return Err(deny("total reply byte budget exceeded"));
                }
                let peer = address
                    .ok_or_else(|| deny("response has no sender"))
                    .and_then(|addr| {
                        SocketAddrNetlink::try_from(addr)
                            .map_err(|_| deny("wrong sender address family"))
                    })?;
                if peer.pid() != 0 || peer.groups() != 0 {
                    return Err(deny("netlink reply not from kernel"));
                }
                if consume(
                    &buffer[..received],
                    seq,
                    own.pid(),
                    expected,
                    family,
                    &mut rows,
                )? {
                    return Ok(rows);
                }
            }
            Err(Errno::AGAIN) => thread::sleep(Duration::from_millis(2)),
            Err(_) => return Err(deny("kernel read error")),
        }
    }
}

fn digest_dump(
    family: u8,
    kind: u16,
    record_type: u16,
    seq: u32,
) -> Result<[u8; 32], ProviderError> {
    let mut rows = dump(family, kind, record_type, seq)?;
    rows.sort();
    let mut hash = Sha256::new();
    hash.update(b"linura.s18.policy-dump.v1");
    hash.update([family]);
    hash.update(kind.to_ne_bytes());
    hash.update(
        u32::try_from(rows.len())
            .map_err(|_| deny("record count overflow"))?
            .to_ne_bytes(),
    );
    for row in rows {
        hash.update(
            u32::try_from(row.len())
                .map_err(|_| deny("record byte count overflow"))?
                .to_ne_bytes(),
        );
        hash.update(row);
    }
    Ok(hash.finalize().into())
}

/// A policy snapshot keeps rule continuity separate from routes attached to
/// individual kernel ifindices. A radio toggle legitimately may remove routes
/// on affected interfaces. This type never establishes effective connectivity,
/// DNS, remote-administration continuity or offline recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PolicyRouteSnapshot {
    rules_digest: [u8; 32],
    routes: BTreeMap<u32, RouteGroup>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RouteGroup {
    digest: [u8; 32],
    default_routes: u32,
}

fn output_ifindex(row: &[u8]) -> Result<(u32, bool), ProviderError> {
    if row.len() < RT_HEADER || !matches!(row[0], 2 | 10) {
        return Err(deny("route header family is unsupported"));
    }
    let default_route = row[1] == 0 && row[7] == 1;
    let mut attrs = &row[RT_HEADER..];
    let mut output = None;
    let mut ambiguous = false;
    while !attrs.is_empty() {
        if attrs.len() < 4 {
            return Err(deny("partial route attribute"));
        }
        let len = usize::from(u16_native(attrs)?);
        if len < 4 || len > attrs.len() {
            return Err(deny("invalid route attribute length"));
        }
        let kind = u16_native(&attrs[2..])? & 0x3fff;
        if kind == 4 {
            if len != 8 {
                return Err(deny("route output ifindex has invalid width"));
            }
            let index = u32_native(&attrs[4..8])?;
            if index == 0 || output.replace(index).is_some() {
                return Err(deny("route output ifindex is missing or duplicated"));
            }
        } else if kind == 9 || kind == 30 {
            // RTA_MULTIPATH and RTA_NH_ID may route through multiple links.
            // Refuse to attribute them to the one OIF even if it is present.
            ambiguous = true;
        }
        let padded = aligned(len)?;
        if padded > attrs.len() {
            return Err(deny("truncated route attribute padding"));
        }
        attrs = &attrs[padded..];
    }
    Ok((
        if ambiguous { 0 } else { output.unwrap_or(0) },
        default_route,
    ))
}

fn group_digest(mut rows: Vec<Vec<u8>>) -> Result<[u8; 32], ProviderError> {
    rows.sort();
    let mut hash = Sha256::new();
    hash.update(b"linura.s18-6.kernel-route-group.v1");
    hash.update(
        u32::try_from(rows.len())
            .map_err(|_| deny("route group exceeded count bound"))?
            .to_ne_bytes(),
    );
    for row in rows {
        hash.update(
            u32::try_from(row.len())
                .map_err(|_| deny("route byte count exceeded bound"))?
                .to_ne_bytes(),
        );
        hash.update(row);
    }
    Ok(hash.finalize().into())
}

impl PolicyRouteSnapshot {
    fn from_rows(
        rules_digest: [u8; 32],
        families: [(u8, Vec<Vec<u8>>); 2],
    ) -> Result<Self, ProviderError> {
        let mut grouped: BTreeMap<u32, (Vec<Vec<u8>>, u32)> = BTreeMap::new();
        let mut total = 0_usize;
        for (family, rows) in families {
            for row in rows {
                total = total
                    .checked_add(1)
                    .ok_or_else(|| deny("route count overflow"))?;
                if total > MAX_RECORDS * 2 || row.first() != Some(&family) {
                    return Err(deny("route inventory exceeded bound or changed family"));
                }
                let (index, is_default) = output_ifindex(&row)?;
                let entry = grouped.entry(index).or_default();
                if is_default {
                    entry.1 = entry
                        .1
                        .checked_add(1)
                        .ok_or_else(|| deny("default route overflow"))?;
                }
                let mut canonical = Vec::with_capacity(row.len() + 1);
                canonical.push(family);
                canonical.extend_from_slice(&row);
                entry.0.push(canonical);
            }
        }
        let routes = grouped
            .into_iter()
            .map(|(index, (rows, default_routes))| {
                Ok((
                    index,
                    RouteGroup {
                        digest: group_digest(rows)?,
                        default_routes,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, ProviderError>>()?;
        Ok(Self {
            rules_digest,
            routes,
        })
    }

    /// Conservative diagnostic-only policy readback. Require *all* policy
    /// rules unchanged, and all routes on unaffected/unknown ifindices
    /// unchanged. Only routes for explicitly affected kernel links may vary.
    /// Disabled links must not retain an IPv4/IPv6 default route in any table.
    pub(super) fn require_affected_only_change(
        &self,
        after: &Self,
        affected: &BTreeSet<u32>,
        disabling: bool,
    ) -> Result<(), ProviderError> {
        if self.rules_digest != after.rules_digest || affected.contains(&0) {
            return Err(deny("radio readback policy rule or affected index changed"));
        }
        for index in self.routes.keys().chain(after.routes.keys()) {
            if !affected.contains(index) && self.routes.get(index) != after.routes.get(index) {
                return Err(deny(
                    "radio changed routes on an unaffected or unknown link",
                ));
            }
        }
        if disabling
            && (after
                .routes
                .get(&0)
                .is_some_and(|group| group.default_routes != 0)
                || affected.iter().any(|index| {
                    after
                        .routes
                        .get(index)
                        .is_some_and(|group| group.default_routes != 0)
                }))
        {
            return Err(deny(
                "disabled link retained an unverified policy default route",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn fixture(rule_byte: u8) -> Self {
        Self {
            rules_digest: [rule_byte; 32],
            routes: BTreeMap::new(),
        }
    }
}

/// A fresh, bounded two-family route/rule inventory. Not a policy-selected
/// route or DNS oracle: the original session and effect journal are still
/// required, and the completed readback is never an authorization grant.
pub(super) fn policy_snapshot() -> Result<PolicyRouteSnapshot, ProviderError> {
    let first = digest_dump(2, RTM_GETRULE, RTM_NEWRULE, 1)?;
    let second = digest_dump(10, RTM_GETRULE, RTM_NEWRULE, 2)?;
    let mut hash = Sha256::new();
    hash.update(b"linura.s18-6.policy-rules.v1");
    hash.update(first);
    hash.update(second);
    let rules_digest = hash.finalize().into();
    PolicyRouteSnapshot::from_rows(
        rules_digest,
        [
            (2, dump(2, RTM_GETROUTE, RTM_NEWROUTE, 3)?),
            (10, dump(10, RTM_GETROUTE, RTM_NEWROUTE, 4)?),
        ],
    )
}

/// Ask the Linux FIB for the original socket's source/UID-conditioned egress.
///
/// This is an *independent diagnostic*, not proof of an actual remote
/// administration path: SO_MARK, cgroups, VPN interception, mutable routing,
/// connection liveness, and offline recovery remain unverified. A future
/// safety authority MUST NOT use this result alone.
/// Bind the destination lookup to the kernel-reported local socket address
/// and socket-owner UID. This does not cover SO_MARK, the original task's
/// security label, VPN overlays or an independently proven remote path.
pub(super) fn source_uid_selected_oif(
    remote: std::net::IpAddr,
    source: std::net::IpAddr,
    uid: u32,
) -> Result<u32, ProviderError> {
    let (family, query) = source_uid_query(remote, source, uid)?;
    const SEQUENCE: u32 = 7;
    let fd = net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| deny("route lookup socket unavailable"))?;
    net::bind(&fd, &SocketAddrNetlink::new(0, 0)).map_err(|_| deny("route lookup bind failed"))?;
    let own = net::getsockname(&fd)
        .map_err(|_| deny("route lookup port missing"))
        .and_then(|addr| {
            SocketAddrNetlink::try_from(addr)
                .map_err(|_| deny("route lookup address family invalid"))
        })?;
    if own.pid() == 0
        || net::sendto(
            &fd,
            &query,
            SendFlags::empty(),
            &SocketAddrNetlink::new(0, 0),
        )
        .map_err(|_| deny("route lookup send failed"))?
            != query.len()
    {
        return Err(deny("route lookup had invalid sender or partial write"));
    }
    let started = Instant::now();
    loop {
        if started.elapsed() >= PROBE_BUDGET {
            return Err(deny("route lookup exceeded bounded kernel deadline"));
        }
        let mut buffer = [0_u8; MAX_PACKET];
        match net::recvfrom(&fd, &mut buffer, RecvFlags::TRUNC) {
            Ok((received, length, sender)) => {
                if received == 0 || received != length || received > MAX_PACKET {
                    return Err(deny("route lookup response is truncated"));
                }
                let peer = sender
                    .ok_or_else(|| deny("route lookup sender missing"))
                    .and_then(|addr| {
                        SocketAddrNetlink::try_from(addr)
                            .map_err(|_| deny("route lookup peer family invalid"))
                    })?;
                if peer.pid() != 0 || peer.groups() != 0 {
                    return Err(deny("route lookup response not from kernel"));
                }
                return selected_route_reply(&buffer[..received], family, SEQUENCE, own.pid());
            }
            Err(Errno::AGAIN) => thread::sleep(Duration::from_millis(2)),
            Err(_) => return Err(deny("route lookup kernel read failed")),
        }
    }
}

fn source_uid_query(
    remote: std::net::IpAddr,
    source: std::net::IpAddr,
    uid: u32,
) -> Result<(u8, Vec<u8>), ProviderError> {
    let (family, destination, local): (u8, Vec<u8>, Vec<u8>) = match (remote, source) {
        (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
            (2, dst.octets().to_vec(), src.octets().to_vec())
        }
        (std::net::IpAddr::V6(dst), std::net::IpAddr::V6(src)) => {
            (10, dst.octets().to_vec(), src.octets().to_vec())
        }
        _ => {
            return Err(deny(
                "remote socket and kernel source have different address families",
            ));
        }
    };
    if remote.is_unspecified()
        || remote.is_multicast()
        || source.is_unspecified()
        || source.is_multicast()
    {
        return Err(deny("remote route target or local source is not unicast"));
    }
    const SEQUENCE: u32 = 7;
    const REQUEST: u16 = 1;
    const RTA_DST: u16 = 1;
    const RTA_SRC: u16 = 2;
    const RTA_UID: u16 = 25;
    let destination_len = 4 + destination.len();
    let source_len = 4 + local.len();
    let len = NL_HEADER + RT_HEADER + destination_len + source_len + 8;
    let mut query = vec![0_u8; len];
    query[..4].copy_from_slice(
        &u32::try_from(len)
            .map_err(|_| deny("route query length overflow"))?
            .to_ne_bytes(),
    );
    query[4..6].copy_from_slice(&RTM_GETROUTE.to_ne_bytes());
    query[6..8].copy_from_slice(&REQUEST.to_ne_bytes());
    query[8..12].copy_from_slice(&SEQUENCE.to_ne_bytes());
    query[NL_HEADER] = family;
    query[NL_HEADER + 1] = u8::try_from(destination.len() * 8)
        .map_err(|_| deny("invalid destination prefix width"))?;
    query[NL_HEADER + 2] =
        u8::try_from(local.len() * 8).map_err(|_| deny("invalid source prefix width"))?;

    let dst_offset = NL_HEADER + RT_HEADER;
    query[dst_offset..dst_offset + 2].copy_from_slice(
        &u16::try_from(destination_len)
            .map_err(|_| deny("invalid destination attribute"))?
            .to_ne_bytes(),
    );
    query[dst_offset + 2..dst_offset + 4].copy_from_slice(&RTA_DST.to_ne_bytes());
    query[dst_offset + 4..dst_offset + destination_len].copy_from_slice(&destination);

    let src_offset = dst_offset + destination_len;
    query[src_offset..src_offset + 2].copy_from_slice(
        &u16::try_from(source_len)
            .map_err(|_| deny("invalid source attribute"))?
            .to_ne_bytes(),
    );
    query[src_offset + 2..src_offset + 4].copy_from_slice(&RTA_SRC.to_ne_bytes());
    query[src_offset + 4..src_offset + source_len].copy_from_slice(&local);

    let uid_offset = src_offset + source_len;
    query[uid_offset..uid_offset + 2].copy_from_slice(&8_u16.to_ne_bytes());
    query[uid_offset + 2..uid_offset + 4].copy_from_slice(&RTA_UID.to_ne_bytes());
    query[uid_offset + 4..uid_offset + 8].copy_from_slice(&uid.to_ne_bytes());
    Ok((family, query))
}

fn selected_route_reply(
    packet: &[u8],
    family: u8,
    sequence: u32,
    local_port: u32,
) -> Result<u32, ProviderError> {
    if packet.len() < NL_HEADER + RT_HEADER {
        return Err(deny("route lookup response is short"));
    }
    let len =
        usize::try_from(u32_native(packet)?).map_err(|_| deny("route lookup length overflow"))?;
    let flags = u16_native(&packet[6..])?;
    if len < NL_HEADER + RT_HEADER
        || len > packet.len()
        || (aligned(len)? != packet.len() && len != packet.len())
        || u16_native(&packet[4..])? != RTM_NEWROUTE
        || flags & (DUMP_INTERRUPTED | 0x2) != 0
        || u32_native(&packet[8..])? != sequence
    {
        return Err(deny("route lookup replied with an invalid kernel record"));
    }
    let sender_port = u32_native(&packet[12..])?;
    if sender_port != 0 && sender_port != local_port {
        return Err(deny("route lookup response belongs to another port"));
    }
    let row = &packet[NL_HEADER..len];
    if row[0] != family || row[7] != 1 {
        // The kernel may return an unreachable, blackhole, prohibit or
        // unknown route with a nominal output interface. Such a reply is
        // never evidence of a viable unicast administration path.
        return Err(deny("route lookup family or unicast type is invalid"));
    }
    validate_attributes(&row[RT_HEADER..])?;
    let (ifindex, _) = output_ifindex(row)?;
    if ifindex == 0 {
        return Err(deny("route lookup has ambiguous or missing egress device"));
    }
    Ok(ifindex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: u16, family: u8, seq: u32, port: u32, flags: u16) -> Vec<u8> {
        let len = if kind == 3 { 16 } else { 28 };
        let mut result = vec![0_u8; len];
        result[..4].copy_from_slice(&(len as u32).to_ne_bytes());
        result[4..6].copy_from_slice(&kind.to_ne_bytes());
        result[6..8].copy_from_slice(&flags.to_ne_bytes());
        result[8..12].copy_from_slice(&seq.to_ne_bytes());
        result[12..16].copy_from_slice(&port.to_ne_bytes());
        if len > 16 {
            result[16] = family;
        }
        result
    }

    #[test]
    fn typed_dump_is_complete_only_after_kernel_done() {
        let mut rows = Vec::new();
        assert_eq!(
            consume(
                &message(RTM_NEWRULE, 2, 7, 0, 2),
                7,
                42,
                RTM_NEWRULE,
                2,
                &mut rows
            )
            .ok(),
            Some(false)
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(
            consume(&message(3, 0, 7, 0, 2), 7, 42, RTM_NEWRULE, 2, &mut rows).ok(),
            Some(true)
        );
    }

    #[test]
    fn foreign_family_sequence_port_and_interruption_are_denied() {
        let record = message(RTM_NEWROUTE, 10, 3, 0, 2);
        assert!(consume(&record, 3, 42, RTM_NEWROUTE, 2, &mut Vec::new()).is_err());
        assert!(consume(&record, 2, 42, RTM_NEWROUTE, 10, &mut Vec::new()).is_err());
        assert!(consume(&record, 3, 42, RTM_NEWRULE, 10, &mut Vec::new()).is_err());
        assert!(
            consume(
                &message(RTM_NEWROUTE, 10, 3, 15, 2),
                3,
                42,
                RTM_NEWROUTE,
                10,
                &mut Vec::new()
            )
            .is_err()
        );
        assert!(
            consume(
                &message(RTM_NEWROUTE, 10, 3, 0, DUMP_INTERRUPTED),
                3,
                42,
                RTM_NEWROUTE,
                10,
                &mut Vec::new()
            )
            .is_err()
        );
    }

    fn output_row(family: u8, index: Option<u32>, is_default: bool) -> Vec<u8> {
        let mut row = vec![0_u8; RT_HEADER];
        row[0] = family;
        row[1] = if is_default { 0 } else { 24 };
        row[7] = 1;
        if let Some(index) = index {
            row.extend_from_slice(&8_u16.to_ne_bytes());
            row.extend_from_slice(&4_u16.to_ne_bytes());
            row.extend_from_slice(&index.to_ne_bytes());
        }
        row
    }

    fn routing(rows: Vec<Vec<u8>>, rule: u8) -> PolicyRouteSnapshot {
        PolicyRouteSnapshot::from_rows([rule; 32], [(2, rows), (10, Vec::new())])
            .unwrap_or_else(|error| unreachable!("known route fixture: {error:?}"))
    }

    #[test]
    fn radio_readback_allows_only_affected_routes_to_withdraw() {
        let before = routing(
            vec![output_row(2, Some(3), true), output_row(2, Some(5), true)],
            1,
        );
        let after = routing(vec![output_row(2, Some(5), true)], 1);
        let affected = BTreeSet::from([3]);
        assert!(
            before
                .require_affected_only_change(&after, &affected, true)
                .is_ok()
        );
        assert!(
            before
                .require_affected_only_change(&before, &affected, true)
                .is_err()
        );
        let unrelated = routing(vec![output_row(2, Some(3), true)], 1);
        assert!(
            before
                .require_affected_only_change(&unrelated, &affected, true)
                .is_err()
        );
        let changed_rules = routing(vec![output_row(2, Some(5), true)], 2);
        assert!(
            before
                .require_affected_only_change(&changed_rules, &affected, true)
                .is_err()
        );
        let unknown_default = routing(
            vec![output_row(2, None, true), output_row(2, Some(5), true)],
            1,
        );
        assert!(
            before
                .require_affected_only_change(&unknown_default, &affected, true)
                .is_err()
        );
        assert!(
            before
                .require_affected_only_change(&after, &BTreeSet::from([0]), true)
                .is_err()
        );
    }

    #[test]
    fn route_output_identity_denies_duplicate_ambiguous_and_malformed_attributes() {
        let mut row = output_row(2, Some(3), true);
        row.extend_from_slice(&8_u16.to_ne_bytes());
        row.extend_from_slice(&4_u16.to_ne_bytes());
        row.extend_from_slice(&3_u32.to_ne_bytes());
        assert!(output_ifindex(&row).is_err());
        let mut malformed = output_row(2, None, true);
        malformed.extend_from_slice(&3_u16.to_ne_bytes());
        malformed.extend_from_slice(&4_u16.to_ne_bytes());
        assert!(output_ifindex(&malformed).is_err());
        let mut multipath = output_row(2, Some(3), true);
        multipath.extend_from_slice(&4_u16.to_ne_bytes());
        multipath.extend_from_slice(&9_u16.to_ne_bytes());
        assert_eq!(output_ifindex(&multipath).ok(), Some((0, true)));
    }

    #[test]
    fn remote_fib_query_preserves_exact_socket_source_and_uid() {
        let dst: std::net::IpAddr = "10.0.0.2".parse().unwrap_or_else(|e| unreachable!("{e}"));
        let src: std::net::IpAddr = "10.0.0.1".parse().unwrap_or_else(|e| unreachable!("{e}"));
        let (family, query) =
            source_uid_query(dst, src, 1000).unwrap_or_else(|e| unreachable!("{e:?}"));
        assert_eq!(family, 2);
        assert_eq!(query.len(), NL_HEADER + RT_HEADER + 8 + 8 + 8);
        assert_eq!(query[NL_HEADER + 1], 32);
        assert_eq!(query[NL_HEADER + 2], 32);
        assert_eq!(
            u16_native(&query[NL_HEADER + RT_HEADER + 2..]).ok(),
            Some(1)
        );
        assert_eq!(
            &query[NL_HEADER + RT_HEADER + 4..NL_HEADER + RT_HEADER + 8],
            &[10, 0, 0, 2]
        );
        let source_offset = NL_HEADER + RT_HEADER + 8;
        assert_eq!(u16_native(&query[source_offset + 2..]).ok(), Some(2));
        assert_eq!(&query[source_offset + 4..source_offset + 8], &[10, 0, 0, 1]);
        let uid_offset = source_offset + 8;
        assert_eq!(u16_native(&query[uid_offset + 2..]).ok(), Some(25));
        assert_eq!(u32_native(&query[uid_offset + 4..]).ok(), Some(1000));
        assert!(
            source_uid_query(
                dst,
                "::1".parse().unwrap_or_else(|e| unreachable!("{e}")),
                1000
            )
            .is_err()
        );
        assert!(
            source_uid_query(
                dst,
                "0.0.0.0".parse().unwrap_or_else(|e| unreachable!("{e}")),
                1000
            )
            .is_err()
        );
    }

    #[test]
    fn selected_fib_egress_never_accepts_foreign_or_ambiguous_kernel_reply() {
        let mut packet = message(RTM_NEWROUTE, 2, 7, 0, 0);
        packet.extend_from_slice(&8_u16.to_ne_bytes());
        packet.extend_from_slice(&4_u16.to_ne_bytes());
        packet.extend_from_slice(&3_u32.to_ne_bytes());
        packet[..4].copy_from_slice(&36_u32.to_ne_bytes());
        packet[NL_HEADER + 7] = 1; // RTN_UNICAST, never blackhole/prohibit.
        assert_eq!(selected_route_reply(&packet, 2, 7, 42).ok(), Some(3));

        let mut wrong = packet.clone();
        wrong[8..12].copy_from_slice(&8_u32.to_ne_bytes());
        assert!(selected_route_reply(&wrong, 2, 7, 42).is_err());
        wrong = packet.clone();
        wrong[12..16].copy_from_slice(&44_u32.to_ne_bytes());
        assert!(selected_route_reply(&wrong, 2, 7, 42).is_err());
        wrong = packet.clone();
        wrong[6..8].copy_from_slice(&2_u16.to_ne_bytes());
        assert!(selected_route_reply(&wrong, 2, 7, 42).is_err());
        wrong = packet.clone();
        wrong[4..6].copy_from_slice(&RTM_NEWRULE.to_ne_bytes());
        assert!(selected_route_reply(&wrong, 2, 7, 42).is_err());
        wrong = packet.clone();
        wrong[16] = 10;
        assert!(selected_route_reply(&wrong, 2, 7, 42).is_err());
        wrong = packet.clone();
        wrong[NL_HEADER + 7] = 6; // RTN_BLACKHOLE cannot preserve administration.
        assert!(selected_route_reply(&wrong, 2, 7, 42).is_err());
        wrong = packet.clone();
        wrong[NL_HEADER + RT_HEADER + 2..NL_HEADER + RT_HEADER + 4]
            .copy_from_slice(&9_u16.to_ne_bytes());
        assert!(selected_route_reply(&wrong, 2, 7, 42).is_err());
        assert!(selected_route_reply(&packet[..30], 2, 7, 42).is_err());
        assert!(selected_route_reply(&message(RTM_NEWROUTE, 2, 7, 0, 0), 2, 7, 42).is_err());
    }

    #[test]
    fn malformed_attributes_lengths_and_error_terminators_are_denied() {
        let mut bad = message(RTM_NEWRULE, 2, 3, 0, 2);
        bad.extend_from_slice(&[3, 0, 1, 0]);
        bad[..4].copy_from_slice(&32_u32.to_ne_bytes());
        assert!(consume(&bad, 3, 42, RTM_NEWRULE, 2, &mut Vec::new()).is_err());
        let mut oversized = message(RTM_NEWRULE, 2, 3, 0, 2);
        oversized[..4].copy_from_slice(&65_000_u32.to_ne_bytes());
        assert!(consume(&oversized, 3, 42, RTM_NEWRULE, 2, &mut Vec::new()).is_err());
        assert!(
            consume(
                &message(2, 2, 3, 0, 2),
                3,
                42,
                RTM_NEWRULE,
                2,
                &mut Vec::new()
            )
            .is_err()
        );
    }
}
