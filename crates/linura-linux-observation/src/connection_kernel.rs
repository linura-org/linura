//! S18-7 independent, read-only kernel network-route witness.
//!
//! /proc/net/route and /proc/net/ipv6_route expose kernel route tables, not
//! authoritative policy routing, effective DNS, local recovery, off-box
//! reachability or the original user's marked socket. The witness can veto
//! inconsistent provider claims; it must NEVER authorize connectivity loss.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Instant;

use crate::connection_ipv4::{self, Ipv4KernelAddress};
use linura_provider_sdk::ProviderError;

const MAX_KERNEL_BYTES: u64 = 256 * 1024;
const MAX_ROUTES: usize = 4096;
const MAX_AGE_MS: u128 = 2000;

fn deny(reason: &str) -> ProviderError {
    ProviderError::InvalidState(format!("native kernel connection {reason}"))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct KernelRoute {
    family: u8,
    interface: String,
    destination: String,
    prefix: u8,
    gateway: String,
    metric: u32,
    flags: u32,
}

impl KernelRoute {
    fn is_default(&self) -> bool {
        self.prefix == 0 && (self.destination == "0.0.0.0" || self.destination == "::")
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct KernelV6Address {
    interface: String,
    address: String,
    prefix: u8,
    ifindex: u32,
    scope: u32,
    flags: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KernelRows {
    routes: BTreeSet<KernelRoute>,
    addresses_v4: BTreeSet<Ipv4KernelAddress>,
    addresses_v6: BTreeSet<KernelV6Address>,
    namespace: u64,
}

#[derive(Clone, Debug)]
pub(super) struct KernelConnectionSnapshot {
    rows: KernelRows,
    sampled_at: Instant,
}

impl KernelConnectionSnapshot {
    pub(super) fn require_same_source(&self, next: &Self) -> Result<(), ProviderError> {
        if self.rows != next.rows
            || next.sampled_at <= self.sampled_at
            || next.sampled_at.duration_since(self.sampled_at).as_millis() > MAX_AGE_MS
        {
            return Err(deny(
                "kernel witness changed during live NetworkManager observation",
            ));
        }
        Ok(())
    }

    /// Exact current IPv4/IPv6 main-table default route presence, not a
    /// promise that policy routing, VPN, split DNS or remote reachability work.
    pub(super) fn main_default_for(&self, family: u8, interface: &str) -> bool {
        self.rows.routes.iter().any(|route| {
            route.family == family && route.interface == interface && route.is_default()
        })
    }

    /// Verify the actual kernel ifindex owns exactly the IPv4 addresses that
    /// the fresh NetworkManager IPConfig claims. Extra kernel or provider
    /// addresses veto settlement. This is NOT effective routing or DNS proof.
    pub(super) fn require_provider_ipv4(
        &self,
        ifindex: u32,
        configured: &[String],
    ) -> Result<(), ProviderError> {
        if ifindex == 0 || configured.len() > 128 {
            return Err(deny("unbounded or unspecified IPv4 device"));
        }
        let mut asserted = BTreeSet::new();
        for item in configured {
            let (address, prefix) = item
                .split_once('/')
                .ok_or_else(|| deny("invalid NetworkManager IPv4 address"))?;
            let ip: std::net::Ipv4Addr = address
                .parse()
                .map_err(|_| deny("invalid provider IPv4 address"))?;
            let mask: u8 = prefix
                .parse()
                .map_err(|_| deny("invalid provider IPv4 prefix"))?;
            if mask > 32 || !asserted.insert((ip, mask)) {
                return Err(deny("duplicate or invalid provider IPv4 address"));
            }
        }
        let actual: BTreeSet<_> = self
            .rows
            .addresses_v4
            .iter()
            .filter(|value| value.ifindex == ifindex)
            .map(|value| (value.address, value.prefix))
            .collect();
        if actual != asserted {
            return Err(deny("kernel IPv4 addresses disagree with NetworkManager"));
        }
        Ok(())
    }

    /// Cross-check NM IPv6 address rows against the kernel's independent
    /// /proc/net/if_inet6 view on the exact original ifindex. Link-local and
    /// temporary addresses may be present beyond the NM projection; extra
    /// kernel addresses never confer a successful routing or DNS claim.
    pub(super) fn require_provider_ipv6(
        &self,
        ifindex: u32,
        configured: &[String],
    ) -> Result<(), ProviderError> {
        if ifindex == 0 || configured.len() > 128 {
            return Err(deny("unbounded or unspecified IPv6 device"));
        }
        let mut asserted = BTreeSet::new();
        for item in configured {
            let (address, prefix) = item
                .split_once('/')
                .ok_or_else(|| deny("invalid NetworkManager IPv6 address"))?;
            let ip: std::net::Ipv6Addr = address
                .parse()
                .map_err(|_| deny("invalid provider IPv6 address"))?;
            let mask: u8 = prefix
                .parse()
                .map_err(|_| deny("invalid provider IPv6 prefix"))?;
            if mask > 128
                || ip.is_unspecified()
                || ip.is_multicast()
                || !asserted.insert((ip.to_string(), mask))
            {
                return Err(deny("duplicate or unusable provider IPv6 address"));
            }
        }
        for (address, mask) in asserted {
            if !self.rows.addresses_v6.iter().any(|row| {
                row.ifindex == ifindex
                    && row.address == address
                    && row.prefix == mask
                    && row.flags & (0x04 | 0x08 | 0x20 | 0x40) == 0
            }) {
                return Err(deny("kernel IPv6 address is absent, unready or foreign"));
            }
        }
        Ok(())
    }

    /// An unrelated main-table route/address disappearing or being modified
    /// is an independent reason to deny settlement.
    pub(super) fn require_unaffected_stable(
        &self,
        after: &Self,
        target: &str,
        target_ifindex: u32,
    ) -> Result<(), ProviderError> {
        let other_routes = |rows: &KernelRows| {
            rows.routes
                .iter()
                .filter(|route| route.interface != target)
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        let other_v6 = |rows: &KernelRows| {
            rows.addresses_v6
                .iter()
                .filter(|address| address.interface != target)
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        let other_v4 = |rows: &KernelRows| {
            rows.addresses_v4
                .iter()
                .filter(|address| address.ifindex != target_ifindex)
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        if target_ifindex == 0
            || self.rows.namespace == 0
            || self.rows.namespace != after.rows.namespace
            || other_v4(&self.rows) != other_v4(&after.rows)
            || self.sampled_at >= after.sampled_at
            || after.sampled_at.duration_since(self.sampled_at).as_millis() > 15_000
            || other_routes(&self.rows) != other_routes(&after.rows)
            || other_v6(&self.rows) != other_v6(&after.rows)
        {
            return Err(deny(
                "kernel namespace or unaffected routes/IPv6 addresses changed",
            ));
        }
        Ok(())
    }

    /// A kernel default route remaining on the detached device contradicts
    /// deactivation. Missing fallback on *either* affected family is another
    /// reason to deny, never proof that surviving routes actually work.
    pub(super) fn require_deactivated(
        &self,
        after: &Self,
        target: &str,
        target_ifindex: u32,
    ) -> Result<(), ProviderError> {
        self.require_unaffected_stable(after, target, target_ifindex)?;
        if after
            .rows
            .addresses_v4
            .iter()
            .any(|address| address.ifindex == target_ifindex)
        {
            return Err(deny("deactivated device retains kernel IPv4 addresses"));
        }
        for family in [4, 6] {
            if after.main_default_for(family, target) {
                return Err(deny("deactivated device retains main default route"));
            }
            if self.main_default_for(family, target)
                && !after.rows.routes.iter().any(|route| {
                    route.family == family && route.interface != target && route.is_default()
                })
            {
                return Err(deny("deactivation lost the last main-table default route"));
            }
        }
        Ok(())
    }

    /// The absence of marked socket routing, effective DNS and independently
    /// verified offline local restoration forbids promoting this to a permit.
    #[must_use]
    pub(super) const fn proves_safe_effective_routing_or_recovery(&self) -> bool {
        false
    }

    #[cfg(test)]
    pub(super) fn with_fallback_fixture(target: &str, active: bool, ifindex: u32) -> Self {
        let mut routes = BTreeSet::from([KernelRoute {
            family: 4,
            interface: "eth0".into(),
            destination: "0.0.0.0".into(),
            prefix: 0,
            gateway: "10.0.0.1".into(),
            metric: 100,
            flags: 3,
        }]);
        if active {
            routes.insert(KernelRoute {
                family: 4,
                interface: target.to_owned(),
                destination: "0.0.0.0".into(),
                prefix: 0,
                gateway: "192.168.1.1".into(),
                metric: 200,
                flags: 3,
            });
        }
        let addresses_v4 = if active {
            BTreeSet::from([Ipv4KernelAddress {
                ifindex,
                address: std::net::Ipv4Addr::new(10, 0, 0, 4),
                prefix: 24,
            }])
        } else {
            BTreeSet::new()
        };
        Self::fixture(KernelRows {
            routes,
            addresses_v4,
            addresses_v6: BTreeSet::new(),
            namespace: 7,
        })
    }

    #[cfg(test)]
    fn fixture(rows: KernelRows) -> Self {
        Self {
            rows,
            sampled_at: Instant::now(),
        }
    }
}

fn bounded_kernel_file(path: &Path) -> Result<String, ProviderError> {
    let file = File::open(path).map_err(|_| deny("kernel route source unavailable"))?;
    let mut bytes = Vec::new();
    file.take(MAX_KERNEL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| deny("kernel route source read failed"))?;
    if bytes.len() as u64 > MAX_KERNEL_BYTES {
        return Err(deny("kernel route source exceeded bounded budget"));
    }
    String::from_utf8(bytes).map_err(|_| deny("kernel route source has invalid encoding"))
}

fn kernel_interface(name: &str) -> Result<&str, ProviderError> {
    if name.is_empty()
        || name.len() > 15
        || name == "."
        || name == ".."
        || name.starts_with('-')
        || name
            .bytes()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'@')))
    {
        return Err(deny("kernel route interface name is invalid"));
    }
    Ok(name)
}

fn ipv4_le(value: &str) -> Result<String, ProviderError> {
    if value.len() != 8 {
        return Err(deny("invalid kernel IPv4 byte width"));
    }
    let word = u32::from_str_radix(value, 16)
        .map_err(|_| deny("invalid kernel IPv4 hexadecimal value"))?;
    Ok(std::net::Ipv4Addr::from(word.to_le_bytes()).to_string())
}

fn ipv6_kernel_hex(value: &str) -> Result<String, ProviderError> {
    if value.len() != 32 {
        return Err(deny("invalid kernel IPv6 byte width"));
    }
    let mut addr = [0u8; 16];
    for (n, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let s = std::str::from_utf8(pair).map_err(|_| deny("invalid kernel IPv6 encoding"))?;
        addr[n] = u8::from_str_radix(s, 16).map_err(|_| deny("invalid kernel IPv6 hex digit"))?;
    }
    Ok(std::net::Ipv6Addr::from(addr).to_string())
}

fn ipv4_prefix(mask: &str) -> Result<u8, ProviderError> {
    let bits = u32::from_str_radix(mask, 16).map_err(|_| deny("invalid IPv4 route mask"))?;
    let network = bits.to_be();
    let prefix = network.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if network != expected {
        return Err(deny("kernel IPv4 route mask is not contiguous"));
    }
    Ok(prefix)
}

fn push_route(result: &mut BTreeSet<KernelRoute>, row: KernelRoute) -> Result<(), ProviderError> {
    if result.len() >= MAX_ROUTES || !result.insert(row) {
        return Err(deny("route inventory overflow or duplicate"));
    }
    Ok(())
}

fn parse_v4_routes(text: &str, routes: &mut BTreeSet<KernelRoute>) -> Result<(), ProviderError> {
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| deny("missing IPv4 route table header"))?;
    if !header.contains("Iface") || !header.contains("Destination") || !header.contains("Mask") {
        return Err(deny("unexpected IPv4 route table header"));
    }
    for (index, line) in lines.enumerate() {
        if index >= MAX_ROUTES {
            return Err(deny("IPv4 route inventory exceeded"));
        }
        let row: Vec<_> = line.split_ascii_whitespace().collect();
        if row.len() != 11 {
            return Err(deny("invalid IPv4 route table row"));
        }
        let interface = kernel_interface(row[0])?.to_owned();
        let flags =
            u32::from_str_radix(row[3], 16).map_err(|_| deny("invalid IPv4 route flags"))?;
        if flags & 1 == 0 || flags & 0x200 != 0 {
            return Err(deny("IPv4 route is down or rejecting packets"));
        }
        let metric: u32 = row[6]
            .parse()
            .map_err(|_| deny("invalid IPv4 route metric"))?;
        push_route(
            routes,
            KernelRoute {
                family: 4,
                interface,
                destination: ipv4_le(row[1])?,
                prefix: ipv4_prefix(row[7])?,
                gateway: ipv4_le(row[2])?,
                metric,
                flags,
            },
        )?;
    }
    Ok(())
}

fn parse_v6_routes(text: &str, routes: &mut BTreeSet<KernelRoute>) -> Result<(), ProviderError> {
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_ROUTES {
            return Err(deny("IPv6 route inventory exceeded"));
        }
        let row: Vec<_> = line.split_ascii_whitespace().collect();
        if row.len() != 10 {
            return Err(deny("invalid IPv6 route table row"));
        }
        let prefix =
            u8::from_str_radix(row[1], 16).map_err(|_| deny("invalid IPv6 route prefix"))?;
        let source_prefix =
            u8::from_str_radix(row[3], 16).map_err(|_| deny("invalid IPv6 source prefix"))?;
        if prefix > 128 || source_prefix > 128 {
            return Err(deny("invalid IPv6 route prefix width"));
        }
        let _ = ipv6_kernel_hex(row[2])?;
        let metric = u32::from_str_radix(row[5], 16).map_err(|_| deny("invalid IPv6 metric"))?;
        let flags =
            u32::from_str_radix(row[8], 16).map_err(|_| deny("invalid IPv6 route flags"))?;
        let _ = u32::from_str_radix(row[6], 16)
            .map_err(|_| deny("invalid IPv6 kernel route reference"))?;
        let _ =
            u32::from_str_radix(row[7], 16).map_err(|_| deny("invalid IPv6 kernel route usage"))?;
        // Linux RTF_UP for IPv6; do not infer an RTN_UNICAST from flags.
        if flags & 1 == 0 || flags & 0x200 != 0 {
            return Err(deny("IPv6 route is down or rejecting packets"));
        }
        push_route(
            routes,
            KernelRoute {
                family: 6,
                interface: kernel_interface(row[9])?.to_owned(),
                destination: ipv6_kernel_hex(row[0])?,
                prefix,
                gateway: ipv6_kernel_hex(row[4])?,
                metric,
                flags,
            },
        )?;
    }
    Ok(())
}

fn parse_v6_addresses(text: &str) -> Result<BTreeSet<KernelV6Address>, ProviderError> {
    let mut result = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_ROUTES {
            return Err(deny("IPv6 address inventory exceeded"));
        }
        let row: Vec<_> = line.split_ascii_whitespace().collect();
        if row.len() != 6 {
            return Err(deny("invalid kernel IPv6 address row"));
        }
        let ifindex =
            u32::from_str_radix(row[1], 16).map_err(|_| deny("invalid IPv6 address ifindex"))?;
        let prefix =
            u8::from_str_radix(row[2], 16).map_err(|_| deny("invalid IPv6 address prefix"))?;
        let scope =
            u32::from_str_radix(row[3], 16).map_err(|_| deny("invalid IPv6 address scope"))?;
        let flags =
            u32::from_str_radix(row[4], 16).map_err(|_| deny("invalid IPv6 address flags"))?;
        if ifindex == 0 || prefix > 128 {
            return Err(deny("invalid kernel IPv6 address generation"));
        }
        if !result.insert(KernelV6Address {
            interface: kernel_interface(row[5])?.to_owned(),
            address: ipv6_kernel_hex(row[0])?,
            prefix,
            ifindex,
            scope,
            flags,
        }) {
            return Err(deny("duplicate kernel IPv6 address"));
        }
    }
    Ok(result)
}

fn observe_rows() -> Result<KernelRows, ProviderError> {
    let namespace = fs::metadata("/proc/self/ns/net")
        .map_err(|_| deny("kernel network namespace unavailable"))?
        .ino();
    let initial = fs::metadata("/proc/1/ns/net")
        .map_err(|_| deny("initial kernel network namespace unavailable"))?
        .ino();
    if namespace == 0 || namespace != initial {
        return Err(deny(
            "observer is not in the host initial network namespace",
        ));
    }
    let mut routes = BTreeSet::new();
    parse_v4_routes(
        &bounded_kernel_file(Path::new("/proc/net/route"))?,
        &mut routes,
    )?;
    parse_v6_routes(
        &bounded_kernel_file(Path::new("/proc/net/ipv6_route"))?,
        &mut routes,
    )?;
    let addresses_v6 = parse_v6_addresses(&bounded_kernel_file(Path::new("/proc/net/if_inet6"))?)?;
    let addresses_v4 = connection_ipv4::sample()?;
    if fs::metadata("/proc/self/ns/net")
        .map_err(|_| deny("network namespace vanished"))?
        .ino()
        != namespace
    {
        return Err(deny("kernel namespace changed during route sample"));
    }
    Ok(KernelRows {
        routes,
        addresses_v4,
        addresses_v6,
        namespace,
    })
}

/// Double-read independent kernel state with a bounded monotonic budget.
/// Such evidence must be paired with fresh NM, original user and trusted
/// recovery facts; it cannot grant an effect by itself.
pub(super) fn sample() -> Result<KernelConnectionSnapshot, ProviderError> {
    let start = Instant::now();
    let before = observe_rows()?;
    if before != observe_rows()? || start.elapsed().as_millis() > MAX_AGE_MS {
        return Err(deny(
            "kernel route inventory changed during bounded observation",
        ));
    }
    Ok(KernelConnectionSnapshot {
        rows: before,
        sampled_at: Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_default(interface: &str) -> KernelRoute {
        KernelRoute {
            family: 4,
            interface: interface.to_owned(),
            destination: "0.0.0.0".into(),
            prefix: 0,
            gateway: "192.168.1.1".into(),
            metric: 100,
            flags: 3,
        }
    }

    fn rows(routes: impl IntoIterator<Item = KernelRoute>) -> KernelRows {
        KernelRows {
            routes: routes.into_iter().collect(),
            addresses_v4: BTreeSet::new(),
            addresses_v6: BTreeSet::new(),
            namespace: 7,
        }
    }

    #[test]
    fn ipv4_main_table_has_strict_flags_prefix_and_endian() {
        let mut routes = BTreeSet::new();
        let text = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\nwlan0 00000000 0101A8C0 0003 0 0 100 00000000 0 0 0\n";
        assert!(parse_v4_routes(text, &mut routes).is_ok());
        assert!(routes.contains(&v4_default("wlan0")));
        assert_eq!(ipv4_le("0101A8C0").ok().as_deref(), Some("192.168.1.1"));
        for wrong in [
            "Iface Destination Mask\nwlan0 dead beef\n",
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\nwlan0 00000000 0101A8C0 0003 0 0 100 00FF00FF 0 0 0\n",
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\nwlan0 00000000 0101A8C0 0203 0 0 100 00000000 0 0 0\n",
        ] {
            assert!(parse_v4_routes(wrong, &mut BTreeSet::new()).is_err());
        }
    }

    #[test]
    fn kernel_route_veto_does_not_claim_local_recovery_or_remote_survival() {
        let before = KernelConnectionSnapshot::fixture(rows([v4_default("wlan0")]));
        let mut after = KernelConnectionSnapshot::fixture(rows([]));
        after.sampled_at = before.sampled_at + std::time::Duration::from_millis(5);
        assert!(before.require_deactivated(&after, "wlan0", 7).is_err());
        assert!(!after.proves_safe_effective_routing_or_recovery());
        let mut has_fallback = KernelConnectionSnapshot::fixture(rows([v4_default("eth0")]));
        has_fallback.sampled_at = after.sampled_at;
        assert!(
            before
                .require_deactivated(&has_fallback, "wlan0", 7)
                .is_err()
        );
        let prior =
            KernelConnectionSnapshot::fixture(rows([v4_default("wlan0"), v4_default("eth0")]));
        assert!(prior.require_deactivated(&has_fallback, "wlan0", 7).is_ok());
        let mut stale =
            KernelConnectionSnapshot::fixture(rows([v4_default("wlan0"), v4_default("eth0")]));
        stale.sampled_at = prior.sampled_at;
        assert!(prior.require_unaffected_stable(&stale, "wlan0", 7).is_err());
    }

    #[test]
    fn ipv6_provider_claim_requires_ready_kernel_ifindex_address() {
        let mut kernel = rows([]);
        kernel.addresses_v6.insert(KernelV6Address {
            interface: "wlan0".into(),
            address: "2001:db8::4".into(),
            prefix: 64,
            ifindex: 7,
            scope: 0,
            flags: 0x80,
        });
        let snapshot = KernelConnectionSnapshot::fixture(kernel.clone());
        assert!(
            snapshot
                .require_provider_ipv6(7, &["2001:db8::4/64".into()])
                .is_ok()
        );
        assert!(
            snapshot
                .require_provider_ipv6(8, &["2001:db8::4/64".into()])
                .is_err()
        );
        assert!(
            snapshot
                .require_provider_ipv6(7, &["2001:db8::5/64".into()])
                .is_err()
        );
        assert!(
            snapshot
                .require_provider_ipv6(7, &["2001:db8::4/129".into()])
                .is_err()
        );
        let Some(row) = kernel.addresses_v6.pop_first() else {
            unreachable!("kernel IPv6 fixture");
        };
        kernel.addresses_v6.insert(KernelV6Address {
            flags: row.flags | 0x40,
            ..row
        });
        let not_ready = KernelConnectionSnapshot::fixture(kernel);
        assert!(
            not_ready
                .require_provider_ipv6(7, &["2001:db8::4/64".into()])
                .is_err()
        );
    }

    #[test]
    fn ipv6_routes_and_addresses_reject_malformed_generations() {
        let route = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000064 00000000 00000000 00000001 eth0";
        let mut parsed = BTreeSet::new();
        assert!(parse_v6_routes(route, &mut parsed).is_ok());
        assert_eq!(parsed.len(), 1);
        assert!(parsed.iter().all(KernelRoute::is_default));
        assert!(parse_v6_routes(&route.replace(" 00 ", " ff "), &mut BTreeSet::new(),).is_err());
        assert!(parse_v6_addresses("not a kernel address row").is_err());
        assert!(parse_v6_addresses("00000000000000000000000001000000 00 40 00 80 eth0").is_err());
    }
}
