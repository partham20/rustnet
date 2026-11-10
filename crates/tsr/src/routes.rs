//! Which IPv4 prefixes to point at the tunnel: subnet routes that peers
//! advertise (`--accept-routes`) and the internet through an exit node
//! (`--exit-node`), with or without the local network (`--exit-node-allow-lan-access`).

use ipnet::Ipv4Net;
use std::collections::BTreeSet;

/// Never sent to an exit node: "this network", the tailnet itself, loopback,
/// multicast (mDNS, SSDP) and the reserved block that holds broadcast.
const NEVER_EXIT: [&str; 5] = [
    "0.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

/// Private and link-local ranges: the local network. Kept off the exit node
/// with `--exit-node-allow-lan-access`.
const LAN: [&str; 4] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
];

fn nets(list: &[&str]) -> Vec<Ipv4Net> {
    list.iter().map(|s| s.parse().unwrap()).collect()
}

/// Prefixes that send internet traffic to the exit node. They are all more
/// specific than the real default route, so they win over it, while subnets
/// this computer is directly on stay local either way (their routes are more
/// specific still).
pub fn exit_routes(allow_lan: bool) -> BTreeSet<Ipv4Net> {
    let mut holes = nets(&NEVER_EXIT);
    if allow_lan {
        holes.extend(nets(&LAN));
    }
    subtract("0.0.0.0/0".parse().unwrap(), &holes)
        .into_iter()
        .collect()
}

/// `net` minus every hole, as a minimal list of prefixes.
fn subtract(net: Ipv4Net, holes: &[Ipv4Net]) -> Vec<Ipv4Net> {
    if holes.iter().any(|h| h.contains(&net)) {
        return Vec::new();
    }
    if !holes.iter().any(|h| net.contains(h)) {
        return vec![net];
    }
    net.subnets(net.prefix_len() + 1)
        .unwrap()
        .flat_map(|half| subtract(half, holes))
        .collect()
}

/// Is `net` a LAN this computer is directly on (or overlapping one)? Accepting
/// a peer's route for it would pull local traffic into the tunnel.
pub fn overlaps_local(net: &Ipv4Net, local: &[Ipv4Net]) -> bool {
    local.iter().any(|l| l.contains(net) || net.contains(l))
}

/// IPv4 subnets of this computer's own network interfaces, skipping loopback,
/// the tunnel adapter and tailnet addresses.
pub fn local_subnets(tun_name: &str) -> Vec<Ipv4Net> {
    let tailnet: Ipv4Net = "100.64.0.0/10".parse().unwrap();
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback() && i.name != tun_name)
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => Ipv4Net::with_netmask(v4.ip, v4.netmask)
                .ok()
                .map(|n| n.trunc()),
            _ => None,
        })
        .filter(|n| !tailnet.contains(n) && n.prefix_len() > 0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn covers(routes: &BTreeSet<Ipv4Net>, ip: &str) -> bool {
        let ip: std::net::Ipv4Addr = ip.parse().unwrap();
        routes.iter().any(|n| n.contains(&ip))
    }

    #[test]
    fn exit_without_lan_access() {
        let r = exit_routes(false);
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "192.168.1.10",
            "10.1.2.3",
            "203.0.113.5",
        ] {
            assert!(covers(&r, ip), "{ip} should go to the exit node");
        }
        for ip in [
            "100.101.102.103",
            "127.0.0.1",
            "224.0.0.251",
            "255.255.255.255",
        ] {
            assert!(!covers(&r, ip), "{ip} must stay off the exit node");
        }
        assert!(!r.iter().any(|n| n.prefix_len() == 0));
    }

    #[test]
    fn exit_with_lan_access() {
        let r = exit_routes(true);
        for ip in [
            "1.1.1.1",
            "172.15.0.1",
            "172.32.0.1",
            "192.167.1.1",
            "11.0.0.1",
        ] {
            assert!(covers(&r, ip), "{ip} should go to the exit node");
        }
        for ip in [
            "192.168.1.10",
            "10.1.2.3",
            "172.16.5.5",
            "172.31.255.1",
            "169.254.1.1",
        ] {
            assert!(!covers(&r, ip), "{ip} is LAN and must stay local");
        }
        // Disjoint prefixes.
        let v: Vec<_> = r.iter().collect();
        for (i, a) in v.iter().enumerate() {
            for b in &v[i + 1..] {
                assert!(!a.contains(*b) && !b.contains(*a), "{a} overlaps {b}");
            }
        }
    }

    #[test]
    fn local_overlap() {
        let local = vec!["192.168.1.0/24".parse().unwrap()];
        assert!(overlaps_local(&"192.168.1.0/24".parse().unwrap(), &local));
        assert!(overlaps_local(&"192.168.0.0/16".parse().unwrap(), &local));
        assert!(!overlaps_local(&"192.168.2.0/24".parse().unwrap(), &local));
    }
}
