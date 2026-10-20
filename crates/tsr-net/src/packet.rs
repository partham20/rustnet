//! Minimal IP packet helpers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Destination address of an IPv4 or IPv6 packet.
pub fn dst_addr(p: &[u8]) -> Option<IpAddr> {
    match p.first()? >> 4 {
        4 if p.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19]))),
        6 if p.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&p[24..40]).ok()?,
        ))),
        _ => None,
    }
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in data.chunks(2) {
        let word = if c.len() == 2 {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from(c[0]) << 8
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv4 ICMP echo request.
pub fn icmp_echo_request(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
    let payload = b"tsr ping";
    let icmp_len = 8 + payload.len();
    let total = 20 + icmp_len;
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64; // TTL
    p[9] = 1; // ICMP
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let c = checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    let icmp = &mut p[20..];
    icmp[0] = 8; // echo request
    icmp[4..6].copy_from_slice(&id.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq.to_be_bytes());
    icmp[8..].copy_from_slice(payload);
    let c = checksum(icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    p
}

/// If `p` is an IPv4 ICMP echo reply, return (source, id, seq).
pub fn parse_icmp_echo_reply(p: &[u8]) -> Option<(Ipv4Addr, u16, u16)> {
    if p.len() < 28 || p[0] >> 4 != 4 || p[9] != 1 {
        return None;
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    let icmp = p.get(ihl..)?;
    if icmp.len() < 8 || icmp[0] != 0 {
        return None;
    }
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    Some((
        src,
        u16::from_be_bytes([icmp[4], icmp[5]]),
        u16::from_be_bytes([icmp[6], icmp[7]]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_request_checksums_verify() {
        let p = icmp_echo_request(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            7,
            1,
        );
        assert_eq!(checksum(&p[..20]), 0);
        assert_eq!(checksum(&p[20..]), 0);
        assert_eq!(dst_addr(&p), Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))));
    }
}
