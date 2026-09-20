use anyhow::{bail, Result};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

pub fn effective_ip(
    peer: IpAddr,
    header: Option<&str>,
    trusted: &[IpNet],
    max_hops: usize,
) -> Result<IpAddr> {
    let peer = normalize(peer);
    if !trusted.iter().any(|n| n.contains(&peer)) {
        return Ok(peer);
    }
    let raw = header.ok_or_else(|| anyhow::anyhow!("trusted proxy omitted X-Forwarded-For"))?;
    if raw.len() > 4096 {
        bail!("X-Forwarded-For is too large")
    }
    let values: Vec<IpAddr> = raw.split(',').map(parse_address).collect::<Result<_>>()?;
    if values.is_empty() || values.len() > max_hops {
        bail!("invalid X-Forwarded-For hop count")
    }
    let mut candidate = peer;
    for address in values.iter().rev() {
        if !trusted.iter().any(|n| n.contains(&candidate)) {
            return Ok(candidate);
        }
        candidate = *address;
    }
    Ok(*values.first().expect("non-empty"))
}

pub fn allowed(ip: IpAddr, networks: &[IpNet]) -> bool {
    let ip = normalize(ip);
    networks.is_empty() || networks.iter().any(|n| n.contains(&ip))
}

fn parse_address(value: &str) -> Result<IpAddr> {
    let value = value.trim();
    value
        .parse::<IpAddr>()
        .map(normalize)
        .or_else(|_| {
            value
                .parse::<SocketAddr>()
                .map(|address| normalize(address.ip()))
        })
        .map_err(|_| anyhow::anyhow!("invalid X-Forwarded-For"))
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trusted_chain() {
        let t = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(
            effective_ip(
                "10.0.0.2".parse().unwrap(),
                Some("192.0.2.1, 10.0.0.3"),
                &t,
                4
            )
            .unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
    }
    #[test]
    fn untrusted_peer_ignores_header() {
        let t = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(
            effective_ip("192.0.2.2".parse().unwrap(), Some("10.0.0.3"), &t, 4).unwrap(),
            "192.0.2.2".parse::<IpAddr>().unwrap()
        );
    }
    #[test]
    fn malformed_trusted_header_fails() {
        let t = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(effective_ip("10.0.0.2".parse().unwrap(), Some("bad"), &t, 4).is_err());
    }

    #[test]
    fn accepts_ports_and_normalizes_mapped_ipv4() {
        let trusted = vec!["127.0.0.0/8".parse().unwrap()];
        assert_eq!(
            effective_ip(
                "::ffff:127.0.0.1".parse().unwrap(),
                Some("192.0.2.10:1234"),
                &trusted,
                4,
            )
            .unwrap(),
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
    }
}
