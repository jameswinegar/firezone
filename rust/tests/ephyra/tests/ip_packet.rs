//! `ip_packet::make` constructors and `IpPacket::new` against an independent RFC 1071 model.
//!
//! The AFL target in `rust/tests/fuzz` checks the mutators against `ip_packet`'s own
//! `calculate_*_checksum`. This suite checks what it leaves out: packets the
//! constructors build, and IPv4 options stripped on parse (Linux), verified from the
//! raw bytes with a checksum implementation that shares no code with the crate.
//!
//! Sources of truth: RFC 791 / 8200 (header layout), RFC 768 / 793 / 792 / 4443
//! (transport checksums and their pseudo-headers), RFC 1071 (the checksum), and the
//! crate docs ("`make`: Factory module for making all kinds of packets"; `ipv4_packet`
//! / `ipv6_packet`: "computing all checksums").

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::ControlFlow;

use ephyra::{GenExt as _, Source};
use ip_packet::{IpPacket, MAX_IP_SIZE};

fn ones_sum(bytes: &[u8], mut acc: u32) -> u16 {
    for chunk in bytes.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        acc += u32::from(word);
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    acc as u16
}

fn pseudo_header(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> Vec<u8> {
    let mut p = Vec::new();
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(&[0, proto]);
            p.extend_from_slice(&(len as u16).to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(&(len as u32).to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, proto]);
        }
        _ => unreachable!(),
    }
    p
}

/// Every checksum the raw bytes carry verifies; returns what is wrong otherwise.
fn checksum_errors(bytes: &[u8]) -> Vec<String> {
    let mut errors = Vec::new();
    let (src, dst, proto, l4): (IpAddr, IpAddr, u8, &[u8]) = match bytes[0] >> 4 {
        4 => {
            let ihl = usize::from(bytes[0] & 0xF) * 4;
            let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            if ones_sum(&bytes[..ihl], 0) != 0xFFFF {
                errors.push("IPv4 header checksum".to_owned());
            }
            let src = Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[12..16]).unwrap());
            let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[16..20]).unwrap());
            (src.into(), dst.into(), bytes[9], &bytes[ihl..total])
        }
        6 => {
            let len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).unwrap());
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).unwrap());
            (src.into(), dst.into(), bytes[6], &bytes[40..40 + len])
        }
        v => panic!("not an IP packet: version {v}"),
    };
    let with_pseudo = |l4: &[u8]| {
        let p = pseudo_header(src, dst, proto, l4.len());
        let acc = u32::from(ones_sum(&p, 0));
        ones_sum(l4, acc)
    };
    match proto {
        17 => {
            let stored = u16::from_be_bytes([l4[6], l4[7]]);
            // Over IPv4 a zero UDP checksum means "not computed"; over IPv6 it is mandatory.
            let unchecked = src.is_ipv4() && stored == 0;
            if !unchecked && with_pseudo(l4) != 0xFFFF {
                errors.push(format!("UDP checksum {stored:#06x}"));
            }
            if src.is_ipv6() && stored == 0 {
                errors.push("UDP checksum zero over IPv6".to_owned());
            }
        }
        6 if with_pseudo(l4) != 0xFFFF => errors.push("TCP checksum".to_owned()),
        58 if with_pseudo(l4) != 0xFFFF => errors.push("ICMPv6 checksum".to_owned()),
        1 if ones_sum(l4, 0) != 0xFFFF => errors.push("ICMPv4 checksum".to_owned()),
        _ => {}
    }
    errors
}

fn reparse(p: &IpPacket) -> IpPacket {
    let mut buf = ip_packet::packet_buffer();
    let raw = p.packet();
    buf[..raw.len()].copy_from_slice(raw);
    IpPacket::new(buf, raw.len()).expect("a constructed packet parses again")
}

#[derive(Clone, Debug)]
enum Kind {
    Udp,
    Tcp {
        seq: u32,
        syn: bool,
        ack: bool,
        rst: bool,
        options: Vec<u8>,
    },
    EchoRequest {
        seq: u16,
        id: u16,
    },
    EchoReply {
        seq: u16,
        id: u16,
    },
}

#[derive(Clone, Debug)]
struct Spec {
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    kind: Kind,
    payload: Vec<u8>,
    /// Also build the ICMP errors for the packet.
    errors: bool,
}

fn addr(g: &mut Source, v6: bool) -> IpAddr {
    let edge = g.bool_with(0.3);
    if v6 {
        let v: u128 = if edge {
            *g.pick(&[0, u128::MAX, 1])
        } else {
            u128::from(g.int::<u64>(..)) << 64 | u128::from(g.int::<u64>(..))
        };
        Ipv6Addr::from(v).into()
    } else {
        let v: u32 = if edge {
            *g.pick(&[0, u32::MAX, 1])
        } else {
            g.int(..)
        };
        Ipv4Addr::from(v).into()
    }
}

fn spec(g: &mut Source) -> Spec {
    let v6 = g.bool();
    let payload_len = match g.int(0u8..=3) {
        0 => 0,
        1 => g.int(0usize..=20),
        2 => g.int(0usize..=MAX_IP_SIZE),
        _ => MAX_IP_SIZE - g.int(0usize..=80),
    };
    let zeros = g.bool_with(0.3);
    let kind = match g.int(0u8..=3) {
        0 => Kind::Udp,
        1 => Kind::Tcp {
            seq: g.int(..),
            syn: g.bool(),
            ack: g.bool(),
            rst: g.bool(),
            // Up to 48 bytes: the data offset field only describes up to 40.
            options: (0..4 * g.int(0usize..=12))
                .map(|_| if zeros { 0 } else { g.int(..) })
                .collect(),
        },
        2 => Kind::EchoRequest {
            seq: g.int(..),
            id: g.int(..),
        },
        _ => Kind::EchoReply {
            seq: g.int(..),
            id: g.int(..),
        },
    };
    Spec {
        src: addr(g, v6),
        dst: addr(g, v6),
        sport: if zeros { 0 } else { g.int(..) },
        dport: if zeros { 0 } else { g.int(..) },
        kind,
        payload: (0..payload_len)
            .map(|_| if zeros { 0 } else { g.int(..) })
            .collect(),
        errors: g.bool_with(0.5),
    }
}

fn shrink_spec(s: &Spec, visit: &mut dyn FnMut(Spec) -> ControlFlow<()>) -> ControlFlow<()> {
    if !s.payload.is_empty() {
        visit(Spec {
            payload: Vec::new(),
            ..s.clone()
        })?;
        visit(Spec {
            payload: s.payload[..s.payload.len() / 2].to_vec(),
            ..s.clone()
        })?;
    }
    if s.payload.iter().any(|b| *b != 0) {
        visit(Spec {
            payload: vec![0; s.payload.len()],
            ..s.clone()
        })?;
    }
    if let Kind::Tcp { options, .. } = &s.kind
        && !options.is_empty()
    {
        let mut k = s.kind.clone();
        if let Kind::Tcp { options, .. } = &mut k {
            options.truncate(options.len() - 4);
        }
        visit(Spec {
            kind: k,
            ..s.clone()
        })?;
    }
    ControlFlow::Continue(())
}

fn build(s: &Spec) -> anyhow::Result<IpPacket> {
    use ip_packet::make;
    match &s.kind {
        Kind::Udp => make::udp_packet(s.src, s.dst, s.sport, s.dport, &s.payload),
        Kind::Tcp {
            seq,
            syn,
            ack,
            rst,
            options,
        } => make::tcp_packet_with_options(
            s.src,
            s.dst,
            s.sport,
            s.dport,
            *seq,
            make::TcpFlags {
                syn: *syn,
                ack: *ack,
                rst: *rst,
            },
            options,
            &s.payload,
        ),
        Kind::EchoRequest { seq, id } => {
            make::icmp_request_packet(s.src, s.dst, *seq, *id, &s.payload)
        }
        Kind::EchoReply { seq, id } => make::icmp_reply_packet(s.src, s.dst, *seq, *id, &s.payload),
    }
}

fn header_len(s: &Spec) -> usize {
    let ip = if s.src.is_ipv4() { 20 } else { 40 };
    let l4 = match &s.kind {
        Kind::Udp | Kind::EchoRequest { .. } | Kind::EchoReply { .. } => 8,
        Kind::Tcp { options, .. } => 20 + options.len(),
    };
    ip + l4
}

#[ephyra::test(gen = spec.with_shrink(shrink_spec), tests = 20_000)]
fn constructed_packets_are_valid(s: Spec) {
    let fits = header_len(&s) + s.payload.len() <= MAX_IP_SIZE;
    let tcp_options_fit = !matches!(&s.kind, Kind::Tcp { options, .. } if options.len() > 40);
    let packet = match build(&s) {
        Ok(p) => p,
        Err(e) => {
            assert!(!fits || !tcp_options_fit, "valid packet rejected: {e:?}");
            return;
        }
    };
    assert!(
        fits,
        "oversized packet of {} bytes built",
        packet.packet().len()
    );
    assert!(
        tcp_options_fit,
        "TCP packet with {} option bytes built: data offset overflows",
        header_len(&s) - 40
    );

    let raw = packet.packet().to_vec();
    assert_eq!(raw.len(), header_len(&s) + s.payload.len());
    assert_eq!(packet.source(), s.src);
    assert_eq!(packet.destination(), s.dst);
    assert_eq!(
        &raw[raw.len() - s.payload.len()..],
        s.payload.as_slice(),
        "payload changed"
    );
    let errors = checksum_errors(&raw);
    assert!(
        errors.is_empty(),
        "constructed packet has bad checksums: {errors:?}"
    );

    let again = reparse(&packet);
    assert_eq!(again.packet(), raw.as_slice(), "packet changed on reparse");

    if let Some(tcp) = packet.as_tcp() {
        assert_eq!(
            (tcp.source_port(), tcp.destination_port()),
            (s.sport, s.dport)
        );
    }
    if let Some(udp) = packet.as_udp() {
        assert_eq!(
            (udp.source_port(), udp.destination_port()),
            (s.sport, s.dport)
        );
    }

    if s.errors {
        for make in [
            ip_packet::make::icmp_dest_unreachable_network,
            ip_packet::make::icmp_dest_unreachable_prohibited,
        ] {
            let Ok(error) = make(&packet) else {
                // Only ICMP errors are refused, and echo messages are not errors.
                panic!("ICMP error refused for a non-error packet");
            };
            assert_eq!(error.source(), s.dst);
            assert_eq!(error.destination(), s.src);
            let errors = checksum_errors(error.packet());
            assert!(
                errors.is_empty(),
                "ICMP error has bad checksums: {errors:?}"
            );
            assert!(error.packet().len() <= MAX_IP_SIZE);
            // RFC 792: the error carries the original IP header and the first 8 bytes of its payload.
            let quoted = &error.packet()[header_len_of(error.packet()) + 8..];
            let want = if s.src.is_ipv4() {
                raw.len().min(20 + 8)
            } else {
                raw.len().min(MAX_IP_SIZE - 48)
            };
            assert_eq!(
                quoted,
                &raw[..want],
                "ICMP error does not quote the original packet"
            );
        }
    }
}

fn header_len_of(bytes: &[u8]) -> usize {
    match bytes[0] >> 4 {
        4 => usize::from(bytes[0] & 0xF) * 4,
        _ => 40,
    }
}

/// An IPv4 packet with options; `IpPacket::new` strips them on Linux.
#[derive(Clone, Debug)]
struct WithOptions {
    options: Vec<u8>,
    inner: Spec,
}

fn with_options(g: &mut Source) -> WithOptions {
    let mut inner = spec(g);
    if let Kind::Tcp { options, .. } = &mut inner.kind {
        options.truncate(40);
    }
    inner.src = addr(g, false);
    inner.dst = addr(g, false);
    let words = g.int(1usize..=10);
    // NOP (1), End of Option List (0) or arbitrary bytes: the parser must not care.
    let options = (0..4 * words)
        .map(|_| *g.pick(&[0u8, 1, 1, 7, 0x44, 0x94, 0xFF]))
        .collect();
    let max_payload = MAX_IP_SIZE - header_len(&inner) - 4 * words;
    inner.payload.truncate(max_payload);
    WithOptions { options, inner }
}

#[ephyra::test(gen = with_options, tests = 10_000)]
fn ipv4_options_are_stripped_consistently(w: WithOptions) {
    let packet = build(&w.inner).expect("fits");
    let raw = packet.packet();

    // Insert the options after the 20-byte header and fix up IHL, total length and checksum.
    let mut bytes = raw[..20].to_vec();
    bytes.extend_from_slice(&w.options);
    bytes.extend_from_slice(&raw[20..]);
    bytes[0] = 0x40 | (5 + w.options.len() / 4) as u8;
    let total = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&total.to_be_bytes());
    bytes[10..12].copy_from_slice(&[0, 0]);
    let ihl = 20 + w.options.len();
    let c = !ones_sum(&bytes[..ihl], 0);
    bytes[10..12].copy_from_slice(&c.to_be_bytes());
    assert!(
        checksum_errors(&bytes).is_empty(),
        "test setup: packet with options must be valid"
    );

    let mut buf = ip_packet::packet_buffer();
    buf[..bytes.len()].copy_from_slice(&bytes);
    let parsed = IpPacket::new(buf, bytes.len()).expect("a valid IPv4 packet with options parses");

    let out = parsed.packet();
    let errors = checksum_errors(out);
    assert!(
        errors.is_empty(),
        "checksums broken after parsing: {errors:?}"
    );
    assert_eq!(parsed.source(), w.inner.src);
    assert_eq!(parsed.destination(), w.inner.dst);
    assert_eq!(
        &out[header_len_of(out)..],
        &raw[20..],
        "transport layer changed"
    );
    if cfg!(target_os = "linux") {
        assert_eq!(out[0], 0x45, "options not stripped");
        assert_eq!(out.len(), raw.len());
        // Everything but IHL, total length and checksum is kept.
        assert_eq!(&out[1..2], &raw[1..2]);
        assert_eq!(&out[4..10], &raw[4..10]);
        assert_eq!(&out[12..20], &raw[12..20]);
    }
}
