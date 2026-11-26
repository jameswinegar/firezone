//! `flow_tracker::Tracker` driven as a Gateway would, observed through `flow-log-writer`.
//!
//! Sources of truth: the crate docs. "A [`Tracker`] turns a stream of packet
//! observations into [`Record`]s"; packets in the "tx" direction create, update or split
//! a flow, "rx" packets "only update the counters ... of an already-open flow"; a flow
//! "is closed if no packet is seen for" two minutes; `close_all` "pushes a close record
//! for every currently-active flow". And the integration tests in
//! `flow-tracker/tests/writer.rs`: `tx_bytes` / `rx_bytes` count transport payload bytes.
//!
//! Properties: every flow that is opened is closed exactly once, no record counts more
//! bytes than were observed, and on traffic the tracker is documented to count in full
//! (no FIN/RST, rx only on open flows, no two-minute gaps) every byte is counted.

use std::net::{Ipv4Addr, SocketAddr};
use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use base64::Engine as _;
use connlib_model::{ClientId, ClientOrGatewayId};
use ephyra::{GenExt as _, Source, gens};
use flow_tracker::{IngestToken, Role, Tracker};
use ip_packet::IpPacket;
use tracing_subscriber::layer::SubscriberExt as _;

pub const AUTHZ: &str = "22222222-2222-2222-2222-222222222222";

#[derive(Clone, Copy, Debug, PartialEq)]
struct Flags {
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
}

#[derive(Clone, Debug)]
enum Op {
    /// Initiator-to-responder packet(s) arriving over the network.
    Tx {
        tuple: usize,
        flags: Flags,
        payloads: Vec<usize>,
        remote: usize,
    },
    /// Responder-to-initiator packet read from TUN.
    Rx {
        tuple: usize,
        flags: Flags,
        payload: usize,
    },
    Advance {
        secs: u64,
    },
}

/// The inner 5-tuples: two TCP connections and one UDP flow.
const TUPLES: [(bool, u16, u16); 3] = [(true, 1234, 443), (true, 1235, 443), (false, 5000, 53)];

fn flags(g: &mut Source, full: bool) -> Flags {
    Flags {
        syn: g.bool_with(0.2),
        ack: g.bool_with(0.7),
        fin: full && g.bool_with(0.1),
        rst: full && g.bool_with(0.05),
    }
}

fn op(g: &mut Source, full: bool) -> Op {
    let payload = |g: &mut Source| *g.pick(&[0usize, 1, 100, 1000]);
    match g.int(0u8..=9) {
        0..=4 => Op::Tx {
            tuple: g.int(0..=2),
            flags: flags(g, full),
            payloads: (0..g.int(1usize..=3)).map(|_| payload(g)).collect(),
            remote: if g.bool_with(0.1) { g.int(0..=20) } else { 0 },
        },
        5..=7 => Op::Rx {
            tuple: g.int(0..=2),
            flags: flags(g, full),
            payload: payload(g),
        },
        _ => Op::Advance {
            secs: if full {
                *g.pick(&[1u64, 30, 119, 121, 300])
            } else {
                *g.pick(&[0u64, 1, 30, 60])
            },
        },
    }
}

fn shrink_ops(ops: &Vec<Op>, visit: &mut dyn FnMut(Vec<Op>) -> ControlFlow<()>) -> ControlFlow<()> {
    for i in (0..ops.len()).rev() {
        let mut s = ops.clone();
        s.remove(i);
        visit(s)?;
    }
    ControlFlow::Continue(())
}

fn ops(full: bool) -> impl ephyra::Gen<Value = Vec<Op>> {
    gens::vec(move |g: &mut Source| op(g, full))
        .len(1..=40)
        .with_shrink(shrink_ops)
}

fn packet(tuple: usize, flags: Flags, payload: usize, reply: bool) -> IpPacket {
    let (tcp, sport, dport) = TUPLES[tuple];
    let (client, resource) = (Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(10, 0, 0, 5));
    let (src, dst, sport, dport) = if reply {
        (resource, client, dport, sport)
    } else {
        (client, resource, sport, dport)
    };
    let data = vec![0u8; payload];
    if tcp {
        // `make` has no FIN flag: a FIN is a raw flag patch on the built segment.
        let mut p = ip_packet::make::tcp_packet(
            src,
            dst,
            sport,
            dport,
            ip_packet::make::TcpFlags {
                syn: flags.syn,
                ack: flags.ack,
                rst: flags.rst,
            },
            &data,
        )
        .unwrap();
        if flags.fin {
            let mut raw = p.packet().to_vec();
            raw[20 + 13] |= 0x01; // IPv4 header without options, then the TCP flags byte.
            let mut buf = ip_packet::packet_buffer();
            buf[..raw.len()].copy_from_slice(&raw);
            p = IpPacket::new(buf, raw.len()).unwrap();
            p.compute_checksums();
            assert!(p.tcp_flags().unwrap().contains(ip_packet::TcpFlags::FIN));
        }
        p
    } else {
        ip_packet::make::udp_packet(src, dst, sport, dport, &data).unwrap()
    }
}

fn token() -> IngestToken {
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let claims = format!(
        r#"{{"account_id":"c1e296cd-b8ff-4565-8a4c-b6023a4a4b10","iat":1782756000,"exp":1785434400,"uploads_enabled":true,"role":"responder","initiator_device_id":"d-1","responder_device_id":"d-2","policy_authorization_id":"{AUTHZ}","policy_id":"p-1","resource_id":"r-1","resource_name":"web","initiator_actor_id":"a-1","initiator_actor_name":"Alice","authorized_at":"2026-07-01T00:00:00Z","authorization_expires_at":"2026-07-02T00:00:00Z"}}"#
    );
    let token = format!(
        "{}.{}.{}",
        encode(br#"{"alg":"HS256"}"#),
        encode(claims.as_bytes()),
        encode(b"signature")
    );

    serde_json::from_value(serde_json::Value::String(token)).unwrap()
}

struct Totals {
    tx_bytes: u64,
    rx_bytes: u64,
}

/// Runs the ops and returns the spooled reports plus what was fed in.
fn run(ops: &[Op], tick: Duration) -> (Vec<serde_json::Value>, Vec<serde_json::Value>, Totals) {
    let dir = tempfile::tempdir().unwrap();
    let token = token();
    flow_log_writer::write_token(dir.path(), token.as_str()).unwrap();

    let start = Instant::now();
    let mut now = start;
    let mut tracker: Tracker<ClientOrGatewayId> =
        Tracker::new(now, Duration::from_secs(1_700_000_000));
    tracker.set_enabled(true);
    let mut totals = Totals {
        tx_bytes: 0,
        rx_bytes: 0,
    };
    let local: SocketAddr = "198.51.100.1:51820".parse().unwrap();

    let (layer, guard) = flow_log_writer::layer(dir.path().to_owned());
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        for op in ops {
            now += tick;
            match op {
                Op::Tx {
                    tuple,
                    flags,
                    payloads,
                    remote,
                } => {
                    let remote: SocketAddr =
                        format!("203.0.113.7:{}", 51820 + remote).parse().unwrap();
                    let mut flow = tracker.begin_network_packet(local, remote, now);
                    flow_tracker::record_decrypted_packet(&packet(
                        *tuple,
                        *flags,
                        payloads[0],
                        false,
                    ));
                    flow_tracker::record_peer(ClientId::from_u128(1), Role::Responder);
                    flow_tracker::record_ingest_token(Some(&token));
                    for p in &payloads[1..] {
                        flow.count_packet(&packet(
                            *tuple,
                            Flags {
                                syn: false,
                                fin: false,
                                rst: false,
                                ack: true,
                            },
                            *p,
                            false,
                        ));
                    }
                    drop(flow);
                    totals.tx_bytes += payloads.iter().sum::<usize>() as u64;
                }
                Op::Rx {
                    tuple,
                    flags,
                    payload,
                } => {
                    let flow =
                        tracker.begin_tun_packet(&packet(*tuple, *flags, *payload, true), now);
                    flow_tracker::record_peer(ClientId::from_u128(1), Role::Responder);
                    flow_tracker::record_transmit(
                        Some(local),
                        "203.0.113.7:51820".parse().unwrap(),
                    );
                    drop(flow);
                    totals.rx_bytes += *payload as u64;
                }
                Op::Advance { secs } => {
                    now += Duration::from_secs(*secs);
                    tracker.handle_timeout(now);
                }
            }
        }
        tracker.close_all(now);
    });
    guard.join();

    let authz_dir = dir.path().join("responder").join(AUTHZ);
    let read = |suffix: &str| -> Vec<serde_json::Value> {
        let Ok(entries) = std::fs::read_dir(&authz_dir) else {
            return Vec::new();
        };
        entries
            .map(|e| e.unwrap().path())
            .filter(|p| p.to_string_lossy().ends_with(suffix))
            .map(|p| flow_log_spool::deserialize(&std::fs::read(p).unwrap()).unwrap())
            .collect()
    };

    (read(".start.json"), read(".end.json"), totals)
}

fn sum(reports: &[serde_json::Value], field: &str) -> u64 {
    reports
        .iter()
        .map(|r| {
            r[field]
                .as_u64()
                .unwrap_or_else(|| panic!("{field} missing: {r}"))
        })
        .sum()
}

/// Every op happens on its own event-loop tick (1 ms apart). Two flows on one 4-tuple
/// starting in the same tick collide in the spool; see the reproducers at the end.
const TICK: Duration = Duration::from_millis(1);

#[ephyra::test(gen = ops(true), tests = 1_500)]
fn every_flow_closes_once_and_counts_no_phantom_bytes(ops: Vec<Op>) {
    let (starts, ends, totals) = run(&ops, TICK);

    assert_eq!(
        starts.len(),
        ends.len(),
        "opened {} flows but closed {}",
        starts.len(),
        ends.len()
    );
    assert!(
        sum(&ends, "tx_bytes") <= totals.tx_bytes,
        "more tx bytes recorded than sent"
    );
    assert!(
        sum(&ends, "rx_bytes") <= totals.rx_bytes,
        "more rx bytes recorded than received"
    );
    for end in &ends {
        assert!(
            end["tx_packets"].as_u64().unwrap() >= 1,
            "closed flow without a tx packet: {end}"
        );
        let (s, e) = (
            end["flow_start"].as_str().unwrap(),
            end["flow_end"].as_str().unwrap(),
        );
        assert!(s <= e, "flow ends before it starts: {end}");
    }
}

/// Traffic the tracker documents as fully counted: every tx packet of a flow after
/// the first is counted, rx is counted on open flows, nothing closes early.
#[ephyra::test(gen = ops(false), tests = 1_500)]
fn every_byte_of_plain_traffic_is_counted(ops: Vec<Op>) {
    // Make the ops fully countable: the first tx packet of a TCP flow is not a bare ACK,
    // and rx only carries bytes while its flow is open, i.e. after a tx packet and before
    // two idle minutes.
    let mut open = [false; 3];
    let mut last = [0u64; 3];
    let mut now = 0u64; // In ms, ticking like `run`.
    let mut ops = ops;
    for op in &mut ops {
        now += TICK.as_millis() as u64;
        match op {
            Op::Tx {
                tuple,
                flags,
                payloads,
                ..
            } => {
                if TUPLES[*tuple].0 && !open[*tuple] && !flags.syn && payloads[0] == 0 {
                    flags.syn = true;
                }
                open[*tuple] = true;
                last[*tuple] = now;
            }
            Op::Rx { tuple, payload, .. } => {
                if open[*tuple] {
                    last[*tuple] = now;
                } else {
                    *payload = 0;
                }
            }
            Op::Advance { secs } => {
                now += *secs * 1000;
                for t in 0..3 {
                    if now - last[t] > 120_000 {
                        open[t] = false;
                    }
                }
            }
        }
    }

    let (starts, ends, totals) = run(&ops, TICK);

    assert_eq!(starts.len(), ends.len());
    assert_eq!(
        sum(&ends, "tx_bytes"),
        totals.tx_bytes,
        "tx bytes lost: {ends:#?}"
    );
    assert_eq!(
        sum(&ends, "rx_bytes"),
        totals.rx_bytes,
        "rx bytes lost: {ends:#?}"
    );
}

// Reproducers. connlib reads the clock once per event-loop tick and processes a whole
// received batch with it, so all packets below share one `now`.

const SAME_TICK: Duration = Duration::ZERO;

fn data(tuple: usize, bytes: usize, remote: usize) -> Op {
    Op::Tx {
        tuple,
        flags: Flags {
            syn: false,
            ack: true,
            fin: false,
            rst: false,
        },
        payloads: vec![bytes],
        remote,
    }
}

/// A SYN after data on the same 4-tuple splits the flow (`record_tx`, "Splitting
/// existing TCP flow; new TCP SYN"); both flows start in the same tick.
#[test]
fn flow_split_by_syn_in_one_tick_keeps_both_reports() {
    let ops = [
        data(0, 100, 0),
        Op::Tx {
            tuple: 0,
            flags: Flags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
            },
            payloads: vec![0],
            remote: 0,
        },
    ];

    let (starts, ends, totals) = run(&ops, SAME_TICK);

    assert_eq!(totals.tx_bytes, 100);
    assert_eq!(
        starts.len(),
        2,
        "two flows were opened, but only {} start report survived",
        starts.len()
    );
    assert_eq!(
        sum(&ends, "tx_bytes"),
        100,
        "the first flow's bytes were lost: {ends:#?}"
    );
}

/// The 17th outer tuple splits the flow so "a peer cannot flap its path to keep later
/// tuples out of the log" (`MAX_CONTEXTS_PER_FLOW`); here all 17 arrive in one tick.
#[test]
fn flow_split_by_path_flapping_in_one_tick_keeps_both_reports() {
    let ops = (0..17)
        .map(|remote| data(2, 10, remote))
        .collect::<Vec<_>>();

    let (starts, ends, _) = run(&ops, SAME_TICK);

    let outers: usize = ends
        .iter()
        .map(|e| e["outers"].as_array().unwrap().len())
        .sum();
    assert_eq!(
        starts.len(),
        2,
        "two flows were opened, but only {} start report survived",
        starts.len()
    );
    assert_eq!(outers, 17, "outer tuples missing from the log: {ends:#?}");
    assert_eq!(sum(&ends, "tx_bytes"), 170);
}
