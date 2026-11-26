//! `dns_over_tcp::Client` talking to `dns_over_tcp::Server` over their in-memory TCP stacks.
//!
//! Source of truth: the crate docs. The client "maintains a single TCP connection for
//! each configured resolver" and one of its design goals "is to always provide a result
//! for a query"; the server "parses incoming DNS queries and allows writing back
//! responses". RFC 1035 4.2.2 / RFC 7766: messages on a TCP connection are framed by a
//! 2-byte length, so any message up to 65,535 bytes is valid, and a connection carries
//! any number of them.
//!
//! The property: every query the client sends over a healthy, lossless link reaches the
//! server once and its response reaches the client, well before the query timeout.

use std::collections::BTreeSet;
use std::ops::ControlFlow;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use dns_types::{DomainName, Query, RecordType, ResponseBuilder, ResponseCode};
use ephyra::{GenExt as _, Source, gens};

const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct Exchange {
    pub name: String,
    /// How many A records the server answers with.
    pub answers: usize,
}

#[derive(Clone, Debug)]
pub struct Round {
    pub exchanges: Vec<Exchange>,
    /// The server holds the round's queries and answers them in reverse order (RFC 7766 6.2.1.1).
    pub reorder: bool,
}

fn label(g: &mut Source) -> String {
    let max = *g.pick(&[1usize, 3, 8, 20, 50]);
    let len = g.int(1..=max);
    (0..len).map(|_| char::from(*g.pick(b"abz09"))).collect()
}

/// At most 4 labels of at most 50 characters plus the suffix: always a valid name.
fn name(g: &mut Source) -> String {
    if g.bool_with(0.2) {
        // A small pool, so rounds repeat names and connections carry concurrent duplicates.
        return g.pick(&["a.example.com", "b.example.com"]).to_string();
    }
    let labels = g.int(1usize..=4);
    let mut parts = (0..labels).map(|_| label(g)).collect::<Vec<_>>();
    parts.push("example.com".to_owned());
    parts.join(".")
}

fn exchange_with(max_large: usize) -> impl Fn(&mut Source) -> Exchange + Clone {
    move |g: &mut Source| {
        let answers = match g.int(0u8..=9) {
            0..=5 => g.int(0usize..=8),
            6..=7 => g.int(9usize..=max_large.min(100).max(9)),
            _ => g.int(9usize..=max_large.max(9)),
        };
        Exchange { name: name(g), answers }
    }
}

fn shrink_exchange(e: &Exchange, visit: &mut dyn FnMut(Exchange) -> ControlFlow<()>) -> ControlFlow<()> {
    for answers in [0, e.answers / 2, e.answers.saturating_sub(1)] {
        if answers < e.answers {
            visit(Exchange { answers, ..e.clone() })?;
        }
    }
    if e.name != "a.example.com" {
        visit(Exchange { name: "a.example.com".to_owned(), ..e.clone() })?;
    }
    ControlFlow::Continue(())
}

fn shrink_round(r: &Round, visit: &mut dyn FnMut(Round) -> ControlFlow<()>) -> ControlFlow<()> {
    if r.reorder {
        visit(Round { reorder: false, ..r.clone() })?;
    }
    for i in 0..r.exchanges.len() {
        if r.exchanges.len() > 1 {
            let mut s = r.clone();
            s.exchanges.remove(i);
            visit(s)?;
        }
    }
    for i in 0..r.exchanges.len() {
        let mut out = ControlFlow::Continue(());
        let _ = shrink_exchange(&r.exchanges[i], &mut |e| {
            let mut s = r.clone();
            s.exchanges[i] = e;
            out = visit(s);
            out
        });
        out?;
    }
    ControlFlow::Continue(())
}

fn round_with(max_per_round: usize, max_large: usize) -> impl Fn(&mut Source) -> Round + Clone {
    move |g: &mut Source| {
        let n = g.int(1..=max_per_round);
        let ex = exchange_with(max_large);
        Round { exchanges: (0..n).map(|_| ex(g)).collect(), reorder: g.bool_with(0.4) }
    }
}

/// Rounds of queries; the client sends a round at once and waits for it to complete.
pub fn rounds() -> impl ephyra::Gen<Value = Vec<Round>> {
    gens::vec(round_with(3, 3500).with_shrink(shrink_round)).len(1..=12)
}

/// Like [`rounds`], but each direction of the connection carries well under 64 KiB in total.
///
/// Excludes the ring-buffer wrap stall (see `dns_over_tcp_regressions.rs`) so other
/// failures can surface: at most 8 rounds of 6 queries with at most 16 records each, i.e.
/// 48 responses of at most ~1.1 KB and 48 queries of at most ~230 bytes.
pub fn bounded_rounds() -> impl ephyra::Gen<Value = Vec<Round>> {
    gens::vec(round_with(6, 16).with_shrink(shrink_round)).len(1..=8)
}

fn a_records(name: &DomainName, n: usize) -> Vec<(DomainName, u32, dns_types::OwnedRecordData)> {
    (0..n)
        .map(|i| (name.clone(), 60, dns_types::records::a(Ipv4Addr::from(0x0A00_0000 + i as u32))))
        .collect()
}

pub struct Outcome {
    pub answered: usize,
    pub failed: Vec<String>,
    pub server_received: usize,
    pub bytes_to_client: usize,
}

fn trace(at: Duration, dir: &str, p: &ip_packet::IpPacket) {
    if std::env::var_os("TRACE_TCP").is_none() {
        return;
    }
    if let Some(t) = p.as_tcp() {
        let hl = t.header_len();
        println!(
            "{at:>10.3?} {dir} seq={} ack={} win={} flags={:?} len={}",
            t.sequence_number(),
            t.acknowledgment_number(),
            t.window_size(),
            p.tcp_flags(),
            p.payload().len() - hl
        );
    }
}

fn answers_for(round: &Round, domain: &DomainName) -> usize {
    let domain = domain.to_string();
    round
        .exchanges
        .iter()
        .find(|e| domain.trim_end_matches('.') == e.name)
        .expect("server received a query the client never sent")
        .answers
}

/// Runs the exchange with a strict sans-IO driver and a simulated clock.
pub fn run(rounds: &[Round]) -> Outcome {
    let start = Instant::now();
    let mut now = start;
    let resolver = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(100, 100, 111, 1), 53));

    let mut client = dns_over_tcp::Client::<49152, 65535>::new(now, QUERY_TIMEOUT, [7u8; 32]);
    client.set_source_interface(Ipv4Addr::new(100, 90, 215, 97), Ipv6Addr::LOCALHOST);
    let mut server = dns_over_tcp::Server::new(now);
    server.set_listen_addresses::<1>(BTreeSet::from([resolver]));

    let mut outcome = Outcome { answered: 0, failed: Vec::new(), server_received: 0, bytes_to_client: 0 };

    for (r, round) in rounds.iter().enumerate() {
        let mut outstanding = 0usize;
        for (i, ex) in round.exchanges.iter().enumerate() {
            // Stub resolvers reuse IDs (Windows always sends 1 over TCP), so IDs repeat.
            let q = Query::new(ex.name.parse().expect("valid name"), RecordType::A).with_id((i % 2) as u16);
            client.send_query(resolver, q).expect("source interface is set");
            outstanding += 1;
        }

        let mut held = Vec::new();
        let mut received_this_round = 0;
        // Give the round a generous deadline that is still shorter than the query timeout.
        let round_deadline = now + QUERY_TIMEOUT / 2;
        while outstanding > 0 && now < round_deadline {
            client.handle_timeout(now);
            server.handle_timeout(now);

            let mut progressed = false;
            while let Some(p) = client.poll_outbound() {
                progressed = true;
                trace(now - start, "c->s", &p);
                if server.accepts(&p) {
                    server.handle_inbound(p);
                }
            }
            while let Some(p) = server.poll_outbound() {
                progressed = true;
                outcome.bytes_to_client += p.payload().len();
                trace(now - start, "s->c", &p);
                if client.accepts(&p) {
                    client.handle_inbound(p);
                }
            }
            while let Some(q) = server.poll_queries() {
                progressed = true;
                outcome.server_received += 1;
                received_this_round += 1;
                held.push(q);
            }
            if !round.reorder || received_this_round == round.exchanges.len() {
                if round.reorder {
                    held.reverse();
                }
                for q in held.drain(..) {
                    let records = a_records(&q.message.domain(), answers_for(round, &q.message.domain()));
                    let response =
                        ResponseBuilder::for_query(&q.message, ResponseCode::NOERROR).with_records(records).build();
                    if let Err(e) = server.send_message(q.local, q.remote, response) {
                        outcome.failed.push(format!("round {r}: server failed to send: {e:#}"));
                    }
                }
            }
            while let Some(res) = client.poll_query_result() {
                progressed = true;
                outstanding -= 1;
                match res.result {
                    Ok(resp) => {
                        assert_eq!(resp.domain(), res.query.domain(), "round {r}: response for another name");
                        assert_eq!(resp.id(), res.query.id(), "round {r}: response ID not translated back");
                        assert_eq!(
                            resp.records().count(),
                            answers_for(round, &res.query.domain()),
                            "round {r}: response for another query"
                        );
                        outcome.answered += 1;
                    }
                    Err(e) => outcome.failed.push(format!("round {r}: {e:#}")),
                }
            }

            if !progressed {
                let next = [client.poll_timeout(), server.poll_timeout()].into_iter().flatten().min();
                now = match next {
                    Some(t) if t > now => t,
                    _ => now + Duration::from_millis(1),
                };
            }
        }
        if outstanding > 0 {
            outcome.failed.push(format!(
                "round {r}: {outstanding} queries still unanswered after {:?} ({received_this_round} received by server)",
                now - start
            ));
            return outcome;
        }
    }

    outcome
}

fn check(rounds: &[Round]) {
    let total: usize = rounds.iter().map(|r| r.exchanges.len()).sum();
    let outcome = run(rounds);
    ephyra::target(outcome.bytes_to_client as f64);
    assert!(
        outcome.failed.is_empty(),
        "{} of {total} answered, {} received by server, {} bytes to client: {:?}",
        outcome.answered,
        outcome.server_received,
        outcome.bytes_to_client,
        outcome.failed
    );
    assert_eq!(outcome.answered, total);
}

#[ephyra::test(gen = rounds(), tests = 300)]
fn every_query_over_tcp_is_answered(rounds: Vec<Round>) {
    check(&rounds);
}

#[ephyra::test(gen = bounded_rounds(), tests = 2_000)]
fn every_query_over_tcp_is_answered_below_64k(rounds: Vec<Round>) {
    check(&rounds);
}

#[test]
#[ignore = "debugging aid"]
fn trace_minimal_failure() {
    let ex = |name: &str, answers| Exchange { name: name.to_owned(), answers };
    let round = |exchanges| Round { exchanges, reorder: false };
    let rounds = vec![
        round(vec![ex("a.aabab09a09zz0.azzza.0bbbab9a0b.example.com", 550)]),
        round(vec![
            ex("z.bb.b00b.example.com", 7),
            ex("b.0.b0b9z9a0bzbb9z9azbbbzbzz99z0.example.com", 3),
            ex("b9.b99bbb9azzz99z0a9bbzbb0b090za9b9a.example.com", 498),
        ]),
    ];
    let o = run(&rounds);
    println!("answered={} failed={:?}", o.answered, o.failed);
}
