//! Plain reproducers for the failures `every_query_over_tcp_is_answered` found.
//!
//! Each test fails on the code it was written against (upstream `023d09d0`).

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use dns_types::{DomainName, Query, RecordType, Response, ResponseBuilder, ResponseCode};

const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

struct Pair {
    start: Instant,
    now: Instant,
    resolver: SocketAddr,
    client: dns_over_tcp::Client,
    server: dns_over_tcp::Server,
}

impl Pair {
    fn new() -> Self {
        let now = Instant::now();
        let resolver = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(100, 100, 111, 1), 53));
        let mut client = dns_over_tcp::Client::new(now, QUERY_TIMEOUT, [7u8; 32]);
        client.set_source_interface(Ipv4Addr::new(100, 90, 215, 97), Ipv6Addr::LOCALHOST);
        let mut server = dns_over_tcp::Server::new(now);
        server.set_listen_addresses::<1>(BTreeSet::from([resolver]));

        Self { start: now, now, resolver, client, server }
    }

    /// Sends one query and drives both sides until the client has a result, answering
    /// with `respond`. Returns the result, or `None` if the query is still pending
    /// after half the query timeout on a lossless link.
    fn exchange(
        &mut self,
        query: Query,
        respond: impl Fn(&Query) -> Response,
    ) -> Option<Result<Response, String>> {
        self.client.send_query(self.resolver, query).unwrap();
        let deadline = self.now + QUERY_TIMEOUT / 2;

        while self.now < deadline {
            self.client.handle_timeout(self.now);
            self.server.handle_timeout(self.now);

            let mut progressed = false;
            while let Some(p) = self.client.poll_outbound() {
                progressed = true;
                self.server.handle_inbound(p);
            }
            while let Some(p) = self.server.poll_outbound() {
                progressed = true;
                self.client.handle_inbound(p);
            }
            while let Some(q) = self.server.poll_queries() {
                progressed = true;
                let response = respond(&q.message);
                if let Err(e) = self.server.send_message(q.local, q.remote, response) {
                    return Some(Err(format!("server failed to send response: {e:#}")));
                }
            }
            if let Some(r) = self.client.poll_query_result() {
                return Some(r.result.map_err(|e| format!("{e:#}")));
            }
            if !progressed {
                let next = [self.client.poll_timeout(), self.server.poll_timeout()].into_iter().flatten().min();
                self.now = next.filter(|t| *t > self.now).unwrap_or(self.now + Duration::from_millis(1));
            }
        }

        None
    }
}

fn a_records(query: &Query, n: usize) -> Response {
    let records = (0..n).map(|i| (query.domain(), 60, dns_types::records::a(Ipv4Addr::from(0x0A00_0000 + i as u32))));

    ResponseBuilder::for_query(query, ResponseCode::NOERROR).with_records(records).build()
}

fn name(s: &str) -> DomainName {
    s.parse().unwrap()
}

/// Responses of ~10 KB each: the 7th one crosses byte 65,535 of the stream.
#[test]
fn client_keeps_receiving_after_64k_of_responses() {
    let mut pair = Pair::new();

    for i in 0..20u16 {
        let query = Query::new(name("a.example.com"), RecordType::A).with_id(i);
        let result = pair.exchange(query, |q| a_records(q, 350));

        let elapsed = pair.now - pair.start;
        assert!(
            matches!(result, Some(Ok(_))),
            "response {i} not delivered (elapsed {elapsed:?}): {result:?}"
        );
    }
}

/// Queries of ~70 bytes each, one at a time: query ~937 crosses byte 65,535 of the stream.
#[test]
fn server_keeps_receiving_after_64k_of_queries() {
    let mut pair = Pair::new();
    let long = name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com");

    for i in 0..1200u16 {
        let query = Query::new(long.clone(), RecordType::A).with_id(i);
        let result = pair.exchange(query, |q| a_records(q, 0));

        let elapsed = pair.now - pair.start;
        assert!(
            matches!(result, Some(Ok(_))),
            "query {i} not answered (elapsed {elapsed:?}): {result:?}"
        );
    }
}

/// RFC 1035 4.2.2 allows TCP messages up to 65,535 bytes; the 2-byte prefix makes the
/// framed message 65,537 bytes, which does not fit the 65,535-byte socket buffers.
#[test]
fn largest_tcp_response_is_delivered() {
    let mut pair = Pair::new();
    let query = Query::new(name("a.example.com"), RecordType::A).with_id(1);

    // A records get within a few hundred bytes of the limit, a TXT record with one
    // character-string of `k` bytes fills the rest.
    let response_with = |(a_count, k): (u32, usize)| {
        let mut records = (0..a_count)
            .map(|i| (query.domain(), 60, dns_types::records::a(Ipv4Addr::from(0x0A00_0000 + i))))
            .collect::<Vec<_>>();
        let txt = std::iter::once(k as u8).chain(std::iter::repeat_n(b'x', k)).collect();
        records.push((query.domain(), 60, dns_types::records::txt(txt).unwrap()));

        ResponseBuilder::for_query(&query, ResponseCode::NOERROR).with_records(records).build()
    };
    let encoded_len = |r: &Response| r.clone().into_bytes(u16::MAX).len();
    let response = (2_200..2_300)
        .find_map(|a| {
            let k = 65_535usize.checked_sub(encoded_len(&response_with((a, 0))))?;
            (k <= 255).then(|| response_with((a, k)))
        })
        .expect("test setup: some record mix makes the response exactly 65,535 bytes");
    let len = response.clone().into_bytes(u16::MAX).len();

    let result = pair.exchange(query, move |q| response.clone().with_id(q.id()));

    assert!(matches!(result, Some(Ok(_))), "{len}-byte response not delivered: {result:?}");
}
