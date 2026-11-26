//! `dns_types` queries and responses: building, serializing, truncating and parsing back.
//!
//! Sources of truth: the crate docs (`Response::into_bytes`: "In case the payload is
//! bigger than `max_len`, it will be truncated and the TC bit in the header will be set";
//! `ResponseBuilder::with_records_that_fit`: "Appends the leading `records` that fit in a
//! message of at most 65,535 bytes, with room left for a note"; `with_note`: the note is
//! attached "if the query carried EDNS"), and RFC 1035 for what a parser must accept back.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::ControlFlow;

use dns_types::{
    DomainName, OwnedRecordData, Query, RecordType, Response, ResponseBuilder, ResponseCode,
    records,
};
use ephyra::{GenExt as _, Source, gens};

fn label(g: &mut Source) -> String {
    let max = *g.pick(&[1usize, 5, 20, 63]);
    let len = g.int(1..=max);
    (0..len).map(|_| char::from(*g.pick(b"aZz09-_"))).collect()
}

/// A name of at most 253 characters in presentation format, i.e. a valid one.
fn domain_name(g: &mut Source) -> String {
    let mut name = String::new();
    for _ in 0..g.int(1usize..=8) {
        let l = label(g);
        if name.len() + 1 + l.len() > 253 {
            break;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&l);
    }
    name
}

#[derive(Clone, Debug)]
enum Data {
    A(u32),
    Aaaa(u128),
    Ptr(String),
    Txt(Vec<u8>),
    Srv(u16, u16, u16, String),
}

impl Data {
    fn record(&self) -> OwnedRecordData {
        match self {
            Data::A(ip) => records::a(Ipv4Addr::from(*ip)),
            Data::Aaaa(ip) => records::aaaa(Ipv6Addr::from(*ip)),
            Data::Ptr(n) => records::ptr(n.parse().expect("valid name")),
            Data::Txt(content) => {
                // Wire format: one length-prefixed character-string per 255 bytes.
                let mut wire = Vec::new();
                for chunk in content.chunks(255) {
                    wire.push(chunk.len() as u8);
                    wire.extend_from_slice(chunk);
                }
                if content.is_empty() {
                    wire.push(0);
                }
                records::txt(wire).expect("valid TXT wire format")
            }
            Data::Srv(p, w, port, n) => records::srv(*p, *w, *port, n.parse().expect("valid name")),
        }
    }
}

fn data(g: &mut Source) -> Data {
    match g.int(0u8..=4) {
        0 => Data::A(g.int(..)),
        1 => Data::Aaaa(u128::from(g.int::<u64>(..)) << 64 | u128::from(g.int::<u64>(..))),
        2 => Data::Ptr(domain_name(g)),
        3 => {
            let len = *g.pick(&[0usize, 1, 254, 255, 256, 600]);
            Data::Txt((0..g.int(0..=len)).map(|_| g.int(..)).collect())
        }
        _ => Data::Srv(g.int(..), g.int(..), g.int(..), domain_name(g)),
    }
}

#[derive(Clone, Debug)]
struct Case {
    name: String,
    qtype: u16,
    id: u16,
    edns: bool,
    rcode: u8,
    /// Each record is owned by the query name (`None`) or another name.
    records: Vec<(Option<String>, u32, Data)>,
    note: Option<String>,
    max_len: u16,
}

fn case(g: &mut Source) -> Case {
    let n = *g.pick(&[0usize, 1, 3, 20, 200]);
    Case {
        name: domain_name(g),
        qtype: {
            let random = g.int(..);
            *g.pick(&[1u16, 28, 12, 16, 33, 65, 255, random])
        },
        id: g.int(..),
        edns: g.bool(),
        rcode: *g.pick(&[0u8, 2, 3, 5]),
        records: (0..g.int(0..=n))
            .map(|_| {
                let owner = g.bool_with(0.2).then(|| domain_name(g));
                let random = g.int(..);
                let ttl = *g.pick(&[0u32, 60, u32::MAX, random]);
                (owner, ttl, data(g))
            })
            .collect(),
        // Notes are never empty in production; an empty Extended DNS Error text reads back as no note.
        note: g.bool_with(0.5).then(|| {
            let len = *g.pick(&[1usize, 10, 40, 60]);
            (0..g.int(1..=len))
                .map(|_| char::from(*g.pick(b"Lists 0123456789of names")))
                .collect()
        }),
        max_len: {
            let random = g.int(300..=u16::MAX);
            *g.pick(&[512u16, 1200, 1252, 4096, u16::MAX, random])
        },
    }
}

fn shrink_case(c: &Case, visit: &mut dyn FnMut(Case) -> ControlFlow<()>) -> ControlFlow<()> {
    if !c.records.is_empty() {
        visit(Case {
            records: c.records[..c.records.len() / 2].to_vec(),
            ..c.clone()
        })?;
        visit(Case {
            records: c.records[1..].to_vec(),
            ..c.clone()
        })?;
        visit(Case {
            records: c.records[..c.records.len() - 1].to_vec(),
            ..c.clone()
        })?;
    }
    if c.note.is_some() {
        visit(Case {
            note: None,
            ..c.clone()
        })?;
    }
    if c.edns {
        visit(Case {
            edns: false,
            ..c.clone()
        })?;
    }
    if c.name != "a" {
        visit(Case {
            name: "a".to_owned(),
            ..c.clone()
        })?;
    }
    ControlFlow::Continue(())
}

fn cases() -> impl ephyra::Gen<Value = Case> {
    case.with_shrink(shrink_case)
}

fn query(c: &Case) -> Query {
    let q = Query::new(
        c.name.parse().expect("valid name"),
        RecordType::from_int(c.qtype),
    )
    .with_id(c.id);
    if c.edns { q.with_edns() } else { q }
}

fn owned_records(c: &Case, q: &Query) -> Vec<(DomainName, u32, OwnedRecordData)> {
    c.records
        .iter()
        .map(|(owner, ttl, d)| {
            let owner = owner
                .as_ref()
                .map_or_else(|| q.domain(), |o| o.parse().expect("valid name"));
            (owner, *ttl, d.record())
        })
        .collect()
}

#[ephyra::test(gen = cases(), tests = 5_000)]
fn query_round_trips(c: Case) {
    let q = query(&c);
    let parsed = Query::parse(&q.clone().into_bytes()).expect("a built query parses");

    assert_eq!(parsed.id(), c.id);
    assert_eq!(parsed.domain(), q.domain());
    assert_eq!(parsed.qtype(), RecordType::from_int(c.qtype));
    assert!(parsed.is_standard_query());
}

#[ephyra::test(gen = cases(), tests = 5_000)]
fn response_survives_serialization(c: Case) {
    let q = query(&c);
    let records = owned_records(&c, &q);
    let n = records.len();
    let response = ResponseBuilder::for_query(&q, ResponseCode::masked_from_int(c.rcode))
        .with_records(records)
        .with_note(c.note.clone())
        .build();
    let full_len = response.clone().into_bytes(u16::MAX).len();
    let bytes = response.clone().into_bytes(c.max_len);
    let parsed =
        Response::parse(&bytes).unwrap_or_else(|e| panic!("response does not parse back: {e:#}"));

    assert_eq!(parsed.id(), c.id);
    assert_eq!(parsed.domain(), q.domain());
    assert_eq!(parsed.qtype(), q.qtype());
    assert_eq!(
        parsed.response_code(),
        ResponseCode::masked_from_int(c.rcode)
    );

    ephyra::cover(full_len > usize::from(c.max_len), "truncated");
    ephyra::cover(c.edns && c.note.is_some(), "edns note");
    if full_len <= usize::from(c.max_len) {
        assert!(
            !parsed.truncated(),
            "a response that fits must not be truncated"
        );
        assert_eq!(
            parsed.records().count(),
            n,
            "records lost without truncation"
        );
        assert_eq!(bytes.len(), full_len);
        if c.edns {
            assert_eq!(
                parsed.note(),
                c.note.as_deref(),
                "note lost for an EDNS query"
            );
        } else {
            assert_eq!(parsed.note(), None, "note attached to a non-EDNS query");
        }
    } else {
        assert!(parsed.truncated(), "an oversized response must have TC set");
        assert!(
            bytes.len() <= usize::from(c.max_len),
            "truncated response of {} bytes exceeds max_len {}",
            bytes.len(),
            c.max_len
        );
    }
}

#[derive(Clone, Debug)]
struct Listing {
    name: String,
    edns: bool,
    names: Vec<String>,
    /// Extra names the portal knows about beyond those given.
    hidden: usize,
}

fn listing(g: &mut Source) -> Listing {
    let long = g.bool_with(0.5);
    let count = *g.pick(&[1usize, 100, 300, 2_000, 5_000]);
    let names = (0..g.int(0..=count))
        .map(|i| {
            if long {
                // Distinct names close to the maximum length, so the limit is hit quickly.
                format!(
                    "{i}.{}",
                    "x".repeat(60) + "." + &"y".repeat(60) + "." + &"z".repeat(60) + ".example.com"
                )
            } else {
                domain_name(g)
            }
        })
        .collect();
    Listing {
        name: domain_name(g),
        edns: g.bool(),
        names,
        hidden: *g.pick(&[0usize, 1, 1_000_000, usize::MAX / 2]),
    }
}

fn shrink_listing(
    l: &Listing,
    visit: &mut dyn FnMut(Listing) -> ControlFlow<()>,
) -> ControlFlow<()> {
    if !l.names.is_empty() {
        visit(Listing {
            names: l.names[..l.names.len() / 2].to_vec(),
            ..l.clone()
        })?;
        visit(Listing {
            names: l.names[..l.names.len() - 1].to_vec(),
            ..l.clone()
        })?;
    }
    if l.hidden > 0 {
        visit(Listing {
            hidden: 0,
            ..l.clone()
        })?;
    }
    ControlFlow::Continue(())
}

/// Mirrors `DeviceStubResolver::handle_device_domain_browsed`.
#[ephyra::test(gen = listing.with_shrink(shrink_listing), tests = 300)]
fn records_that_fit_leave_room_for_the_note(l: Listing) {
    let q = Query::new(l.name.parse().expect("valid name"), RecordType::PTR).with_id(7);
    let q = if l.edns { q.with_edns() } else { q };
    let total = l.names.len() + l.hidden;
    let records = l
        .names
        .iter()
        .map(|n| (q.domain(), 60, records::ptr(n.parse().expect("valid name"))));

    let (builder, listed) =
        ResponseBuilder::for_query(&q, ResponseCode::NOERROR).with_records_that_fit(records);
    let note = (listed < total).then(|| format!("Lists {listed} of {total} names"));
    let response = builder.with_note(note.clone()).build();

    let bytes = response.clone().into_bytes(u16::MAX);
    ephyra::cover(listed < l.names.len(), "hit the size limit");
    let parsed = Response::parse(&bytes).expect("parses");
    assert!(
        !parsed.truncated(),
        "the listing plus its note must fit in one TCP message"
    );
    assert_eq!(parsed.records().count(), listed);
    if l.edns {
        assert_eq!(parsed.note(), note.as_deref());
    }
    // Everything that fit is the leading run of names.
    assert!(listed <= l.names.len());
}

fn doh_url(g: &mut Source) -> String {
    let host = if g.bool_with(0.3) {
        format!("[{}]", Ipv6Addr::from(u128::from(g.int::<u64>(..)) << 64))
    } else if g.bool_with(0.3) {
        Ipv4Addr::from(g.int::<u32>(..)).to_string()
    } else {
        // A non-numeric TLD: WHATWG parses a host whose last label is a number as IPv4.
        let name = domain_name(g).to_lowercase().replace('_', "-");
        let name = name
            .split('.')
            .map(|l| l.trim_matches('-'))
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>();
        let name = name.into_iter().take(4).collect::<Vec<_>>().join(".");
        if name.is_empty() {
            "example".to_owned()
        } else {
            name + ".example"
        }
    };
    let port = if g.bool_with(0.3) {
        format!(":{}", g.int(1u16..=u16::MAX))
    } else {
        String::new()
    };
    let path = *g.pick(&["", "/", "/dns-query", "/a/b%20c", "/resolve/"]);
    format!("https://{host}{port}{path}")
}

#[ephyra::test(gen = doh_url, tests = 5_000)]
fn doh_url_round_trips(s: String) {
    let Ok(url) = s.parse::<dns_types::DoHUrl>() else {
        panic!("valid https URL rejected: {s}");
    };
    let again: dns_types::DoHUrl = url.to_string().parse().expect("display output parses");
    assert_eq!(again.to_string(), url.to_string());
    assert_eq!(again.host(), url.host());
    assert_eq!(again.port(), url.port());

    let q = Query::new("example.com".parse().unwrap(), RecordType::A).with_id(42);
    let req = q.try_into_http_request(&url).expect("valid request");
    let uri = req.uri().to_string();
    assert!(
        uri.starts_with(url.to_str().as_ref()),
        "{uri} does not start with {url}"
    );
    assert_eq!(
        req.uri().query().map(|q| q.starts_with("dns=")),
        Some(true),
        "{uri}"
    );
    let _ = gens::bool();
}

/// RFC 6891 7: "If an OPT record is present in a received request, compliant responders
/// MUST include an OPT record in their respective responses."
#[ephyra::test(gen = cases(), tests = 2_000)]
fn responses_to_edns_queries_carry_opt(c: Case) {
    let c = Case { edns: true, ..c };
    let q = query(&c);
    let response = ResponseBuilder::for_query(&q, ResponseCode::masked_from_int(c.rcode))
        .with_records(owned_records(&c, &q))
        .with_note(c.note.clone())
        .build();
    let bytes = response.into_bytes(u16::MAX);
    let message = domain::base::Message::from_octets(bytes.as_slice()).expect("valid message");

    assert!(
        message.opt().is_some(),
        "response to an EDNS query has no OPT record"
    );
}
