# Ephyra properties

Property tests written with [Ephyra](https://github.com/datadog-labs/ephyra) for connlib's parsers, data structures and DNS-over-TCP stack. The crate is standalone (its own `[workspace]` and lockfile, seeded from `rust/Cargo.lock`) so the suite and its dependencies stay out of the main workspace. It copies the workspace's `[patch.crates-io]` section because path dependencies don't inherit it.

Run everything with `cargo test` from this directory. `EPHYRA_SEED`, `EPHYRA_TESTS`, `EPHYRA_BUDGET_MS` and `EPHYRA_FAILURES` change a run without recompiling, and a failure prints an `EPHYRA_REPLAY=<seed>:<iteration>` line that reruns exactly that case. Failures are remembered in `.ephyra/regressions/` and replayed first on the next run. The release profile keeps debug assertions and overflow checks on, so `cargo test --release` is the fast way to run long searches.

Tests named `*_regressions.rs`, and the plain `#[test]` reproducers at the end of `flow_tracker.rs`, fail on the code they were written against (upstream `023d09d0`). They are the reproducers for the findings below and should pass once each bug is fixed.

## Properties

| File | Property | Oracle and source |
|---|---|---|
| `checksum.rs` | `incremental_update_always_verifies` | Chains of 16/32/128-bit field updates via `ChecksumUpdate` always verify and match a from-scratch RFC 1071 sum, including all-zero data and the RFC 768 `0xFFFF` encoding. |
| `deadline_map.rs` | `deadline_map_matches_model` | Op sequences against a `BTreeMap` model: `poll_timeout` is the earliest deadline, and `due_mut` never leaves out a due value (crate docs). |
| `ip_packet.rs` | `constructed_packets_are_valid` | `make::*` packets (UDP, TCP with options, ICMP echo, ICMP errors) reparse identically and every checksum verifies under an independent RFC 1071 implementation; ICMP errors quote the original as RFC 792 / 4443 require. |
| `ip_packet.rs` | `ipv4_options_are_stripped_consistently` | IPv4 packets with options parse, and on Linux come out without options with a valid header and untouched transport layer. |
| `dns_types.rs` | `query_round_trips`, `response_survives_serialization` | Build, serialize, truncate and parse back; truncation sets TC and respects `max_len`; notes survive for EDNS queries (crate docs). |
| `dns_types.rs` | `records_that_fit_leave_room_for_the_note` | Mirrors the device-browse path: the listing plus its note always fits one TCP message. |
| `dns_types.rs` | `doh_url_round_trips` | `DoHUrl` parse and display round trip, and DoH requests carry the `dns=` parameter. |
| `dns_types.rs` | `responses_to_edns_queries_carry_opt` | RFC 6891 section 7: a response to a query with OPT carries OPT. |
| `dns_over_tcp.rs` | `every_query_over_tcp_is_answered` (and `_below_64k`) | The real `Client` and `Server` over their in-memory TCP stacks with a strict sans-IO driver and simulated clock: every query is answered once, with its own response, before the timeout. The bounded variant adds pipelining, out-of-order answers and repeated stub IDs while keeping each direction under 64 KiB. |
| `flow_tracker.rs` | `every_flow_closes_once_and_counts_no_phantom_bytes`, `every_byte_of_plain_traffic_is_counted` | Gateway-style packet sequences through the tracker, observed in the `flow-log-writer` spool: every opened flow closes once, no report counts bytes that were never seen, and documented-countable traffic is counted in full. |

## Findings

**DNS over TCP stalls permanently after 64 KiB on a connection** (`dns_over_tcp_regressions.rs`: `client_keeps_receiving_after_64k_of_responses`, `server_keeps_receiving_after_64k_of_queries`). `codec::try_recv` reads through smoltcp's `Socket::recv`, which hands out only the contiguous part of the 65,535-byte receive ring, and refuses to consume a partial message. smoltcp's TCP receive path never rewinds the ring, so the message that straddles byte 65,535 of the stream can never be read. Nothing is consumed, the window closes, and every later message on that connection is stuck behind it. Both `Client` (the one connection it keeps per resolver) and `Server` are affected; the server hit it at query 851 of ~77 bytes, the client at the seventh ~10 KB response.

**DNS-over-TCP messages of 65,534 and 65,535 bytes cannot be sent** (`largest_tcp_response_is_delivered`). `l3_tcp::create_tcp_socket` sizes both buffers to `u16::MAX` so that one maximum-size message fits, but the 2-byte length prefix makes that message 65,537 bytes. `codec::try_send` fails after writing the prefix and the server aborts the connection.

**Flow-log reports of a split flow overwrite each other within one event-loop tick** (`flow_tracker.rs`: `flow_split_by_syn_in_one_tick_keeps_both_reports`, `flow_split_by_path_flapping_in_one_tick_keeps_both_reports`). `flow-log-writer` names a report after the flow's protocol, inner 4-tuple and `flow_start`, and documents that "distinct flows never collide". The tunnel processes a received batch with one `now`, so when the tracker splits a flow (a SYN after data, or the 17th outer tuple) in the tick the flow started, both flows have the same name and the second overwrites the first's `.start` and `.end` reports. The context cap exists so "a peer cannot flap its path to keep later tuples out of the log"; flapping all paths within one batch does exactly that.

**Responses built for EDNS queries carry no OPT record unless they carry a note** (`responses_to_edns_queries_carry_opt`). RFC 6891 section 7 requires one. Low impact; resolvers that see no OPT may downgrade to plain DNS for the server.

Nothing failed in `incremental-inet-checksum`, `deadline-map`, the `ip-packet` constructors and option stripping, or the rest of `dns-types`.
