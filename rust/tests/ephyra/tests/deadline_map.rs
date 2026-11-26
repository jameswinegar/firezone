//! `DeadlineMap` against a model that recomputes every deadline from scratch.
//!
//! Source of truth: the crate docs. "Every mutable access marks the value; marked
//! values are polled again before the cache is read", `poll_timeout` "returns the
//! earliest deadline", and `due_mut` "hands out and marks the marked entries and those
//! due at `now`". The invariant callers rely on: no value whose deadline has passed is
//! ever left out of `due_mut`, and `poll_timeout` never reports a later deadline than
//! the earliest one any value reports.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use deadline_map::{DeadlineMap, PollTimeout};
use ephyra::gens;

#[derive(Debug)]
struct Value(Option<Instant>);

impl PollTimeout for Value {
    fn poll_timeout(&mut self) -> Option<Instant> {
        self.0
    }
}

#[derive(Clone, Debug, ephyra::Arbitrary)]
enum Op {
    PollTimeout,
    Insert(
        #[ephyra(gen = gens::int(0u8..=5))] u8,
        #[ephyra(gen = gens::option(gens::int(0u64..=10)))] Option<u64>,
    ),
    SetViaGetMut(
        #[ephyra(gen = gens::int(0u8..=5))] u8,
        #[ephyra(gen = gens::option(gens::int(0u64..=10)))] Option<u64>,
    ),
    GetOrInsert(
        #[ephyra(gen = gens::int(0u8..=5))] u8,
        #[ephyra(gen = gens::option(gens::int(0u64..=10)))] Option<u64>,
        /// Overwrite the value through the returned reference.
        #[ephyra(gen = gens::option(gens::option(gens::int(0u64..=10))))]
        Option<Option<u64>>,
    ),
    Remove(#[ephyra(gen = gens::int(0u8..=5))] u8),
    ExtractOdd,
    /// Sets the first `n` values handed out by `iter_mut`.
    IterMutSet(
        #[ephyra(gen = gens::int(0usize..=6))] usize,
        #[ephyra(gen = gens::option(gens::int(0u64..=10)))] Option<u64>,
    ),
    /// Sets the first `n` values without a deadline handed out by `filter_mut`.
    FilterMutSet(
        #[ephyra(gen = gens::int(0usize..=6))] usize,
        #[ephyra(gen = gens::option(gens::int(0u64..=10)))] Option<u64>,
    ),
    /// Advances to `now` and sets every due value to the deadline given.
    Due(
        #[ephyra(gen = gens::int(0u64..=10))] u64,
        #[ephyra(gen = gens::option(gens::int(0u64..=10)))] Option<u64>,
    ),
    /// `get_mut` without changing anything.
    Touch(#[ephyra(gen = gens::int(0u8..=5))] u8),
    Reindex,
    Clear,
}

fn at(base: Instant, d: Option<u64>) -> Option<Instant> {
    d.map(|s| base + Duration::from_secs(s))
}

#[ephyra::test(gen = gens::vec(ephyra::any::<Op>()).len(0..=40), tests = 20_000)]
fn deadline_map_matches_model(ops: Vec<Op>) {
    let base = Instant::now();
    let mut map: DeadlineMap<u8, Value> = DeadlineMap::default();
    let mut model: BTreeMap<u8, Option<u64>> = BTreeMap::new();

    for (step, op) in ops.iter().enumerate() {
        match op {
            Op::PollTimeout => {}
            Op::Insert(k, d) => {
                let prev = map.insert(*k, Value(at(base, *d)));
                assert_eq!(
                    prev.map(|v| v.0),
                    model.insert(*k, *d).map(|d| at(base, d)),
                    "step {step}"
                );
            }
            Op::SetViaGetMut(k, d) => {
                if let Some(v) = map.get_mut(k) {
                    v.0 = at(base, *d);
                }
                if let Some(m) = model.get_mut(k) {
                    *m = *d;
                }
            }
            Op::GetOrInsert(k, d, overwrite) => {
                let v = map.get_or_insert(*k, Value(at(base, *d)));
                let m = model.entry(*k).or_insert(*d);
                assert_eq!(
                    v.0,
                    at(base, *m),
                    "step {step}: get_or_insert returned a different value"
                );
                if let Some(o) = overwrite {
                    v.0 = at(base, *o);
                    *m = *o;
                }
            }
            Op::Remove(k) => {
                assert_eq!(
                    map.remove(k).map(|v| v.0),
                    model.remove(k).map(|d| at(base, d)),
                    "step {step}"
                );
            }
            Op::ExtractOdd => {
                let mut got: Vec<u8> = map
                    .extract_if(|k, _| k % 2 == 1)
                    .into_iter()
                    .map(|(k, _)| k)
                    .collect();
                got.sort();
                let want: Vec<u8> = model.keys().copied().filter(|k| k % 2 == 1).collect();
                model.retain(|k, _| k % 2 == 0);
                assert_eq!(got, want, "step {step}");
            }
            Op::IterMutSet(n, d) => {
                for (k, v) in map.iter_mut().take(*n) {
                    v.0 = at(base, *d);
                    model.insert(k, *d);
                }
            }
            Op::FilterMutSet(n, d) => {
                for (k, v) in map.filter_mut(|v| v.0.is_none()).take(*n) {
                    assert!(
                        v.0.is_none(),
                        "step {step}: filter_mut handed out a non-matching value"
                    );
                    v.0 = at(base, *d);
                    model.insert(k, *d);
                }
            }
            Op::Due(now, d) => {
                let now_i = base + Duration::from_secs(*now);
                let truly_due: BTreeSet<u8> = model
                    .iter()
                    .filter(|(_, d)| d.is_some_and(|d| d <= *now))
                    .map(|(k, _)| *k)
                    .collect();
                let mut handed: BTreeSet<u8> = BTreeSet::new();
                for (k, v) in map.due_mut(now_i) {
                    handed.insert(k);
                    if v.0.is_some_and(|t| t <= now_i) {
                        v.0 = at(base, *d);
                        model.insert(k, *d);
                    }
                }
                assert!(
                    truly_due.is_subset(&handed),
                    "step {step}: due_mut({now}) handed out {handed:?}, missing some of {truly_due:?}"
                );
            }
            Op::Touch(k) => {
                let _ = map.get_mut(k);
            }
            Op::Reindex => map.reindex(|_, _| {}),
            Op::Clear => {
                map.clear();
                model.clear();
            }
        }

        // Read-only invariants after every step.
        assert_eq!(map.len(), model.len(), "step {step}: len");
        let expected = model
            .values()
            .filter_map(|d| *d)
            .min()
            .map(|s| base + Duration::from_secs(s));
        assert_eq!(
            map.poll_timeout(),
            expected,
            "step {step}: poll_timeout after {op:?}"
        );
        for (k, d) in &model {
            assert_eq!(
                map.get(k).map(|v| v.0),
                Some(at(base, *d)),
                "step {step}: get({k})"
            );
        }

        // `due_mut` at the earliest deadline hands out at least every value that is due.
        if let Some(earliest) = expected {
            let handed: BTreeSet<u8> = map.due_mut(earliest).map(|(k, _)| k).collect();
            for (k, d) in &model {
                if d.is_some_and(|d| base + Duration::from_secs(d) <= earliest) {
                    assert!(
                        handed.contains(k),
                        "step {step}: due value {k} not handed out at its deadline"
                    );
                }
            }
        }
    }
}
