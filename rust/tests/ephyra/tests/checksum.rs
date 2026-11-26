//! `incremental_inet_checksum::ChecksumUpdate` against a from-scratch RFC 1071 model.
//!
//! Source of truth: RFC 1071 / RFC 1624 and the crate docs, which promise that an
//! update "will adjust the checksum as if it would have been computed for the packet
//! with the new [field]" and that the result always verifies, including for all-zero
//! data (`into_ip_checksum`).

use std::ops::ControlFlow;

use ephyra::{GenExt as _, Source};
use incremental_inet_checksum::ChecksumUpdate;

/// End-around-carry sum of 16-bit words, i.e. the one's complement sum (RFC 1071).
fn ones_sum(words: impl IntoIterator<Item = u16>) -> u16 {
    let mut acc = 0u32;
    for w in words {
        acc += u32::from(w);
        acc = (acc & 0xFFFF) + (acc >> 16);
    }

    acc as u16
}

/// What a receiver checks: the data plus the checksum sums to all ones.
fn verifies(data: &[u16], checksum: u16) -> bool {
    ones_sum(data.iter().copied().chain([checksum])) == 0xFFFF
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Width {
    U16,
    U32,
    U128,
}

impl Width {
    fn words(self) -> usize {
        match self {
            Width::U16 => 1,
            Width::U32 => 2,
            Width::U128 => 8,
        }
    }
}

#[derive(Clone, Debug)]
struct Update {
    width: Width,
    /// Reduced modulo the number of valid offsets when applied.
    offset: usize,
    /// The new field value; only the low `16 * width.words()` bits are used.
    value: u128,
}

#[derive(Clone, Debug)]
struct Case {
    data: Vec<u16>,
    /// The checksum is stored as `0xFFFF` instead of `0x0000` (RFC 768 for UDP).
    udp_style: bool,
    updates: Vec<Update>,
}

fn word(g: &mut Source) -> u16 {
    // Zeros and all-ones are where one's complement has two representations.
    match g.int(0u8..=9) {
        0..=2 => 0,
        3..=4 => 0xFFFF,
        5 => 1,
        6 => 0xFFFE,
        _ => g.int(..),
    }
}

fn field(g: &mut Source, width: Width) -> u128 {
    let words = width.words();
    let mut v = 0u128;
    for _ in 0..words {
        v = (v << 16) | u128::from(word(g));
    }
    v
}

fn case(g: &mut Source) -> Case {
    let all_zero = g.bool_with(0.2);
    let len = g.int(8usize..=40);
    let data = (0..len)
        .map(|_| if all_zero { 0 } else { word(g) })
        .collect();
    let n = g.int(1usize..=6);
    let updates = (0..n)
        .map(|_| {
            let width = *g.pick(&[Width::U16, Width::U32, Width::U128]);
            Update {
                width,
                offset: g.int(0usize..=64),
                value: if all_zero && g.bool_with(0.5) {
                    0
                } else {
                    field(g, width)
                },
            }
        })
        .collect();

    Case {
        data,
        udp_style: g.bool(),
        updates,
    }
}

fn shrink_case(c: &Case, visit: &mut dyn FnMut(Case) -> ControlFlow<()>) -> ControlFlow<()> {
    for i in 0..c.updates.len() {
        if c.updates.len() > 1 {
            let mut s = c.clone();
            s.updates.remove(i);
            visit(s)?;
        }
    }
    if c.data.len() > 8 {
        let mut s = c.clone();
        s.data.pop();
        visit(s)?;
    }
    for i in 0..c.data.len() {
        if c.data[i] != 0 {
            let mut s = c.clone();
            s.data[i] = 0;
            visit(s)?;
        }
    }
    for i in 0..c.updates.len() {
        if c.updates[i].value != 0 {
            let mut s = c.clone();
            s.updates[i].value = 0;
            visit(s)?;
        }
    }
    ControlFlow::Continue(())
}

fn cases() -> impl ephyra::Gen<Value = Case> {
    case.with_shrink(shrink_case)
}

fn read_field(data: &[u16], at: usize, width: Width) -> u128 {
    data[at..at + width.words()]
        .iter()
        .fold(0u128, |acc, w| (acc << 16) | u128::from(*w))
}

fn write_field(data: &mut [u16], at: usize, width: Width, value: u128) {
    let n = width.words();
    for i in 0..n {
        data[at + i] = (value >> (16 * (n - 1 - i))) as u16;
    }
}

fn apply(update: ChecksumUpdate, width: Width, old: u128, new: u128) -> ChecksumUpdate {
    match width {
        Width::U16 => update.remove_u16(old as u16).add_u16(new as u16),
        Width::U32 => update.remove_u32(old as u32).add_u32(new as u32),
        Width::U128 => update.remove_u128(old).add_u128(new),
    }
}

#[ephyra::test(gen = cases(), tests = 20_000)]
fn incremental_update_always_verifies(c: Case) {
    let mut data = c.data.clone();
    let computed = !ones_sum(data.iter().copied());
    let mut checksum = if c.udp_style && computed == 0 {
        0xFFFF
    } else {
        computed
    };
    assert!(verifies(&data, checksum), "model checksum must verify");

    for (step, u) in c.updates.iter().enumerate() {
        let slots = data.len() - u.width.words() + 1;
        let at = u.offset % slots;
        let mask = if u.width == Width::U128 {
            u128::MAX
        } else {
            (1u128 << (16 * u.width.words())) - 1
        };
        let new = u.value & mask;
        let old = read_field(&data, at, u.width);
        write_field(&mut data, at, u.width, new);

        let update = apply(ChecksumUpdate::new(checksum), u.width, old, new);
        checksum = if c.udp_style {
            update.into_udp_checksum()
        } else {
            update.into_ip_checksum()
        };

        assert!(
            verifies(&data, checksum),
            "step {step}: checksum {checksum:#06x} does not verify for {data:04x?}"
        );
        let scratch = !ones_sum(data.iter().copied());
        assert!(
            checksum == scratch || (scratch == 0 && checksum == 0xFFFF),
            "step {step}: incremental {checksum:#06x} vs from-scratch {scratch:#06x}"
        );
    }
}
