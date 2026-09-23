// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// Rust fixture: index out of bounds panic (run with RUST_BACKTRACE=1).
fn pick(values: &[u32], i: usize) -> u32 {
    values[i]
}

fn last(values: &[u32]) -> u32 {
    pick(values, values.len())
}

fn main() {
    let values = vec![1, 2, 3];
    println!("{}", last(&values));
}
