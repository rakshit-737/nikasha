// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// Rust fixture: unwrap() on None (run with RUST_BACKTRACE=full).
use std::collections::HashMap;

fn lookup(table: &HashMap<&str, u32>, key: &str) -> u32 {
    *table.get(key).unwrap()
}

fn timeout(table: &HashMap<&str, u32>) -> u32 {
    lookup(table, "timeout") * 1000
}

fn main() {
    let mut table = HashMap::new();
    table.insert("port", 8080);
    println!("{}", timeout(&table));
}
