// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// Rust fixture: a panic inside a spawned thread (run with RUST_BACKTRACE=1).
use std::thread;

fn check(job: u32) {
    if job == 2 {
        panic!("job {job} has no owner");
    }
}

fn run(job: u32) {
    check(job);
}

fn main() {
    let handle = thread::spawn(|| {
        for job in 1..=3 {
            run(job);
        }
    });
    let _ = handle.join();
}
