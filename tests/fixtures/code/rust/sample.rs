// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;

macro_rules! bail {
    ($msg:expr) => {
        return Err(make_error($msg))
    };
}

pub struct Cache<K> {
    map: HashMap<K, u32>,
}

pub enum Mode {
    Fast,
    Safe,
}

pub trait Store {
    fn get(&self, k: &str) -> Option<u32>;
    fn has(&self, k: &str) -> bool {
        self.get(k).is_some()
    }
}

impl<K: std::hash::Hash + Eq> Cache<K> {
    pub fn new() -> Self {
        Cache { map: HashMap::new() }
    }

    fn put(&mut self, k: K, v: u32) {
        self.map.insert(k, v);
    }
}

fn make_error(msg: &str) -> String {
    msg.to_string()
}

pub fn run(input: &str) -> Result<u32, String> {
    if input.is_empty() {
        bail!("empty");
    }
    println!("{}", checksum(input));
    let n = parse_num(input)?;
    Ok(n)
}

mod util {
    pub fn helper() -> u32 {
        super::make_error("x").len() as u32
    }
}
