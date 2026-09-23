// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// Node fixture: a custom Error class thrown through nested functions.
'use strict';

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

function requireKey(config, key) {
  if (!(key in config)) {
    throw new ConfigError('missing key: ' + key);
  }
  return config[key];
}

function loadPort(config) {
  return Number(requireKey(config, 'port'));
}

function main() {
  console.log(loadPort({ host: 'localhost' }));
}

main();
