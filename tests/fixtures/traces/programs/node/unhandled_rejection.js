// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// Node fixture: an unhandled promise rejection from an async function (async frames).
'use strict';

async function fetchRecord(id) {
  await Promise.resolve();
  throw new Error('record ' + id + ' not found');
}

async function loadProfile(id) {
  const record = await fetchRecord(id);
  return record.profile;
}

async function main() {
  await loadProfile(7);
}

main();
