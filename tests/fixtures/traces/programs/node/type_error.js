// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// Node fixture: TypeError reading a property of undefined, three calls deep.
'use strict';

function userName(session) {
  return session.user.name;
}

function greeting(session) {
  return 'hello ' + userName(session);
}

function main() {
  console.log(greeting({}));
}

main();
