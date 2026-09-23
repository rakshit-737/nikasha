// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
'use strict';

function parseQuery(qs) {
  return qs.split('&').map(decodePair);
}

const decodePair = (pair) => {
  const [k, v] = pair.split('=');
  return [decodeURIComponent(k), v];
};

const legacy = function (x) {
  return parseQuery(x);
};

class Router {
  constructor(routes) {
    this.routes = routes;
  }

  match(url) {
    const q = parseQuery(url);
    return this.lookup(q);
  }

  handle = (req) => {
    return this.match(req.url);
  };
}

const helpers = {
  wrap(fn) {
    return fn();
  },
  twice: (x) => double(double(x)),
};

module.exports = new Router([]);
