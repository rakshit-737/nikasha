<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# The local web UI (`nikasha serve`)

`nikasha serve` starts a small web page on this machine for people who would rather paste a
report into a form than run a command. It is the same pipeline as `nikasha check`, with the
same verdicts and the same self-contained HTML report, behind three pages:

- **New check**: paste or upload a report, name the repository (a local path or an
  `https://` URL) and optionally the version, git ref and product, and choose whether the
  run may use the network. The reproduction toggle is present but disabled: PoCs run only
  in the sandbox and only with `--repro`, which arrives in M5.
- **Result**: the verdict, score, target and rule; the full HTML report in a frame; and the
  report and the result JSON as downloads.
- **History**: the results of this session, kept in memory only, with a button that
  forgets them all. Nothing is written to disk and nothing survives a restart.

```console
$ pip install 'nikasha[web]'
$ nikasha serve
Nikasha web UI: http://127.0.0.1:51823/?token=k1Q9...
Listening on 127.0.0.1 only. The URL carries this run's access token; do not share it.
```

Open the printed URL. `--port N` pins the port; the default picks a free one.

A check is a plain form submission: the browser waits while the pipeline runs (resolving,
indexing and checking a large repository can take a minute the first time) and is then
redirected to the result. Progress over Server-Sent Events, which SPEC §16.4 lists as a
SHOULD, is not implemented: the pipeline exposes no stage callback yet, so a stream could
only say "still running", which the browser already shows. It can be added without
changing the pages once the pipeline reports its stages.

## Why "localhost only" is not a security boundary

The UI exists because of the MCP Inspector remote-code-execution bug (CVE-2025-49596),
which is the standard failure of local developer servers. That server listened on
localhost with no authentication and no `Origin` check, on the assumption that only the
user could reach it. But every browser tab on the machine is on localhost too. A web page
the user happened to have open could send requests to the server (a cross-site request
from JavaScript, or a plain form post), and DNS rebinding let an attacker's own hostname
resolve to `127.0.0.1` so that even same-origin checks in the browser were of no help.

The Nikasha UI handles embargoed vulnerability reports. A tab that can read them, or can
make the tool run against a repository of the attacker's choosing, is not acceptable. So
the server is built on six rules, each with a test in
`tests/security/test_web_hardening.py`, and all of them live in one module,
`src/nikasha/integrations/web/security.py`, that imports no web framework so it can be
read and tested on its own.

## The six rules

1. **Loopback only, random port.** The socket is bound to `127.0.0.1` before the server
   starts, on a port the operating system picks unless `--port` is given. There is no
   option to bind anywhere else, and the source contains no other address. The test
   binds a socket, reads its address back, and checks the command's signature.

2. **An access token in the URL.** Every run generates `secrets.token_urlsafe(32)` and
   prints it once, in the URL. Every request must carry it, in the query string or in an
   `X-Nikasha-Token` header, and it is compared in constant time. A missing or wrong token
   gets a `403 Forbidden` whose body is exactly that: no hint about what was expected, no
   `WWW-Authenticate`, and the same answer whether the token was absent or wrong. The
   token is never set as a cookie. Cookies are shared across ports on `localhost`, so a
   cookie would be readable by any other local server, and a browser would attach it to a
   cross-site request without the page knowing.

3. **The `Host` header must be ours.** Only `127.0.0.1:<port>` and `localhost:<port>` are
   answered; anything else is `421 Misdirected Request`. This is the DNS-rebinding defence:
   a page at `attacker.example` whose name has been rebound to `127.0.0.1` still sends
   `Host: attacker.example`, and is refused before the token is even looked at.

4. **Every POST needs the token and a same-origin `Origin`.** The `Origin` must be exactly
   `http://<Host>`. Missing, `null`, another site, another port, another scheme, or even
   the other loopback name are all `403 Forbidden`. `Sec-Fetch-Site: cross-site` is refused
   too. A form on another page cannot submit a check or purge the history.

5. **Security headers on every response**, including the refusals: a Content Security
   Policy of `default-src 'none'` with only same-origin script and style,
   `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (the token is in the
   URL, so the referrer must never leave the page), `Cross-Origin-Opener-Policy:
   same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `X-Frame-Options`, and
   `Cache-Control: no-store`. The pages contain no inline script and no inline event
   handler, and load nothing from a CDN. The framed report keeps its own policy (one
   script pinned by SHA-256, no fetches at all) plus permission to be framed by this
   origin only. The frame is sandboxed without `allow-same-origin`, so the report runs
   in an opaque origin and cannot reach the page around it or its token-bearing links.

6. **Caps and validation before use.** The upload and paste limit equals the intake limit
   (`nikasha.ingest.MAX_INPUT_BYTES`), a request larger than that is refused from its
   `Content-Length` before the body is read, a POST with no `Content-Length` (a chunked
   body, which would otherwise be spooled to disk uncapped) is `411`, and an upload is read in chunks up to the
   cap. A repository must be an existing local git directory or an `https://` URL that
   the clone cache's own canonicaliser accepts; `http`, `ssh`, `git`, `file`, `git@` and
   anything starting with `-` never reach git, and UNC paths (`\\host\share`, `//host`)
   are refused before the filesystem is touched, since merely probing one makes Windows
   offer credentials to that host. Versions, refs and product names must fit
   conservative patterns, and a ref additionally passes the same check every revision
   from a report passes. When any field fails, the pipeline does not run.

## Escaping and confidentiality

Pages are Jinja templates with autoescaping on, and nothing derived from input is ever
marked safe. The report itself is rendered by the same code as `nikasha check --format
html`, whose escaping contract has its own test file. The web tests submit the same
payload corpus through the form, the upload name and a failing pipeline message, and
parse the served pages to check that none of it becomes an element.

Report contents are never logged. The uvicorn access log is off (its lines would carry
the token), errors are logged by exception type only, and the pipeline's own error
messages are shown to the user but not written anywhere. The temporary file the
pipeline reads is created in a private directory and removed before the response is
sent; the result JSON records the display name of the paste or upload, never that path,
so two runs on the same report produce the same result.

## What remains

- The token sits in the URL, so it is in the browser's history and visible to anyone who
  can read the user's screen or shell. It is valid only while the process runs.
- There is no TLS. Traffic never leaves the loopback interface, where TLS would protect
  nothing; a user who can sniff loopback already owns the account.
- Another process running as the same user can read the server's memory and connect to
  it. That is the boundary of any local tool.
- The UI is single-user: checks run one at a time, and the history is one list.
