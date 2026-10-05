# Security policy

## Supported versions

Fixes go into the `main` branch and the next release. Older releases are not
patched.

## Reporting a vulnerability

Please report it privately through GitHub:
<https://github.com/Git-huber2007/CipherGuard/security/advisories/new>

Do not open a public issue for a vulnerability.

Include:

- The version or commit you tested.
- What an attacker can do, and what they need in order to do it.
- Steps to reproduce. A capture file or a request that triggers the problem is
  the most useful thing you can send.

This is a small volunteer project, so there is no guaranteed response time. You
will be credited in the fix unless you ask not to be.

## What counts

CipherGuard parses untrusted captures and can serve an HTTP API, so these are
in scope:

- A crafted capture that crashes the dissector, hangs it or makes it use
  unbounded memory.
- Reading or writing files outside the intended directories through an upload
  or a path argument.
- Reaching an API route without the token when one is required, or reading the
  API from another origin.
- Packet payload bytes, keys or nonces being written to disk, a database or a
  log.
- Any outbound network call made by the tool.

The README section "Security posture of the analyzer itself" describes the
intended behaviour.

These are not vulnerabilities in CipherGuard:

- Weak cryptography in a network you analysed. Reporting that is what the tool
  is for.
- Weak suites in the lab captures under `samples/`. They are generated to be
  weak.
- Running `cipherguard serve` with `--insecure-bind`. That flag removes the
  token check on purpose.
