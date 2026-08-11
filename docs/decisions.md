# Locked decisions

Nine decisions settle most arguments before they start. They are locked: they
can be revisited with an argument, never routed around.

## D1 — Plausible surrogates, never sentinels

`[HOST_1]` and `<IP_3>` destroy the agent's ability to reason. A surrogate is
plausible and **type-faithful**, and the invariant is stated once:

> A surrogate must be indistinguishable in nature from what it replaces, and
> must never designate a real-world entity.

Both halves matter. The first was breached when a `/24` came out as a word.
The second when varying an octet of a documentation range walked out of
reserved space into somebody's routed network — a command the model proposes
would then reach a stranger's machine. See [Surrogates](surrogates.md).

## D2 — No resolution inside a stream

Restoring surrogates inside `partial_json` fragments cuts values in half.
Accumulate, wait for the block to close, parse, resolve atomically.

## D3 — Signed blocks stay opaque

`thinking` and `redacted_thinking` are signed by the API. Rewriting them
invalidates the signature. The list of deltas to resolve is therefore
**positive**, not an exclusion list: an unknown future delta is left alone
rather than modified.

## D4 — A secret is a reference, never restored

Tokens, passwords and keys are replaced by a reference and are **never
restored** into model output. Restoring one would put a live credential back
into a command the model just generated. This is why URL credentials are
stripped before anything else touches the URL.

## D5 — Fail-closed

An unknown surrogate is never guessed. A detector outage is a 503, not a
best-effort pass-through. A hallucinated surrogate resolves to nothing rather
than to a plausible neighbour — a fictional host wearing a real zone is worse
than an unresolved name.

## D6 — Strict injectivity

Two real values never share a surrogate, enforced by uniqueness in the store
and checked in CI. Measured on 10 000 values: zero collisions, byte-for-byte
determinism, and 50 threads writing at once without a duplicate.

## D7 — The detector is a separate process

AnonShield is GPL-3.0 and is reached over HTTP only. Nothing imports across the
boundary, in either direction, and a test enforces it. See
[Licensing](licensing.md).

## D8 — Read-only MVP

No SCIM, no RBAC. A permission model that nobody administers is a false
guarantee.

## D9 — The proxy is the only network path

This is the one decision **not met on a workstation**, and it is stated as
such. Four destinations out of five do not honour `ANTHROPIC_BASE_URL`. The
answer is deployment shape — an `internal` network with the proxy alone
straddling both sides — not a local firewall: `api.anthropic.com` and
`mcp-proxy.anthropic.com` resolve to the same address, so no IP rule can
separate them. See [Network isolation](d9-network-isolation.md).

## The answers that came with them

| Question | Answer |
|---|---|
| Determinism scope | per **project** by default; session, tenant or global on request |
| Tool coverage | nothing hard-coded per tool — generic detection plus custom patterns |
| Preserved attributes | environment, `/24` co-membership, human vs service, internal vs external — all four, as **accepted leaks** |
| Vault location | local, same user; outside the repository; treated as a secret |

The four preserved attributes are deliberate: they are what makes the
pseudonymised text still readable as infrastructure. They are also, precisely,
what a re-identification attack would use — which is why they are listed here
and analysed in the [re-identification analysis](re-identification-analysis.md)
rather than left implicit.
