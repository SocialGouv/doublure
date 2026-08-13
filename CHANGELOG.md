# Changelog

Dates are ISO. Versions follow [semantic versioning](https://semver.org); the
leading `0.` is meant literally — see *Not met yet* below before deploying this
anywhere that matters.

## 0.1.0 — 2026-08-13

First tagged state. Everything below was measured before being written here.

### What it does

**A bidirectional proxy between Claude Code and the Anthropic API.** Sensitive
identifiers become plausible surrogates on the way out and are restored on the
way back: the operator reads the real thing, Anthropic sees none of it.

- **Detection** in two processes behind HTTP — an infrastructure NER
  (AnonShield, GPL-3.0, on GPU) and a PII model for people, dates and postal
  addresses. If either is unreachable the proxy answers 503: an outage never
  decides to open.
- **Surrogates that keep the NATURE of what they replace** — an IP stays an IP
  of the same kind, a date stays a date, a path stays a path, a file keeps its
  extension. Four attributes survive on purpose and are documented as leaks:
  environment, /24 co-membership, human vs service, internal vs external.
- **A vault encrypted at rest** (AES-256-GCM, keys derived from a master
  secret), strictly injective, so restoration is never a guess.
- **A confidentiality policy, closed by default.** What no rule covers is
  recorded as a question and the session continues. The operator answers at one
  of three granularities and one of four scopes, the narrowest and nearest
  winning. A secret is never revealable.
- **A PreToolUse hook** that refuses, before execution, what would send data out
  of band — an environment dump, a vault read, a request to a third party.
- **A forward proxy for remote MCP**, which brings JSON-RPC traffic into the
  reversible channel instead of letting it escape.
- **A control service in Go** on a Unix socket, and a VSCode extension that
  speaks to it. A control surface, never an enforcement point: uninstalling the
  interface opens nothing.

### What is proven, and how

Six proofs are replayed before every commit: the Python suite, the Go suite, the
hook suite, and three end-to-end scripts, one of which runs a real Claude Code
session and one of which crosses the Python/Go boundary.

- **0 real values across 821.9 KB** captured with mitmproxy during a real Claude
  Code session, restoration 3/3 operator-side — re-measured on the released
  code (`tests/phase3_e2e.sh`, 2026-08-13, 3 requests to `api.anthropic.com`).
- **10,000 values, 0 collisions**, byte-for-byte determinism across processes.
- A forbidden command **refused before execution**, traced, with the reason
  quoted back by the model.
- Go decrypts a vault Python sealed, and honours a policy answer Python wrote.

### Not met yet

- **D9 is not met on a workstation.** The egress harness detects; it does not
  prevent. Only the deployment shape — an `internal` network with the proxy
  alone straddling both sides — closes it.
- The vault has **no KMS envelope, no key rotation, no immutable access log**.
- Roughly a dozen measured residuals, each stated in
  [Known limits](docs/limits.md) rather than discovered later.

### Method, because it decided the result

Twenty-four rounds of adversarial review found and fixed well over a hundred
defects — 132 of them counted round by round in `CLAUDE.md`, plus the earlier
passes. It stopped when its findings became defects in code it had itself written hours
earlier — and what it could no longer find, **real sessions found in one
afternoon**: four defects, two of which twenty-four rounds had missed. The
model, told that the layer exists, reads its own surrogates and reports what
does not hold. That is now the first thing to do after any change to a
generator.
