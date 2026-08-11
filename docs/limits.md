# Known limits

Stated here rather than discovered later. If you are writing a risk assessment,
this page and the
[re-identification analysis](re-identification-analysis.md) are the two you
need.

## Channel 2 is not reversible

Bash, WebFetch and MCP do not go through the proxy. The hook **blocks**; it does
not pseudonymise. Anything you deliberately allow through on that channel goes
out as itself.

For Bash this is inherent — a `kubectl` command has to reach the real cluster,
so there is nothing to substitute.

For **remote MCP it is no longer the case**: `task forward -- <agent>` runs any
agent behind a forward proxy that terminates TLS, pseudonymises JSON-RPC bodies
on the way out and restores them on the way back. Destinations come from a list
the operator writes in the state directory, and an unlisted one is refused.

!!! warning "New, and never yet run in a real session"

    The forward mode is covered by tests, including interception proven against
    a client that trusts only our authority. It has not been exercised by a
    real agent for a full session — and in this project, that is the step that
    has found what tests did not, four times.

## D9 is not met on a workstation

**The egress harness detects; it does not prevent.** Say exactly that to a DPO.

Measured on one real session: four destinations out of five escape
`ANTHROPIC_BASE_URL` — `mcp-proxy.anthropic.com` (×12), `mcp.context7.com`
(×11), `registry.npmjs.org` (×4), `api.githubcopilot.com` (×2), against
`api.anthropic.com` (×5). That counts *destinations and connections*, not
volume: the traffic carrying your infrastructure is the model's, and it does go
through the proxy.

!!! info "They escape `ANTHROPIC_BASE_URL`, not a proxy"

    Those same four were **captured through mitmproxy** by the Phase 0 harness,
    with `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS`. So they honour an explicit
    forward proxy; what they ignore is one API client's base-URL setting. A
    forward-proxy mode would bring remote MCP — JSON-RPC, which the walker
    already knows how to traverse — into the reversible channel.

A local firewall cannot fix it either way, because `api.anthropic.com` and
`mcp-proxy.anthropic.com` resolve to the **same address**.

The shape that does close it is deployment: an `internal` network for the
agent, with the proxy alone straddling both sides. That is not a rule to
maintain but an **absence of route**. See
[Network isolation](d9-network-isolation.md).

## The four preserved attributes are leaks

Environment, `/24` co-membership, human vs service, internal vs external
survive substitution on purpose (D1 usability). They are also exactly what a
re-identification attempt would correlate on.

## Detection gaps

Person names, dates and postal addresses **were** the whole of this section
until a real session put three people —
the reporter, the on-call engineer and a customer — in front of a model that
has no class for them. The infrastructure detector is a **cyber-security** NER:
33 labels, `MALWARE`, `THREAT_ACTOR`, `CVE_ID`, `LOCATION`, `ORGANIZATION`, and
no `PERSON`. `Barack Obama met Angela Merkel in Berlin` returned one span:
`Berlin`.

All three are now covered by a **second detector**, in its own process, on the
Apache-2.0 side. It must be running: if it is unreachable the proxy returns
503, exactly as for the other one. `ANONPROXY_PII=off` disables it — an
operator decision, printed at startup — because an outage must not decide that
for you.

A **date is shifted, not drawn**: one constant per scope, so every interval
survives and an incident still reads as a sequence. The end-to-end proof that
asserted this gap *inverted* has been turned the right way round — it failed
the day the gap closed, which is what it was written to do.

!!! warning "Recall depends on context, and it is measured"

    On a 1.1 KB incident file the model returned **two of the three people in
    it**. The one it missed was detected at 0.96 when the same line was
    submitted alone — so the miss is not a matter of document length but of
    context.

    Measured on that file: whole document 315 ms and the name missed;
    300-character windows 669 ms, still missed; paragraphs 894 ms, still
    missed; **line by line 1527 ms and found**, with two false positives.
    Chunking therefore buys recall at roughly five times the latency, and the
    false positives fall in the harmless direction — they substitute more.

    Left as an arbitration rather than decided quietly, because the cost lands
    on every request of every session.

!!! danger "Why this gap deserved its own service"

    A value nobody detects produces no vault entry, no unresolved surrogate,
    and no `public_by_shape` line — that list counts what a *form rule* opened,
    not what was never seen. Nothing in the logs distinguished "there was no
    name in that file" from "three names went out in the clear". The only way
    to find it was to ask the detector.

    That is the shape to look for in whatever remains: not the errors, the
    silences.

## Residuals that are counted

| Residual | Why it stays |
|---|---|
| a single-label domain under a ccTLD used as a file extension (`acme.pl`) | removing those extensions turns `main.py` and `lib.rs` into fake domains, which has already broken a real session |
| a package under a third-party prefix (`sigs.k8s.io/tenant-acme`) | indistinguishable from a real module without an inventory |
| a vendor media type (`application/vnd.acme.x+json`) | dotted by nature; only an inventory can separate it |
| a query parameter *name* without a dot, at-sign or colon (`?jdoe=`) | indistinguishable from an API parameter name |
| `tools[].name`, `mcp_servers[].name`, `allowed_tools` | routing keys — substituting them breaks the tool silently |

Every one of these is a question of **inventory**, not of shape. Filling
`config/inventory.txt` closes them for your environment; no form rule can.

## Residuals that are not counted

**A surrogate truncated by the model is not restored, and nothing counts it.**
It is not a leak — fiction stays fiction — but it is a blind spot in the
observability, which contradicts the rule that an accepted residual must be
countable. The announcement asks the model to quote identifiers whole; that
mitigates without measuring.

## Operational

- **The detector does not reload its lists.** Change `config/` and restart it,
  or you will debug a fix that is not loaded — that has produced three false
  diagnostics in one day.
- **The vault and the master secret live in the same directory.** One wrong
  move takes both, and then nothing already sent can be restored.
- No KMS envelope encryption, no key rotation, no immutable access log, no
  enumeration protection. Out of MVP scope, and named.

## What has been proven

| Claim | Proof |
|---|---|
| zero real values leave on channel 1 | a real Claude Code session captured through mitmproxy: **0 real values across 427 KB**, restoration 3/3 |
| a forbidden command is stopped before execution | traced, with the reason quoted back by the model |
| injectivity and determinism | 10 000 values, 0 collisions, byte-for-byte reproducible |
| detection latency | P95 100.6 ms against a 150 ms budget |
| the GPL boundary | a test that fails on any import crossing it |

None of those prove the absence of a leak in general. They prove specific
claims, which is the most any of them can do.
