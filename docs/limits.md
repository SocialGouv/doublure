# Known limits

Stated here rather than discovered later. If you are writing a risk assessment,
this page and the
[re-identification analysis](re-identification-analysis.md) are the two you
need.

## Channel 2: what "not reversible" actually means

It is easy to read this section as "your shell output leaks". It does not, and
the distinction decides whether the tool is usable at all.

**What the model reads is protected.** A `kubectl` command and its output come
back to the model through the API — channel 1 — and are pseudonymised there
like everything else. Measured:

```
10.1.2.3                              → 172.22.20.25
db-master-01-prod.acmecorp.internal   → vale-glacier-01-prod.litware-contoso.internal
```

**What is not reversible is the EXECUTION.** `kubectl` has to reach the real
cluster; there is no fictional cluster to talk to. So on that path the hook
**blocks** rather than substitutes — its job is to stop the agent sending data
OUT (a `curl` to a third party, a vault read, an environment dump), not to hide
your infrastructure from the model. That second job belongs to channel 1, and
channel 1 does it.

That is inherent, and it will not change.

For **remote MCP it is no longer the case**: `task forward -- <agent>` runs any
agent behind a forward proxy that terminates TLS, pseudonymises JSON-RPC bodies
on the way out and restores them on the way back. Destinations come from a list
the operator writes in the state directory, and an unlisted one is refused.

!!! success "Proven by a real session"

    `tests/forward_e2e.sh` runs a real Claude Code session under the launcher.
    The agent works, its model traffic is seen by the proxy — and the
    destinations Phase 0 measured as escaping are **refused, with no socket
    opened**:

    ```
    api.githubcopilot.com:443 -> refuse (destination non déclarée)
    registry.npmjs.org:443    -> refuse (destination non déclarée)
    mcp.context7.com:443      -> refuse (destination non déclarée)
    api.anthropic.com:443     -> tunnel
    ```

    And the session still completes. A chokepoint that stopped the agent
    working would be a wall, not a control.

## D9 is not met on a workstation

**On the default path, the egress harness detects; it does not prevent.** Under
`task forward`, it *does* prevent — measured above — but only for what honours
`HTTPS_PROXY`. A process opening a raw socket ignores it, so the deployment
shape (an `internal` network, the proxy alone straddling both sides) remains
the only enforcement. Say exactly that to a DPO.

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
    forward-proxy mode brings remote MCP — JSON-RPC, which the walker already
    knows how to traverse — into the reversible channel. That is what
    `task forward` now does.

A local firewall cannot fix it either way, because `api.anthropic.com` and
`mcp-proxy.anthropic.com` resolve to the **same address**.

The shape that does close it is deployment: an `internal` network for the
agent, with the proxy alone straddling both sides. That is not a rule to
maintain but an **absence of route**. See
[Network isolation](d9-network-isolation.md).

## The five preserved attributes are leaks

Environment, `/24` co-membership, human vs service, internal vs external, and
the interval between two dates
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

!!! note "Recall was measured, and it decided the model"

    The first model shipped here returned **two of the three people** in a
    1.1 KB incident file. The third was found at 0.96 when its line was
    submitted alone, so the miss was context, not length — and chunking bought
    it back at 1527 ms against 315 ms.

    Measuring an alternative was cheaper than paying that. GLiNER takes its
    types in natural language, and asking for `address` rather than
    `postal address` is the difference between finding the address and not:
    **3/3 people, both dates and the address in one span, 249 ms**, and zero
    spans on a pure infrastructure file. The chunking arbitration disappeared
    with the measurement that made it unnecessary.

    Formulating those labels is now a detection decision. Changing them without
    measuring is changing the detector.

!!! danger "Why this gap deserved its own service"

    A value nobody detects produces no vault entry, no unresolved surrogate,
    and no `public_by_shape` line — that list counts what a *form rule* opened,
    not what was never seen. Nothing in the logs distinguished "there was no
    name in that file" from "three names went out in the clear". The only way
    to find it was to ask the detector.

    That is the shape to look for in whatever remains: not the errors, the
    silences.

## Two shapes that cannot be told apart

**A line number and a business identifier are the same string.** Digits, a tab,
at the start of a line, sometimes right-aligned by spaces. Tool output numbers
its lines that way; a padded TSV numbers its rows that way. Two attempts at a
local discriminant both let a real identifier out in the clear, so the entity a
span covers is no longer trimmed at its head: on the FIRST line of a numbered
output, the number is substituted along with the entity, and the numbering is
wrong by one line there.

Damaged numbering is visible — the model says so, we have watched it do it. An
identifier that leaves is not.

**An upstream that goes silent mid-body has no deadline.** Distinct from one
that truncates, which answers 502 since round 8. A stalled exchange waits.

## Residuals that are counted

| Residual | Why it stays |
|---|---|
| a single-label domain under a ccTLD used as a file extension (`acme.pl`) | removing those extensions turns `main.py` and `lib.rs` into fake domains, which has already broken a real session |
| a fictional external host on a real TLD (`alpine-relecloud.net`) — **only under `domaines_fictifs=tld_reels`** | the default is now the RFC 2606 reserved space, which is provably nobody's; the real-TLD space stays reachable, but the operator has to declare it |
| a package under a third-party prefix (`sigs.k8s.io/tenant-acme`) | indistinguishable from a real module without an inventory |
| a vendor media type (`application/vnd.acme.x+json`) | dotted by nature; only an inventory can separate it |
| a query parameter *name* without a dot, at-sign or colon (`?jdoe=`) | indistinguishable from an API parameter name |
| `tools[].name`, `mcp_servers[].name`, `allowed_tools` | routing keys — substituting them breaks the tool silently |

Every one of these is a question of **inventory**, not of shape. Filling
`config/inventory.txt` closes them for your environment; no form rule can.

## Residuals that are not counted

**A surrogate truncated by the model is not restored, and nothing counts it.**
It is not a leak — fiction stays fiction — but the operator is shown a
fictional value with no way to tell, and an unresolved surrogate is counted
while one nobody recognises as such is not.

**The same name written two ways gets two identities.** Fragments are now
joined across any horizontal whitespace, so `Marguerite<nbsp>Vasseur` is one
entity rather than two — but the vault key keeps the exact spacing, so the
ordinary-space and non-breaking-space spellings are two vault entries and two
surrogates. Nothing leaks; the model sees two people across two documents.
Normalising the key would fix it and would also orphan every entry already
sealed under the old key, so what has been sent could no longer be restored.

That stopped being theoretical: a date field detected as `3 février 2026 à
14h32` made the whole string the vault key, so the model quoting the date alone
matched nothing and the operator read a date that never existed. Spans are now
narrowed to the entity before they reach the vault — the key is the date, not
the field carrying it. The class remains for anything the model paraphrases
rather than quotes; the announcement asks for whole identifiers, which
mitigates without measuring.

**Only `gzip` is decompressed on an inspected MCP channel.** A `deflate` or
`brotli` body is treated as unreadable and the exchange is refused. Adding a
codec is small, but every decompression path needs the output bound and the
adversarial pass that gzip got; until then the failure is a loud 502 rather
than something relayed unread.

**Two dates glued through a shared year lose the second one's day and month.**
`March 15, 2020/04/16` shifts the first and leaves `04/16` verbatim: the two
matches overlap on the year, and the longer one wins. The year — the only part
that could date the incident on its own — is substituted; a day and month
without it remain. Reachable only if a detector spans such a concatenation.

**A version-shaped string can be read as a date.** `v3.14.2020` shifts to
`v11.6.2022`. Nothing real leaves; something that was never a date comes back
changed, and only if a detector marked it.

**A date within about three years of `9999-12-31` loses its interval.** The
shift rotates within the representable range rather than overflowing, because
overflowing meant copying the real date VERBATIM into the surrogate — and
`9999-12-31` is the ordinary "no end date" of a contract, not a laboratory
case. Rotating keeps the surrogate a date and keeps the mapping injective; what
it costs is the gap to the other dates of the document, for those few values
only. The alternative — shifting them the other way — would let two distinct
real dates land on the same surrogate.

**A four-aligned prefix hides a base64 payload from the sweep.** Prepending a
number of alphabet characters that is a multiple of four preserves the base64
alignment, so every receiver reads straight through and recovers the real value
— while the sweep decodes the whole run at once, gets non-UTF-8 bytes and
concludes there is no payload. The value therefore leaves encoded, with no vault
entry and nothing to count. Distinct from the accepted residual below, where
letters glued in front SHIFT the alignment so that nobody reads the value.
Closing it means trying the shifted alignments when the anchored reading fails,
which touches the core of the sweep; it is pinned by a test that ASSERTS the
leak so that it is counted rather than silent, and that test goes red the day it
is closed.

**A JWT's parts are not read one by one.** A JWT is base64URL without padding —
not the alphabet this proxy reads — and its three parts are decoded as one
stream or not at all. A real value placed in its payload (`iss`, `aud`) therefore
leaves in the clear for whoever decodes that part, and whether the token is
traversed at all depends on how its parts' lengths align: neither behaviour is a
defensible invariant. Pinned by a test that asserts the leak, so that it is
counted rather than silent; it goes red the day the parts are read.

**A date-shaped string that is not a valid date stays verbatim.**
`2020-02-30`, common in an export, is not parsed, so it is carried through as
ordinary text inside a larger value, like any word the module preserves around
a date. Its year is real. Closing it would mean substituting anything with the
SHAPE of a date, which would take `v3.14.2020` above with it.

**Two keys that denote the same entity abort the exchange, loudly.** If a JSON
object carries `Alice.Dupont@acme.internal` and `alice.dupont@acme.internal` as
two distinct keys, canonicalisation gives them one surrogate — correctly, since
they are one address — and there is then no way to render both. The two real
options are to refuse noisily or to drop one silently; the second is the exact
failure this guard was added to close. Merging the values, or tagging the
collision, would change the schema the server expects and let the exchange
continue while the tool receives something it cannot read.

**A base64 payload that decodes as UTF-8 is treated as text, whatever it is
declared to be** — and nothing is layered on top of that decision. A guard that
asked "does this look like text?" was tried and removed: it refused on a NUL
byte, so the sender only had to slip one in to switch the substitution off, and
nothing counted it. Residual, stated: a binary made only of bytes that form
valid UTF-8 gets traversed, so it may come out modified. That failure is
visible; the other one is not.

**Two places have no deadline, on purpose.** An inspected exchange gives up on
an upstream that stops sending — a silence is not a truncation: it produces no
error, no close, no byte, and the agent waits for a response that never comes.
The deadline is an *inactivity* one (a slow body that keeps arriving is
licit, and cutting it would read as an upstream failure).

It does not apply to a **tunnelled** destination, where a silence and a
long-lived stream are indistinguishable — that is what inspection buys: it
knows what it is waiting for. Nor to a **client** holding its connection open
between two turns, where no upstream socket is held and closing would cost a
handshake per pause.

**What an inactivity deadline cannot catch, by construction**: an upstream
that sends one byte just under the deadline holds an exchange indefinitely. A
total ceiling would catch it and would also cut a large body arriving slowly —
the twin defect, and the reason the deadline is written this way. It stays
bounded by what an attacker needs first: the destination must be *declared*
inspectable, and every request is one the agent itself made. Likewise, a
response that stays silent for over two minutes is given up on even if it
would have arrived — on an inspected destination the whole body is buffered
anyway, so a genuine stream is already refused there for a different reason.

## Operational

- **Policy files written before 2026-08-12 are no longer read.** Their names
  came from substituting characters (`:` → `-`, `/` → `_`), which cannot be
  injective: distinct scopes wrote the same file, so a *reveal* decision taken
  in one applied to another. Names now carry a fingerprint of the exact scope.
  A rule that is no longer found falls back to *anonymise*, never to *reveal* —
  the safe direction — but **reveal decisions already taken must be made
  again**.
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
