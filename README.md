# Pseudonymisation proxy — Claude Code ↔ Anthropic API

Sensitive identifiers (hosts, IPs, repositories, accounts, images, secrets) are
replaced by **plausible** surrogates before they leave the machine, and
restored on the way back. The operator always sees the real thing; the model
provider sees none of it.

```
claude ──ANTHROPIC_BASE_URL──► proxy :8090 ──► api.anthropic.com
                                  │
                                  ├── AnonShield detector :9000 (GPL, separate process)
                                  └── SQLite vault (outside the repo)

Bash · WebFetch · MCP ──► PreToolUse hook ──► blocked or allowed
```

## Start

```bash
devbox install        # pinned toolchain: uv, go, node, task, curl, jq
task                  # lists everything that can be run

task detector         # detection service :9000 — leave it running
task proxy            # proxy :8090
task session          # a Claude Code session through the proxy
```

The detector needs the NVIDIA driver and a CUDA build of torch, so it lives
outside devbox in its own virtualenv; `services/anonshield/wrapper/install-cuda.sh`
sets it up the first time, and after any `uv sync` inside `upstream/`.

The vault and the master secret live in the user state directory — outside the
repo, never read by the agent. The vault is **encrypted at rest** (AES-256-GCM,
key derived from the master secret): the file alone reveals nothing. **Back up
both: the secret and the database are the two halves; losing either makes
de-anonymisation impossible.**

## Verify

```bash
task test             # unit suites (Python and Go)
task test:egress      # egress harness
task proofs           # every end-to-end proof (needs the detector)

task bench:corpus     # metrics on the annotated corpus
task bench:latency    # detection latency (<150 ms)
task bench:parser     # inputs the bash grammar still refuses
```

The proofs start real processes and, for two of them, a real Claude Code
session. Three defects were only ever found by them, never by the unit suites.

## Layout

| Path | Role |
|---|---|
| `PLAN-proxy-pseudonymisation.md` | Specification — authoritative, do not modify |
| `CLAUDE.md` | Phase state, locked decisions, deviations, round records |
| `REPRISE.md` | Work in progress, what remains, traps already paid for |
| `Taskfile.yml` | Every command the project needs |
| `anthropic_walker.py` | JSON/SSE traversal (supplied; 4 defects fixed, see `CLAUDE.md`) |
| `src/anonproxy/` | Proxy, surrogate engine, vault, policy |
| `go/` | Control service (arbitration API over a Unix socket) |
| `extension/` | VSCode/VSCodium extension — control surface only |
| `services/anonshield/` | **GPL-3.0 side**: upstream plus the HTTP `/detect` wrapper |
| `hooks/` | PreToolUse guard (channel 2) |
| `corpus/` | Golden set; `corpus/real/` is gitignored |
| `docs/re-identification-analysis.md` | DPO deliverable |
| `docs/d9-network-isolation.md` | What escapes the proxy, and the deployment shape that fixes it |
| `docs/hook-parser.md` | Why the hook splits commands with a grammar |

## Configuration

| Variable | Default | Role |
|---|---|---|
| `ANONPROXY_SCOPE` | `project:<folder>` | Determinism scope (`session:`/`tenant:`/`global`) |
| `ANONPROXY_DETECT_URL` | `http://127.0.0.1:9000` | Detection service |
| `ANONPROXY_MODE` | `auto` | `auto` \| `consciencieux` \| `ferme` — a mode is a set of settings |
| `ANONPROXY_REGEX_THRESHOLD` | `8000` | Above this, regex detection (large volumes) |
| `ANON_DEVICE` | `auto` | `cuda` \| `cpu` — `cuda` fails if unavailable |
| `ANON_ALLOWLIST_FILE` | `config/allowlist.txt` | Read by both sides of the D7 boundary |
| `ANON_CUSTOM_PATTERNS_FILE` | `config/custom_patterns.json` | Read by both sides too |
| `ANON_INVENTORY_FILE` | `config/inventory.txt` | "What is ours" — keep the real one out of the tree |

State paths (vault, master secret, policy) also come from the environment; the
control service has no defaults for them and refuses to start without them, so
that a second source of truth cannot drift from the launcher's.

Detection reads `config/allowlist.txt` (§6 of the plan) and
`config/custom_patterns.json` (environment conventions, to be written with jo).
Those files sit on neutral ground: BOTH the detection service and the surrogate
engine read them, so "this token is public" is maintained in one place.

**What ships here is an example, on synthetic material.** A real deployment
fills `config/inventory.txt` with the labels that are ITS OWN — company name,
internal zones, team prefixes — which is the one list you do not want to
publish by committing it. Point `ANON_INVENTORY_FILE` (and
`ANON_ALLOWLIST_FILE`) at files outside the working tree and keep yours there.
A path you ask for and that does not exist is an error, never an empty
inventory: reading it as empty would re-open, in silence, the names it was
meant to close.

## Confidentiality policy

Closed by default: everything detected is substituted, and every value no rule
covers is recorded as a question — without blocking. The operator answers once,
at one of three granularities (this value, this type, this class) and one of
three scopes (global, project, session), each the default for the next.

```bash
task policy -- questions      # what was anonymised without an explicit rule
task policy -- arbitrate      # answer, one at a time
task control                  # arbitration API, for the IDE extension
```

Revealing is the only decision that lets a value out, so it is never a default,
it is traced, and revoking it does not recall what has already gone. A SECRET
is never revealable (D4).

## Licence

**MIT** ([LICENSE](LICENSE)), except `services/anonshield/**` which is
**GPL-3.0** (upstream plus our wrapper). It communicates with the rest **over
HTTP only**: `src/anonproxy/` never imports from that directory (decision D7),
which is what makes the two licences coexist here.

That is not left to prose — [tests/test_gpl_boundary.py](tests/test_gpl_boundary.py)
fails on any import that crosses, in either direction. Details:
[LICENSES.md](LICENSES.md).

## Known limits

Channel 2 (Bash, MCP) is not reversible: the hook blocks, it does not
pseudonymise. Four destinations out of five do not go through
`ANTHROPIC_BASE_URL` — remote MCP servers, connectors, the npm registry.

**On a workstation, D9 is not met**: the egress harness detects, it does not
prevent. The only shape where the proxy really is the sole path is a
containerised deployment (`internal` network, proxy straddling both) or one
framed by a sandbox — `docs/d9-network-isolation.md`. Plainly: the proxy
reduces the surface, it does not close it.

`docs/re-identification-analysis.md` gives the full inventory of residual risks
and accepted leaks.
