# Start

## Requirements

| Piece | Why it is separate |
|---|---|
| [devbox](https://www.jetify.com/devbox) | pinned toolchain: uv, go, node, task, curl, jq |
| An NVIDIA GPU + CUDA build of torch | the detector is a transformer model; on CPU it misses the latency budget by roughly 6× |
| `claude` CLI | the client the proxy stands in front of |

Python belongs to `uv`, not to devbox: with both declared they fought over the
same `.venv` on every shell entry. The detector lives outside devbox too, in
its own virtualenv, because it depends on the local driver.

## Install

```bash
devbox install          # pinned toolchain
task                    # lists everything that can be run
```

`Taskfile.yml` is the single place where commands live. If an invocation is in
this page and in a script, one of them is already wrong — so this page points
at tasks rather than repeating them.

## Run

Three processes, in this order:

=== "1. Detector"

    ```bash
    task detector       # :9000 — leave it running
    ```

    First start downloads the model and warms it (~12 s from a warm HF cache).
    `curl -s http://127.0.0.1:9000/healthz` reports `loaded_at` — check it
    after changing `config/`, because **the detector does not reload the
    lists**.

=== "2. Proxy"

    ```bash
    task proxy          # :8090
    ```

    It opens the vault, derives the surrogate keys from the master secret, and
    refuses to serve if the detector is unreachable (fail-closed, D5).

=== "3. Session"

    ```bash
    task session        # a Claude Code session pointed at the proxy
    ```

    This sets `ANTHROPIC_BASE_URL`. Nothing else about your Claude Code
    configuration changes.

## Verify

```bash
task test               # unit suites, Python and Go
task test:egress        # egress harness
task proofs             # every end-to-end proof (needs the detector running)
```

`task proofs` starts real processes and, for two of them, a **real Claude Code
session**. That matters: three defects in this codebase were only ever found by
those proofs, never by the unit suites — a schema made invalid, a
`cache_control` value the API rejects, and an assignment the hook wrongly
refused.

## Where the state lives

The vault, the master secret and the policy files live in a per-project state
directory **outside the repository** — a repository is shared, cloned and
wiped, and the vault is none of those things.

!!! danger "Back up both halves"

    The vault is encrypted at rest with a key derived from the master secret.
    Losing either one makes every surrogate already sent **permanently
    unrestorable**. They currently live in the same directory, so one wrong
    move takes both.

## Configuration

| Variable | Default | Role |
|---|---|---|
| `ANONPROXY_SCOPE` | `project:<folder>` | determinism scope (`session:`, `tenant:`, `global`) |
| `ANONPROXY_DETECT_URL` | `http://127.0.0.1:9000` | detection service |
| `ANONPROXY_MODE` | `auto` | `auto`, `consciencieux`, `ferme` — see [Policy](policy.md) |
| `ANONPROXY_REGEX_THRESHOLD` | `8000` | above this many characters, regex-only detection |
| `ANON_DEVICE` | `auto` | `cuda` or `cpu`; `cuda` fails rather than degrade silently |
| `ANON_ALLOWLIST_FILE` | `config/allowlist.txt` | read by **both** sides of the GPL boundary |
| `ANON_INVENTORY_FILE` | `config/inventory.txt` | "what is ours" — keep the real one out of the tree |
| `ANON_CUSTOM_PATTERNS_FILE` | `config/custom_patterns.json` | your naming conventions |

The environment always wins over a mode or a stored setting: it is the
troubleshooting lever, and a lever you cannot reach is not one.
