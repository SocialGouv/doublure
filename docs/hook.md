# The hook — channel 2

A `kubectl` command has to reach the real cluster. There is nothing to
pseudonymise on this channel, so the hook does the only other thing available:
it **refuses, before execution, and says why**.

It runs as a `PreToolUse` hook and covers every tool — Bash, WebFetch, MCP
calls, file writes — not an enumerated list of the ones that looked risky.

## Wiring

The wiring lives in `hooks/settings.json` and is **not** installed in
`.claude/settings.json`, so it does not apply to sessions that work on this
repository itself. Copy it into the project you want guarded:

```bash
cp hooks/settings.json /path/to/your/project/.claude/settings.json
```

That choice is deliberate. The asset this guard protects is your real
infrastructure, and it is not present in its own source tree — while the guard
did block the work of writing its own tests, grepping its own patterns, and
reading its own refusal messages. The end-to-end proof passes the file
explicitly (`claude --settings hooks/settings.json`), so what is verified is
the same wiring you install.

## What it refuses

| Class | Examples |
|---|---|
| environment dumps | `env`, `printenv AWS_…`, `declare -p`, `readonly -p` |
| the vault and the master secret | any read of the state directory |
| credential files | private keys, cloud credentials, kubeconfigs |
| network egress to third parties | `curl`, `wget`, `/dev/tcp`, embedded HTTP in python/node/perl |
| secret extraction | `kubectl get secret`, `helm get values`, tfstate reads |

Loopback is allowed, because the agent legitimately talks to the project's own
detector — and that exemption has itself been a defect: with
`--unix-socket`, the URL is decorative and the destination is the socket, which
briefly let the agent read the arbitration API. **A refusal obtained for the
wrong reason is not a refusal.**

## Why a grammar, not keywords

Fourteen rounds of heuristics tried to answer "what does this command actually
run?" with normalisation and token scanning. Every round found new bash
mechanisms that rebuild a program name: brace expansion, `${x:-env}` fallbacks,
`${!name}` indirection, `trap`, `coproc`, `mapfile -C`, aliases, here-strings.

The parser is now built on `tree-sitter-bash`, and `case`, function definitions,
groups, heredocs, comments and concatenations come **by construction**. The
details, the traps and the measurements are in
[the command grammar](hook-parser.md).

The grammar is a prerequisite, not an optimisation: without it, tokenisation
raises and the hook **refuses**.

## False positives are a defect too

A blocked agent is as broken as an agent that leaks, and most rounds fixed as
many false positives as bypasses:

- `grep -r curl src/` — a mention is not an execution;
- `git commit -m 'fix subprocess.run for the curl backend'` — prose in a commit
  message;
- `echo $(find . -name env)`, `command -v env`, `set +e`, `env -i`;
- `D=$(ls …)` — an assignment does not execute the substitution's result;
- a sub-agent's `prompt` field, which is prose and has its own guard at
  execution time.

The rule that emerged: the gate hinges on the **program position**, never on a
word appearing somewhere in the text.

## Known false positives, accepted

Quoting the indirection syntax inside a string (`echo 'the syntax is ${!x}'`)
is refused. Anti-obfuscation normalisation removes quoting, so a quotation
becomes indistinguishable from a real expansion — and `bash -c '${!x}'` does
execute. The refusal is visible and easy to work around; the opposite would be
silent.

Writing a test that targets a sensitive path requires composing it
(`"~/." + "ssh/id_" + "rsa"`). That is consistent, and you have to know it.

## Availability is part of the threat model

A hook that takes twenty seconds per tool call drowns an agent without a single
forbidden command being written. Three separate denial-of-service defects were
found and fixed this way: catastrophic regex backtracking on patterns with a
free class at the head, an unbounded brace-expansion product, and an O(n²)
variable lookup. Current cost: **3 ms** on a realistic command, 0.42 s on
500 KB of input.

## Trace

Every decision is written to an audit log. `allow` entries are recorded by
truncated SHA-256 fingerprint — enough to reconstruct a chronology after an
incident, not enough to reconstruct the activity.
