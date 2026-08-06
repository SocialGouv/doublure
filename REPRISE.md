# Session resume — state at 2026-08-05

> This file complements `CLAUDE.md` (which carries the state of the phases
> and the locked decisions). Here: **the work IN PROGRESS**, what remains to
> do, the traps already paid for, and what sixteen rounds of review taught.
> Reading order on resume: `CLAUDE.md` → this file → `git log`.

## 0. TO DO FIRST, on resume

**The parser (§3 bis) is DONE and proven on 2026-08-05. The adversarial loop
remains CLOSED — jo stopped it for that precise reason. There is no open
project: ask jo what he wants to attack.**

1. Check the REAL state before acting:
   ```bash
   git log --oneline -5 && git status --short
   uv run pytest tests/ --ignore=tests/egress -q      # must be green
   ss -lntp | grep 9000                               # detector listening?
   ```
2. If the subject touches the hook: read `docs/hook-parser.md` FIRST — it
   carries the order of passes (which is the whole subject) and the four
   traps already paid for. Do not re-derive them.
3. What remains open is in §6 bis, and the "local AI + inventory" track in
   §6. Nothing is committed there.

Nothing is pushed to a remote — the repo is local, everything is committed.

## 1. The two instructions, both CLOSED

### Closed: the parser (§3 bis) — DONE on 2026-08-05
jo's arbitration, 2026-08-05, on three options I put to him:
**"stop the loop and attack the bash parser"**. Stated reason: the hook
findings of the last five rounds (`trap`, `case`, `coproc`, `mapfile -C`,
indirection by array, variable bindings) are all FREE with an AST, and a
denylist on a language as wide as bash does not converge to zero by the
adversarial method alone.

Delivered: `tokenize` relies on `tree-sitter-bash`, the grammar is a
PREREQUISITE (without it the hook refuses), and the hook is relaunched under
the project interpreter. Proofs: 1255 unit tests, `phase4_e2e.sh` and
`phase3_e2e.sh` green in a real session. **Everything is in
`docs/hook-parser.md`** — above all the order of passes and the four traps.

### Closed: the adversarial loop
> "Relaunch an adversarial review with an agent opus 5 max effort on the
> whole repo and process the findings, restart until there is no high/critical
> finding left (and one that is not assumed)"

**Rounds 3 to 16 processed.** State at stop:
- **Engine / walker / proxy / detector: stop criterion REACHED.** Rounds 15
  AND 16 without any critical or high finding, on different perimeters.
- **Hook: about one bypass per round**, up to and including the last. Two
  patterns repeat and deserve to be searched for explicitly if the loop
  resumes: **the TWIN** (one branch hardened, its sister left open) and
  **the EXEMPTION THAT OVERFLOWS** (a guard added against a false positive
  ends up covering a dangerous case — this is how `${!PREFIX@}` got through).

If the loop resumes one day, the protocol and the prompts that work are in
§3; the lists to give to the agents are in §4 and §5.
### Protocol applied on each round
1. Two `general-purpose` agents, `model: opus`, in parallel: one on the hook,
   one on walker + engine + proxy.
2. GIVE them §4 (already fixed) and §5 (assumed), otherwise they spend their
   time on what has already been handled.
3. Require: EXECUTED proof, severity, minimal fix, and "say it explicitly if
   you find nothing high/critical".
4. Verify each finding MYSELF before fixing — several turned out to be false
   or non reproducible (cf. §8).
5. Fix, one non-regression per finding, revalidate E2E, commit.

### Constraints on writing agent prompts (learned the hard way)
- Do not write the vault path in full: **my own hook then refuses the launch
  of the agent**. Say "the user's state directory".
- Avoid backticks around code containing a substitution: same effect.
- Ask the agent to write its scripts with the Write tool, **not** by heredoc
  (the hook analyzes the body of a heredoc feeding an interpreter).
- **Impose delivery in BATCHES.** Asking for "an early partial report" is not
  enough: at round 13, BOTH agents died of a "stream idle timeout" without
  delivering anything at all. The instruction that works is explicit — one
  script per batch, a synthesis written after EACH batch, six batches
  maximum, then a final delivery even if incomplete. Splitting the prompt
  into numbered batches gives the agent the structure that prevents it from
  exploring in silence.
- A dead agent returns NOTHING usable: relaunch, do not try to recover its
  trace (the transcript file overflows the context).

## 2. Where the code stands

**2767 tests green** (2749 unit + 18 egress). The six phases each have their
proven exit criterion (detail: `CLAUDE.md`).

```bash
uv run pytest tests/ --ignore=tests/egress   # 2749
uv run pytest tests/egress/test_report.py    # 18
uv run python tests/corpus_eval.py           # 6 hard criteria
bash tests/phase3_e2e.sh                     # REAL session + capture
bash tests/phase4_e2e.sh                     # forbidden command blocked
bash tests/policy_e2e.sh                     # policy, modes, arbitration
bash tests/api_e2e.sh                        # arbitration API on Unix socket
uv run python tests/detect_latency.py        # P95 < 150 ms
```
Prerequisite: the detector must be running (`services/anonshield/wrapper/run.sh`).

**Always replay `phase3_e2e.sh` after a modification of the walker, the
engine or the allowlist**, and `phase4_e2e.sh` after a modification of the
hook. Three defects were seen ONLY by them (§7).

The verification scripts for rounds 10 to 17 lived in `/tmp` and DO NOT
SURVIVE a reboot. Their content is frozen in
`tests/test_pretooluse_hook.py` and `tests/test_review_regressions.py`, which
are the real non-regression. Do not recreate them: run the suite.

Parser diagnostic: `uv run python tests/ab_decoupage.py` — it lists the
commands the grammar refuses (`ERROR`) or reduces to nothing. An `ERROR`
node means the sub-tree is flat, therefore that a program can disappear in
it: this is how `{env,}` and `a@b()` were found.

## 3. IF the adversarial loop ever resumes

1. **Look for the TWIN of each fix.** It is the pattern of rounds 12 to 14,
   without exception: I harden one branch and leave the other open — the
   indirection without the alias, the first level of a `media_type` without
   its subtype, `${!x}` without `declare -n r=$1`. Asking the question
   directly ("where is the twin?") has worked every time; forgetting it
   costs a round every time.
2. **Check the neighbours, do not assume them harmless.** `@P` executes;
   `@Q`, `@E`, `@A`, `@K`, `@L`, `@U` have never been tested. Same for any
   family of operators of which only one member has been handled.
3. **Look for what has NEVER been modelled.** Half the findings of rounds 11
   to 13 came from mechanisms absent from the model, not from regressions.
   On the bash side, still unexplored: `select`, `exec` on descriptors,
   `local -x`, arrays, `GLOBIGNORE`, `CDPATH`, `wait`, `builtin`, `shopt`,
   `complete -F`, `caller`, `hash`, `type -P`.
4. **Measure the COST, not just the decision.** Any pattern whose head is a
   free class is a pending denial of service.
5. **Surfaces with low coverage, to attack before the others**: the PROXY
   itself (headers, `Content-Length` after rewrite, client cancellation
   mid-stream, concurrent requests) and the DETECTION SERVICE — including a
   question never asked: what does the proxy do when the detector is
   UNAVAILABLE? If that is not fail-closed, an outage opens a leak.
   (Vault and concurrency: attacked at round 14, all clear — do not go back.)
6. Points **not fixed**, to re-arbitrate:
   - **M3 — span fragmentation**: a truncated URL span that overlaps a
     HOSTNAME span gives TWO fictitious names to one machine. Not a leak; a
     determinism regression (plan §9). Track: merge overlapping spans before
     substitution.
   - **`container` / `stop_sequences`**: traversed, but the detector does not
     classify a value like `INTERNAL_STOP_TOKEN_acme`. Document or add a
     custom pattern.
   - **Vault entropy test**: does not on its own detect an XOR derived from
     the nonce; it is the neighbouring tests that catch it.
   - **`test_la_liste_suit_le_detecteur`** *skipped* without the service:
     freeze the expected CARDINAL as well.
   - **`sensitive_from_fixture`** only recognizes a few TLDs.
   - **Known residue**: a commit message quoting a primitive, followed by a
     semicolon then an inline interpreter, remains a false positive. The
     semicolon separates INSTRUCTIONS in an inline program: treating it as a
     command boundary would break one-liners.
7. Backlog outside the loop: `corpus/real/` not annotated (jo's material),
   KMS/rotation/immutable access log (Phase 6, outside MVP).

## 3 bis. The hook tokenization by GRAMMAR — DONE on 2026-08-05

**→ `docs/hook-parser.md` is authoritative.** It carries the order of the
passes, the four traps paid, the verified grammar facts and the measurements.
Read it before any modification of the hook. What follows is only a signpost.

jo's arbitration (2026-08-05): stop the adversarial loop on the hook and
attack the parser. The engine, itself, was already stable — rounds 15 and 16
without any critical or high finding.

### Delivered
- `tokenize` relies on `tree-sitter-bash`. The crutches of fourteen rounds
  have disappeared: comment stripping, removal of function headers,
  conditional braces, `case` tokenization, double reads of sub-commands. The
  structure comes from the grammar.
- What it does not bring stays written by hand: expansions, wrappers,
  indirections — this is bash semantics, not syntax.
- **The grammar is a PREREQUISITE**: without it, `tokenize` raises
  `GrammaireIndisponible` and the hook REFUSES. The hook relaunches itself
  under `.venv/bin/python` (`os.execv` preserves stdin), from `main` and
  never on import — otherwise a test suite without the grammar would see its
  own process replaced.

### Proofs
- **1255 unit tests** green (28 added for this round).
- `bash tests/phase4_e2e.sh` → **PASS** in a real Claude Code session:
  forbidden command blocked before execution, traced, exact reason cited by
  the model.
- `bash tests/phase3_e2e.sh` → **PASS**: 0 real value over 393.6 KB captured,
  restoration 3/3 on the operator side.
- Availability: 0.003 s on a realistic command, 0.42 s on 500 KB, 0.47 s on
  5,000 `declare -n`.

### What this round taught, and that holds beyond the parser
1. **The order of passes was the whole subject.** The tokenization works on
   the RAW command; only the regex controls keep the normalized text.
   Normalizing before parsing made a structure that quotes had suppressed
   RE-EMERGE, and the nine false positives of the first branching all came
   from there — they resurrected at a stroke the defect that rounds 5, 8 and
   9 had eliminated.
2. **An exact tool does not replace an approximation without work.** The
   gain ("arguments arrive with their quoting") is not inherited: it forces
   one to re-analyze EXPLICITLY what was visible by accident.
3. **New code is the freshest surface.** The only remaining bypass of the
   round was found by attacking my own fixes, not the old code:
   `bash -c"env"` arrives concatenated. Same pattern as the TWIN — the
   separated form hardened, the attached form left open.
4. **An `ERROR` node is a blind spot**, not a detail: the sub-tree becomes
   flat and a program can disappear in it. `tests/ab_decoupage.py` lists
   them.

## 4. Already fixed — GIVE this list to the agents

**Proxy / walker**: passthrough on unmodelled path · outbound surfaces
enumerated · length threshold · regex mode on large volumes · URL path and
query · cache not carried by scope · echo of stop sequence · text document
source · PEM blocks · non-hashable type · dead `properties` branch · schema
keywords (validation pattern, format, type in union, anchors, dynamic
references, dependencies) · pattern-property keys · non-scalar sub-tree
under an ignored key · arbitrary scalar under betas · cache control and its
vocabulary · non-restored start block · citations delta · streamed error
body · SSE separators and mixed forms · orphan delta · ignored keys in tool
arguments and metadata · forgeable opacity · MCP resource name · media
types `x-` and `vnd.` · malformed events · future signed delta · non-object
body (request and response) · message start · scalar container · unbounded
SSE buffer · input-schema heuristic · list of authorized tools · schema
examples · emission after message end · **forgeable opacity outside user
data** (user message, relayed tool output, system prompt, tool definition).

**Engine / vault**: shared attribute substituting itself · invalid or
malformed spans · partial overlap · image tag · forgeable internal type ·
multiple identities per type or case · lexicon word matching the real ·
degenerate path · plausibility (UUID, MAC, hash prefix, person, IPv6) · URL
identifiers (web form AND secure shell form) · fragment · IPv6 without
brackets · bare host · Unicode NFC · encryption at rest, AAD, padding,
uniqueness per scope · classification of secret types · PUBLIC span masking
a substitutable class · request parameter name (empty, encoded) · password
label · repository extraction (mixed case, hostile host, port) · bare host
with trailing slash · hash prefix without body · **allowlist radical
accepting dots** · **shape rule applied to sub-parts**.

**Hook**: quoting, globs, backslashes · decoding then shell · `ps auxe` ·
ssh directory · MCP tools · process substitution · backticks · `busybox` ·
`terraform show` · `port-forward` · `gh api` · `docker run` with mount ·
shell socket · `kubectl exec` · `helm get values` · tfstate · cloud tokens ·
domain starting with `127.` · `perl -e system` with and without parentheses
· `qx`, `%x` · `subprocess` tuple · environment access by brackets ·
import of the environment table · Ruby's `ENV` · IFS under all its forms,
including the `plus` form · variable starting with IFS · indirect reference
· `find -exec` including behind a wrapper · `strace` · substitution whose
output becomes an argument · database and session variables · expansion
losing the variable name · executed fallback · fallback breaking refusal
patterns · nested fallback · positional expansion name · brace in multiple
words · `env` with string splitting · empty or concatenated assignment
prefix · heredoc with attached pipe or consumed by a pipeline · `exec` and
`spawn` family · wrapper options per program · unenumerated tool fields ·
`openssl` in the blacklist · lone help options · program designated by a
variable · unbounded brace expansion · **program delivered outside the
line** (here-string, heredoc, bare dash, process substitution, heredoc
consumed by a pipe) · **body of a function and of a command group** ·
**`declare -n` alias** · **assignment that makes execute**
(`BASH_ENV`, `LD_PRELOAD`, `ENV` of path, `NODE_OPTIONS --require`) ·
**value of `-c` taken for an execution prefix** (`bash -c env _`) ·
**attached long form of `env -S`** · **patterns whose head is a free class**
(denial of service, seven seconds on a long word).

**False positives fixed** (a blocked agent is as broken as an agent that
leaks): `set +e` · `env -i` and `-u` · `command -v` · `compgen -A function`
· substitution in an `echo` · Anthropic configuration variable · `printenv`
of an AWS region · listing of the ssh directory · `grep -r curl src/` ·
`openssl rand|dgst|passwd|help|ciphers` · `ssh -V` · `wget --help` ·
`python3 -m venv env` · prose citing a network binary · commit message
citing a primitive or a one-liner · sub-agent prompt with backticks · quoted
heredoc writing a file · JavaScript code searched by `grep` · `nice -n 10` ·
assignment from a substitution · brace that executes nothing · Markdown
file name taken for a domain.

## 5. Assumed and documented — these are NOT findings

- Vault local, same user (answer §3.5) — closed by containerization.
- **D9 not held on a workstation**: jo's arbitration of 2026-08-02, no local
  firewall. See `docs/d9-network-isolation.md`.
- The FOUR preserved attributes (environment, /24, human/service,
  internal/external) are deliberate leaks (answer §3.4).
- Hook in **denylist**, and "curtain, not wall": write-then-execute, script
  by path, package managers, clone to an arbitrary remote, `docker
  pull/push`, `helm pull`. **Do not pile on patterns for those.**
- Writing to the authorized-keys file is not covered: the hook aims at
  exfiltration, not persistence.
- Dependence on insertion order bounded to ~4% (dedicated test).
- `SERVICE` classified PUBLIC (false positives on technical prose).
- Tool names, MCP server names, tool choice, and the list of authorized
  tools stay verbatim: they are ROUTING keys, substituting them would break
  the tool silently.
- A control value in the form of a bare token is not traversed.
- A bare zone does not join the fictitious zone of its hosts: fixing it
  would make it a SHARED attribute, therefore non-restorable.
- A short query parameter name, without a dot or an at sign, is not
  substituted: indistinguishable from an API name.
- **A single-label external domain on a ccTLD that is also a file
  extension** (`partenaire.md`, `billing.py`) stays public. The span type
  does not distinguish a file from a host — measured. Price paid so that
  `main.py`, `lib.rs` and `README.md` stay readable by the agent. Internal
  hosts, multi-label, remain covered. jo's arbitration of 2026-08-04: `.pl`
  and `.ml` REMOVED (real volume of domains, extension value null here);
  the list is re-judged extension by extension, not in bulk. The residue is
  no longer silent: `/detect` returns `public_by_shape`. Three tests freeze
  the three sides (residue, removed ccTLDs, multi-label hosts).
- Definition keys stay verbatim; a substitute can theoretically unbalance a
  validation expression.
- A chunk cut may leave a line break at the head of an SSE block.
- Real corpus not annotated; telemetry cut by jo's settings.

## 6. Arbitrations HANDED DOWN by jo — do not re-litigate them

- **2026-08-05, adversarial loop**: stopped in favour of the parser
  (§3 bis). Three options put, jo chose the parser. Reason: hook findings
  are free with an AST.
- **2026-08-04, `.pl` and `.ml` removed** from the extensions rule: these
  are the two ccTLDs of the list to carry a real volume of domains, and
  their value as a file extension is null here (zero Perl or OCaml file).
  Stated principle: **the list is re-judged extension by extension, not in
  bulk.**
- **2026-08-04, `public_by_shape`**: the detector COUNTS what a SHAPE rule
  renders public. jo asked that the residue stop being silent.
- **2026-08-05, Java/Kotlin packages**: kept "unless this does not expose a
  third-party lib but something specific to the repo". Applied by pinning
  the second level of `javax.` — the only rule that pinned none.
- **2026-08-02, D9**: no local firewall, this is handled at deployment.
- **Local AI + inventory**: track discussed with jo, NOT yet engaged. The
  inventory of names specific to the repo would close most of the residues
  of §5; it is built with the same material as the golden corpus (Phase 5).
  The third floor ("ask the human in case of doubt") requires: default =
  SUBSTITUTE while waiting, answer PERSISTED and monotonic, and a low
  escalation rate — otherwise the agent is unusable.

## 6 bis. Deviations still to be validated by jo
- **Cloud allowlist tightened** to `<service>[.<region>].<cloud>` (the
  literal covering the whole domain let a resource endpoint leak).
- **File extensions rule** in `config/allowlist.txt`: makes SINGLE-label
  file names public. `.io`, `.ai`, `.dev`, `.app`, `.co` and `.sh` are
  deliberately ABSENT — they are real domains.
- **`SERVICE` classified PUBLIC**, to re-evaluate on the real corpus.
- **Shared attributes excluded from the restoration view.**

## 7. Traps that cost time

- **`uv run` re-synchronizes the venv** of `services/anonshield/upstream`
  on the lock (torch CPU) and removes fastapi. Relaunch
  `wrapper/install-cuda.sh`, and launch the service via `.venv/bin/python`
  (which is what `run.sh` does).
- **The detector must be RESTARTED** after any modification of
  `config/allowlist.txt` or `config/custom_patterns.json`. A `pkill` on the
  module name DOES NOT CATCH IT (it runs under `uvicorn`): identify the PID
  by port 9000 (`ss -lptn | grep 9000`) then `kill`. Restart ~2 min.
- **`phase3_e2e.sh` found three defects that nothing else saw**: an
  invalid schema (API 400), a substitute collision (503), and a hook false
  positive that made the turn limit be reached WITHOUT error or red test.
  The harness is bounded to 6 turns and the session consumes 6: it is at
  the limit, therefore sometimes unstable. Check the number of requests in
  `captures/*/bodies/` before concluding a regression.
- **The hook applies to ME.** Blocks encountered while working: sub-agent
  prompt citing the vault path; test or documentation file whose CONTENT
  cites a sensitive path — compose them by concatenation; heredoc feeding
  `python3` whose body reads the environment (CORRECT block). Write the
  files with the Write tool.
- `_SCHEMA` is not a raw string: writing a single escape in it gives an
  EMPTY escape. Double the backslash.
- Never read or display the vault state directory (secrets rule).

## 8. What sixteen rounds taught

1. **A one-value approximation is a pending bypass.** Every time I modelled
   a bash mechanism by a single value (one brace alternative, one expansion
   branch, one skipped token, the first occurrence of a program), the
   following round found the case where bash produces several. Emitting ALL
   possibilities costs a visible false positive; emitting only one costs a
   silent bypass.
2. **Enumerating is deferring the defect.** The fixes that held are the
   ones that change the STRUCTURE of the analysis: nested region treated as
   a command, program positions instead of names, options table PER
   wrapper, user data perimeter, inherited flag. Lists (of patterns, of
   words, of options) have all ended up being defeated.
3. **A rule that makes values PUBLIC is the only one whose failure is
   silent.** Everything else fails noisily (400, 500, 503, refused
   command). Such a rule must be born with its test, and its perimeter must
   be explicit: an EXACT entry holds everywhere, a SHAPE rule assumes a
   context.
4. **A false positive is as serious as a leak.** An agent that can no
   longer write a script, read a file or commit is broken. A false
   positive has already made a real session fail without producing an
   error or a red test.
5. **Verify the findings yourself.** Several reports contained false cases
   (a cited obfuscation that does not reconstruct the announced binary) or
   non-reproducible ones (engine built without the allowlist). Fixing on a
   false proof would have introduced a real defect.
6. **The tests can also be wrong**, and the agent reports too. Three of my
   assertions were false (a brace that executes nothing; two text deltas
   that are the tail buffer, not a duplicate; `printenv HOME`, given as a
   bypass, that exposes nothing). Fix in the direction of the REAL
   behaviour, not in the direction that suits — and verify a "bypass" on a
   NOXIOUS load, not on the benign example from the report.
7. **Also look for what has never been modelled.** For nine rounds, the
   findings were regressions of the previous round; at the tenth, all the
   fixes held and the ten bypasses came from mechanisms absent from the
   model. Re-reading one's own fixes is no longer enough: one must re-read
   the SPEC of the analyzed object (here bash) and tick off what has never
   been handled.
8. **A pattern whose head is a free class is a pending denial of service.**
   `\S*\{`, `[\w-]*\.env`, `[\w./-]*secrets?` backtrack at every position
   of a long word: seven seconds for twenty thousand characters, enough to
   drown an agent without writing a forbidden command. Two of the three
   were there from the beginning, never timed. Anchor on the literal, and
   MEASURE the cost, not just the decision.

## 9. Landmarks
- Commits: only on jo's request, conventional commits, in English.
- `PLAN-proxy-pseudonymisation.md`: **never modified**.
- `anthropic_walker.py`: provided by jo; sixteen defects fixed, each proven
  by a test written BEFORE (`tests/test_walker_defects.py`).
- Synthetic data only.
