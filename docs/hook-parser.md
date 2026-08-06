# The hook tokenization relies on a GRAMMAR

Done on 2026-08-05 (round 17). This document states what the grammar brings,
what it does not bring, and the four traps that each cost one iteration — so
that they are not re-discovered.

jo's arbitration, 2026-08-05: stop the adversarial loop on the hook, attack
the parser. Stated reason: hook findings are free with an AST.

## Why

Sixteen rounds of adversarial review on `hooks/pretooluse_guard.py`. The
engine stabilized (two rounds with no finding); the hook produced roughly one
bypass per round, and **each one came from a bash mechanism never modelled or
from the gap left between two neighbouring guards**: `trap`, `case`, `coproc`,
`mapfile -C`, function names with extended characters, a comment taken for a
program, indirection by an array element.

All are free with a syntax tree. A denylist that approximates the grammar of
bash does not converge to zero via the adversarial method alone.

## What the grammar brings — and what it does NOT bring

It gives the **structure**: `case`, function definitions, groups, heredocs,
comments, substitutions, concatenations. Everything that fourteen rounds of
heuristics were approximating.

It **does not evaluate**. `e${IFS//?/}nv` remains a single node, `${!m[k1]}`
remains an expansion. The expansion, wrapper and indirection logic remains
NECESSARY — it is bash semantics, not syntax. It lives in `_reduire_token`
(word by word) and in `_reecritures_semantiques`.

The real gain: arguments arrive **with their quoting intact**. All the
difficulty of "the quoting has already been stripped, we do not know where the
sub-command ends" — which forced double reads for `trap`, `mapfile -C` and
`bash -c` — disappears.

## The order of the passes, which is the whole subject

```
RAW command
  │
  ├─► normalize()          quoting/globs destroyed  ──► REGEX checks
  │                                                    (vault, files,
  │                                                     DENY_COMMAND_PATTERNS,
  │                                                     sensitive variables)
  │
  └─► _NESTED_RE / _REF_SIMPLE_RE (markers)
        └─► tokenize()  =  _reecritures_semantiques  ──►  grammar
                                                            └─► _reduire_token
```

**The tokenization works on the RAW command.** Normalizing first made a
structure that quotes had suppressed RE-EMERGE: `git commit -m 'handle case in
parser(env)'` became a sub-shell executing `env` again. The nine false
positives of the first branching all came from this, and they resurrected
exactly the defect that rounds 5, 8 and 9 had eliminated.

The regex checks, however, keep the normalized text: it is there that
obfuscation (`an[o]nproxy`, `an''onproxy`) is neutralized.

## The four traps, each paid once

### 1. Brace expansion must precede the grammar
`{env,}` is not valid bash until expansion has taken place: the tree ends in
`ERROR`, and the reconstructed word (`env`) appears nowhere. Expansion is
therefore done BEFORE analysis — but only **outside quotes**
(`_expanse_hors_quotes`), otherwise a JSON body (`'{"a":1,"b":2}'`) is
expanded and the quote pairing, on which the grammar depends, is broken.

Corollary found while fixing: `${IFS,,}` is NOT an alternative, it is a case
operator. Without the `(?<!\$)` in `_ACCOLADES_RE`, `env${IFS,,}> /tmp/dump.txt`
was rewritten as `env$IFS> env$> env$>`.

### 2. The grammar refuses function names that bash accepts
`my.fn()` passes, `a@b()`, `a%b()`, `1fn()` do not: the tree ends in `ERROR`
and the BODY disappears — yet it is the body that carries the programs. Only
the NAME is replaced by a neutral identifier (`_canonise_noms_de_fonction`),
the structure becomes readable again. The name is delimited by walking back
from the parenthesis, never by a regex that would search for it to the left:
a free class at the head backtracks at every position of a long word (fifteen
seconds on twenty thousand characters, round 10).

### 3. A QUOTED argument is no longer read by accident
This is the gain, and it is what breaks if nothing is done: `bash -c 'f() {
env; }; f'` returns a `raw_string` that the grammar does not open. It must be
re-analyzed EXPLICITLY (`_sous_scripts`): the value of `-c` for a SHELL
wrapper, the argument of `trap` (minus the signal specifications), the value
of `mapfile -C` / `readarray -C`, the value of `env -S`, and the body of a
heredoc (which hangs under `heredoc_redirect`, so outside the words of the
command).

Each level goes back through `_reecritures_semantiques`: a nested script can
itself carry a `coproc`, an alias or a brace.

### 4. The grammar concatenates, like bash — the option reader too
`bash -c"env"` produces a `concatenation` node (`word` + `string`), reduced to
`-cenv`. Neither the `-c` rule nor the re-analysis saw it: **bypass
introduced by my own fix**, found by attacking the new code. Splitting it at
the tokenizer would be wrong (bash does produce ONE word, and `/usr/"bin"/env`
must remain `/usr/bin/env`): it is up to the layer that reads options to
separate `-c` from its attached value (`_OPT_C_ATTACHEE_RE`).

## Grammar facts, verified

```
export -p          → declaration_command      (NOT command)
readonly -p        → declaration_command
local -n r=X       → declaration_command
unset FOO          → unset_command
env                → command
bash <<'FIN'…      → heredoc_redirect → heredoc_start, heredoc_body, heredoc_end
bash -c 'f() {…}'  → command_name, word(-c), raw_string      (not opened)
bash -c"env"       → command_name, concatenation(word(-c), string)
coproc { ls; }     → coproc/{/ls as WORDS, then a `}` command
                     (the grammar does NOT know this form)
```

`find … -exec env \;`: the terminator arrives as an ordinary word, and the
escape that distinguished it drops on reduction — keeping it made `env` pass
for a prefix executing `;`.

## Bootstrap

Claude Code launches the hook as an executable, so under the SYSTEM python,
which does not have the grammar. `_relance_sous_interpreteur_du_projet`
replays it under `.venv/bin/python`; `os.execv` PRESERVES stdin, the event
remains readable.

The re-launch happens from `main`, **never on import**: a test suite launched
without the grammar would otherwise see its own process replaced. An
environment marker prevents the loop if the second interpreter does not have
it either.

## Invariant

The hook is **fail-closed** since `f1e00f8`. The grammar has become a
prerequisite of the analysis: without it, `tokenize` raises
`GrammaireIndisponible`, `main` writes a REFUSAL. A hook that crashes writes
no decision, and the tool executes — that is the only failure mode that opens
the channel instead of closing it. Frozen by
`test_sans_grammaire_le_hook_refuse`.

## Diagnostic tool

`uv run python tests/ab_decoupage.py` — lists the commands from the test
corpus that the grammar still refuses (`ERROR`) or reduces to nothing. An
`ERROR` node means that the sub-tree is flat, therefore that a program can
disappear in it: this is how `{env,}` and `a@b()` were found.

It first served as a differential between the heuristics and the grammar, for
the duration of the replacement — it is what showed the `declaration_command`
trap BEFORE the replacement, which would otherwise have re-opened at a stroke
the whole family of dumpers hardened in round 15.

## Measurements (2026-08-05)

| | |
|---|---|
| realistic command | 0.003 s |
| 20,000-character word | 0.016 s |
| 500 KB of text | 0.42 s |
| 100 brace groups | 0.010 s |
| 5,000 `declare -n` | 0.47 s |
| 1,000 lines | 0.08 s |
| re-launch under project interpreter | +30 ms |
| hook timeout (`.claude/settings.json`) | 10 s |
