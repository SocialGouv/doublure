# Adversarial record

Twenty-four rounds of adversarial review, most of them run by independent agents
instructed to **break** the code rather than approve it. The full log lives in
`CLAUDE.md` at the repository root, defect by defect — 132 defects counted round
by round, plus the earlier passes. This page keeps what generalises.

## The uncomfortable headline

**Real sessions find what rounds of adversarial review do not.** A 400 on an API
field nobody had modelled, a repository name leaving in the clear, path segments
bypassing the vault, an IBAN never detected and then torn apart by a false
credit-card match — none were found by an agent.

It got sharper the day the loop stopped. In one afternoon, real sessions
returned four defects, **two of which twenty-four rounds had missed**: a postal
address whose city was drawn from a lexicon of first names, and two colleagues
with no connection given the same surname — a family the substitution had
invented. And the model found the first one itself, reading its own surrogate,
because the announcement tells it the layer exists and asks it to report rather
than work around.

Reviews find what you thought to look for. Use decides. After any change to a
generator, run a session and **read the reasoning as well as the answer**.

## When to stop

The loop stopped at round 24, and the criterion was not "no more findings" —
that never arrives. It stopped when its findings became defects in code it had
itself written hours earlier, while the older surfaces came back clean. That is
not convergence, it is the signal to change lever.

## The patterns that repeat

### The twin

One branch hardened, its twin left open. The same fix applied to `host:port`
and not to `[ipv6]:port`; then to `[ipv6]:port` and not to `[ipv6]<anything>`.
The comment above the code said "fixing only one of the two branches let the
identifier out" — and it was rewritten for one form out of two.

Looking for the twin is part of the fix, not part of the review.

### The overflowing exemption

An exemption written for a legitimate case that quietly covers an illegitimate
one. `${!arr[@]}` yields an array's indices and is harmless; `${!PREFIX@}`,
without brackets, **enumerates the names of variables** starting with a prefix —
that is, the list of secrets in the environment. Normalisation had made the two
forms identical.

### Composition

Two fixes, each correct alone, that open together — and it appears in neither
diff. A `.` in a path shifted the segment rule *and* substituted to itself, so
the rebuilt path was identical to the original; the guard that returns a value
"with nothing to hide" — written to remove spurious 503s — then handed back the
whole path.

This became the dominant pattern in the later rounds.

### Position, not key name

Five times, legitimacy was inferred from a key name or a node's own claim about
itself, and five times a third party could forge it. A hostile MCP server
returning `{"type": "thinking"}` obtained opacity; a nested dict carrying
`role: assistant` obtained it too.

Legitimacy is **sown at the root and propagated**. It is never re-derived from
a node in isolation.

### A refusal for the wrong reason is not a refusal

An end-to-end test refused a request, so the control looked effective. It was
refusing on the grounds of "network egress", and a different invocation of the
same thing — a Unix socket flag, where the URL is decorative — sailed through.

Check **why** a test passes, not only that it passes.

### Documenting a protection that does not exist

A module was defined, tested, documented — and imported by nobody. Worse, a
comment elsewhere justified opening a list of common words on the grounds that
this module "primes". It primed nothing.

Before invoking a counterweight, `grep` for who calls it. And a test that mounts
a class in isolation proves the class works, never that the system uses it.

## The two features shipped and withdrawn

Both declared common words (`code`, `run`, `error`, `low`, `high`) public to cut
arbitration noise. Both leaked.

1. Public outright: a machine actually named `code` came out verbatim.
2. Public **only under the types** `FILE_PATH` and `ORGANIZATION`: measured,
   `reach code at port 8080` yields `FILE_PATH 'code'` — and it is a host;
   `High Fidelity Corp` yields `ORGANIZATION 'High'` — the NER splits a company
   name into tokens.

**A guard built on a classifier's output inherits its errors, and fails exactly
on the ambiguous cases it was written for.** The typed-scope mechanism survived
— it is sound for an entry whose type is stable — but that list could not use
it.

## What the loop cost, honestly

Several rounds fixed defects introduced by the previous round's fixes. One
round produced five bypasses, all from its predecessor, and the cause was a
single repeated mistake: modelling a bash mechanism as a single value where
bash produces several, or chooses between branches.

The loop was stopped by decision, not by convergence: at some point the right
move was to replace the heuristics with a grammar, which retired the whole
class.
