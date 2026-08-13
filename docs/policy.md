# Policy and arbitration

Everything detected gets substituted. Values that no rule covers are not
guessed at and not blocked on — they are **recorded as questions** and the
session continues.

## Two axes, six defaults

An answer is given at one **granularity** and one **scope**, and each becomes
the default for the next answer:

| Granularity | Answers for |
|---|---|
| `valeur` | this exact value |
| `type` | every value of this entity type |
| `classe` | every type in this data class |

| Scope | Applies to |
|---|---|
| `message` | the message being processed, and nothing after it |
| `session` | this session only |
| `projet` | this project |
| `global` | everywhere |

The **narrowest and nearest wins**. A rule is never inherited upward, and a
`reveler` decision is never inherited from a default at all.

`message` is offered as a scope because that is how you think of it — the
nearest one there is — but it is deliberately **not a layer**. A scope is a rule
that survives, and a reveal that outlives what it was granted for is an
inherited reveal. Nothing is written into a scope file, so nothing survives: it
is the answer to the question being asked, and it dies with it.

The channel is cleared when a message **opens**, not when it closes. An answer
written after the message it aimed at is therefore discarded rather than applied
to the next one — a lost answer leaves the value anonymised, the reverse would
let it out. Two concurrent requests discard each other's answer, which is the
same safe direction.

## Answering

```bash
task policy -- questions     # what was anonymised without an explicit rule
task policy -- arbitrer      # answer them
task control                 # the arbitration API, for the IDE extension
```

In `arbitrer`, `m` answers **for this message only** at the granularity on
screen — the whole group if it is grouped, the single value if you expanded it.
The extension offers the same choice as a scope, and so does
`POST /decide` with `{"scope": "message"}`.

To decide on a value you have in mind rather than one the queue is showing:

```bash
task policy -- valeur projet PERSON "Claude" reveler
```

It prints the fingerprint, which is what `retirer` needs to revoke it. The
fingerprint is computed on the **canonical** form of the value, the same one the
engine looks up — computing it on the raw string would write a rule that looks
taken and never applies.

The queue is grouped **by type**, and that is what makes it usable: one real
session produced 462 pending values, which grouping turned into **14 gestures**.
Expanding a group to answer value by value is one keystroke away when a type is
too coarse.

A `--une-par-une` flag walks the queue value by value when you want that.

!!! warning "`--repondre` writes"

    It is not a preview. Answering at type or class level from the command line
    opens whole types at once, without a confirmation step. There is no
    `--simuler` yet.

## What an answer can be

- **anonymiser** — keep substituting. Free, reversible, and the error is
  visible: the agent stumbles and you see it.
- **reveler** — let the real value out from now on. Traced, never inherited,
  and it does **not** recall what has already gone.
- **neither** — tell the model how to work without the value. Often the right
  answer, and the one a queue that blocks would never let you give.

A `SECRET` is never revealable (D4). That is refused when the rule is written
*and* again when it is read, on every path including a message answer: the read
guard is the invariant, the write guard is the ergonomics, and the invariant does
not depend on it.

## Settings

Settings resolve through the **same** scope hierarchy as the rules, with the
environment always winning — it is the troubleshooting lever. A setting that
decides protection cannot be varied by a mode, or choosing a mode would amount
to opening.

| Setting | Values | Default |
|---|---|---|
| `domaines_fictifs` | `reserves` · `tld_reels` | `reserves` |
| `chemins` | `utilisateur_projet` · `utilisateur` · `complet` | `utilisateur_projet` |
| `dates` | `libre` · `cote_du_present` | `libre` |

`dates=cote_du_present` keeps a past date past and a future date future, which
is useful when absolute chronology matters. It has two prices, both stated in
[Known limits](limits.md): "past or future" becomes a preserved attribute, and
the future half expires on its own as today advances. The default preserves
intervals only, and the announcement is what keeps the model from concluding
anything from a date's position.

## The interface

A VSCode/VSCodium extension in `extension/` speaks to the Go control service
over a Unix socket, with `/events` as Server-Sent Events — so a blocked request
surfaces immediately rather than at the next poll. Three seconds of polling lag
is three seconds of an agent doing nothing.

!!! info "Control surface, never an enforcement point"

    Uninstalling the interface must open nothing. That is the design test to
    repeat at every addition, or the "ask the model nicely" anti-pattern comes
    back dressed as an IDE.

## The announcement

The system tells the model, in the system prompt, that it is reading
pseudonymised material and how to behave with it — quote identifiers whole,
ask rather than guess.

This is acknowledged prompt engineering: **it informs, it does not protect.**
It is also what surfaced two of the three defects behind the surrogate
invariant, because a model told to expect fiction reports an inventory that
contradicts itself instead of quietly working around it.
