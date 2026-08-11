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
| `session` | this session only |
| `projet` | this project |
| `global` | everywhere |

The **narrowest and nearest wins**. A rule is never inherited upward, and a
`reveler` decision is never inherited from a default at all.

## Answering

```bash
task policy -- questions     # what was anonymised without an explicit rule
task policy -- arbitrate     # answer them
task control                 # the arbitration API, for the IDE extension
```

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

A `SECRET` is never revealable (D4).

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
