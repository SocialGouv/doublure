# Licensing

| Path | Licence |
|---|---|
| everything not listed below | **MIT** |
| `services/anonshield/wrapper/**` | **GPL-3.0** — it imports AnonShield directly |
| `services/anonshield/upstream/**` | **GPL-3.0**, upstream, gitignored — never redistributed from here |

## Why the mix is lawful

The GPL side is a **separate process** reached over HTTP (`/detect`). Nothing on
the MIT side imports it, links to it or embeds it; nothing on the GPL side
imports ours. That is decision D7, and it is the whole reason two licences can
live in one repository.

The claim is not left to prose: `tests/test_gpl_boundary.py` walks both sides
and fails on any import that crosses, in either direction — including the case
where a licence file is deleted.

```bash
task test        # includes the boundary test
```

!!! danger "Removing the HTTP boundary is a licensing change, not a refactor"

    Calling AnonShield in-process would make the whole program a derivative
    work of a GPL-3.0 library, and the MIT grant would no longer describe what
    you received.

## Third parties

- **AnonShield** — GPL-3.0, pinned, the detection engine.
- **tree-sitter-bash** — MIT, the grammar the hook splits commands with.
- Runtime dependencies are declared in `pyproject.toml`, `go/go.mod` and
  `devbox.json`.

## Note on the name

The project used to be named after AnonShield, which it merely calls over HTTP.
That claimed someone else's work and blurred the boundary this page is about.
It is now **doublure** — the stand-in who takes the hits in the actor's place.
