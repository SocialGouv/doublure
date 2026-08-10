# Licensing — two sides, one repository

| Path | Licence | Why |
|---|---|---|
| everything not listed below | **MIT** — [LICENSE](LICENSE) | our code: proxy, surrogate engine, vault, policy, control service, hook, extension |
| `services/anonshield/wrapper/**` | **GPL-3.0** — [LICENSE](services/anonshield/wrapper/LICENSE) | it imports AnonShield directly, so it is a derivative work |
| `services/anonshield/upstream/**` | **GPL-3.0**, upstream | a clone, gitignored — never redistributed from here |

## Why the mix is lawful

The GPL side is a **separate process** reached over HTTP (`/detect`). Nothing on
the MIT side imports it, links to it, or embeds it; nothing on the GPL side
imports ours. That is decision **D7**, and it is the whole reason the two
licences can live in one repository.

The claim is not left to prose: [tests/test_gpl_boundary.py](tests/test_gpl_boundary.py)
walks both sides and fails on any import that crosses, in either direction —
including the case where a licence file is deleted.

```bash
task test        # includes the boundary test
```

**Removing the HTTP boundary is a licensing change, not a refactor.** Calling
AnonShield in-process would make the whole program a derivative work of a
GPL-3.0 library, and the MIT grant above would no longer describe what you
received.

## Third parties

- **AnonShield** — GPL-3.0, pinned at `d82f917`, detection engine.
- **tree-sitter-bash** — MIT, the grammar the hook splits commands with.
- Runtime dependencies are declared in [pyproject.toml](pyproject.toml),
  [go/go.mod](go/go.mod) and [devbox.json](devbox.json).

`anthropic_walker.py` sits at the root and is covered by the MIT licence like
the rest of our code. It is documented in [CLAUDE.md](CLAUDE.md) as *supplied*
because it arrived complete rather than being grown here; four defects have
since been fixed in it, each with the test that proved them.
