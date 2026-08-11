# Surrogates

## The invariant

> A surrogate must be indistinguishable **in nature** from what it replaces,
> and must never designate a **real-world entity**.

Everything on this page follows from those two clauses. They were written after
three defects that looked unrelated turned out to be the same one: a `/24` that
came out as a word, a documentation range that kept its "private" flag when it
stands for a routable address, and an IPv6 generator that returned a local
address whatever the input.

The test that pins it replays all three; removing any fix makes it fail.

## What is preserved, on purpose

Five attributes survive substitution, because without them the text stops being
readable as infrastructure — and, for the last one, as a chronology:

| Preserved | So that the model can still tell |
|---|---|
| environment | production from staging |
| `/24` co-membership | two machines on the same subnet |
| human vs service account | a person from a robot |
| internal vs external | your network from the internet |
| the interval between two dates | how long an incident actually lasted |

These are **accepted leaks**, listed in the
[re-identification analysis](re-identification-analysis.md). They are the price
of a usable agent, and they are stated rather than discovered.

## Real examples

Produced by the engine, from synthetic inputs:

| Type | Real | Surrogate |
|---|---|---|
| `HOSTNAME` | `db-master.acme.internal` | `island-gateway.fourth-alpine.internal` |
| `HOSTNAME` | `srv-billing-prod-01.acme.internal` | `registry-atlas-01-prod.fourth-alpine.internal` |
| `IP_ADDRESS` | `10.1.2.0/24` | `10.135.1.0/24` |
| `IP_ADDRESS` | `192.168.4.17` | `172.28.131.227` |
| `IP_ADDRESS` | `51.75.28.4` | `198.19.180.33` |
| `EMAIL_ADDRESS` | `alice.dupont@acme.corp` | `winter-peyton.ollie@coho-margie.corp` |
| `URL` | `https://github.com/acme-corp/billing-api` | `https://github.com/humongous-school/prairie-lagoon-api` |
| `URL` | `https://registry.acme.internal/payments/api?tenant=acme-nda` | `https://yew-heather.fourth-alpine.internal/ridge-thicket/upland-compass?tenant=willow-summit` |
| `FILE_PATH` | `/home/alice/acme-nda/notes.md` | `/home/knoll-billing/kestrel-quarry/notes.md` |
| `PHONE_NUMBER` | `+33 6 12 34 56 78` | `+33 6 39 98 10 41` |
| `IBAN_CODE` | `FR76 3000 6000 0112 3456 7890 189` | `FR59 0000 0309 1434 4904 2525 063` |
| `HASH` | `sha256:9f2b1c4e…` | `sha256:ec7a28e3…` |
| `PERSON` | `Thibault Escourrou` | `Emery-wren Corey` |
| `DATE` | `12 mars 2019` | `24 octobre 2019` |
| `DATE` | `2026-02-03T14:32:00Z` | `2026-09-17T14:32:00Z` |
| `ADDRESS` | `14 rue des Grands-Augustins, 75006 Paris` | `76 rue des Darcy, 19449 Zion` |

Read them closely:

- both internal hosts landed in the **same** fictional zone, because they
  shared a real one;
- the private address stayed private; the **public** one became `198.19.x` —
  RFC 2544, reserved for benchmarking, so it can never be someone's machine;
- the URL kept its shape: scheme, path depth, query parameter name. Only what
  identifies moved;
- `github.com` survived while the org and repository did not — the model still
  needs to know it is talking about GitHub;
- the date moved by a constant, so `14:32:00` is untouched and two dates stay
  exactly as far apart as they were — an incident still reads as a sequence;
- the address kept `rue` and `des`, which identify nobody, and lost its
  postcode: keeping the code keeps the LOCALITY, and locality is what a
  re-identification joins on;
- the IBAN is **checksum-valid** (ISO 13616 mod 97) with the bank identifier
  neutralised, so a validator accepts it and it names no bank;
- the phone number sits in the range regulators reserve for fiction (`06 39 98`
  for ARCEP, `555-01xx` for the NANP, `07700 900xxx` for Ofcom).

## Where fictional values come from

| Kind | Space drawn from | Why |
|---|---|---|
| private IPv4 | RFC 1918 | private stays private |
| public IPv4 | RFC 2544 `198.18.0.0/15`, class E | reserved: provably nobody's |
| IPv6 | RFC 3849 `2001:db8::/32`, `fc00::/7` | documentation and unique-local |
| phone | regulator fiction ranges | never rings |
| IBAN / card | mod-97 and Luhn valid, issuer neutralised | passes validation, names no institution |
| hostnames | composed fictional words | plausible, and no dictionary word from the input |

## Determinism and injectivity

The same real value yields the same surrogate for the whole scope — by default
the **project**. Change the scope and you change the mapping; that is the knob
for sharing a vault between sessions or isolating a tenant.

Two real values never share a surrogate (D6), guaranteed by uniqueness in the
store rather than by hoping the generator does not collide.

!!! note "A documented residual"

    For surrogates that collide on the draw, allocation depends on insertion
    order — about 4 % of cases, down from 40 % once two words are composed on
    the first attempt. It has no practical effect (a project has one vault,
    created once); it matters if you ever rebuild a vault and expect the same
    output. A test bounds it.

## What never gets a surrogate

**Secrets.** A token, a password, a private key: replaced by a reference, and
never restored (D4). Restoring one would hand a live credential back to a
command the model just wrote.

**Values the allowlist declares public**, and only those — see
[Detection and lists](detection.md).
