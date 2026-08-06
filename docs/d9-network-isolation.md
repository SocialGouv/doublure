# D9 — the proxy as the only network path

> "A control that can be bypassed is not a control." (plan §2, decision D9)

The proxy (channel 1) and the `PreToolUse` hook (channel 2) protect the
NORMAL path. Neither of them prevents a determined process from opening a
direct socket. D9 therefore requires a constraint that the agent cannot lift
on its own.

**jo's arbitration (2026-08-02): no setup on the workstation.** D9 is dealt
with at the DEPLOYMENT level — containerized environment, and/or integration
into a larger system that already has a sandbox. This document describes the
constraint to satisfy, not a procedure to run locally.

## What escapes the proxy, measured

`tests/datadog_probe.sh`, synthetic session of 2026-08-02, 34 flows:

| Destination | Flows | Goes through `ANTHROPIC_BASE_URL`? |
|---|---|---|
| `mcp-proxy.anthropic.com` | 12 | **no** — claude.ai connectors |
| `mcp.context7.com` | 11 | **no** — remote MCP server |
| `api.anthropic.com` | 5 | yes — this is channel 1 |
| `registry.npmjs.org` | 4 | **no** — installation of MCP servers |
| `api.githubcopilot.com` | 2 | **no** — MCP server of the github plugin |

**Four destinations out of five escape the proxy.** None carries the model
conversation, but all carry requests formulated by the agent — so potentially
internal identifiers in an MCP request.

## Why an IP rule cannot work

```
api.anthropic.com        → 160.79.104.10
mcp-proxy.anthropic.com  → 160.79.104.10
```

**Same address.** A network firewall does not see hostnames: it is therefore
impossible to authorize the model API while blocking the connectors by an IP
rule. Any policy claiming to separate the two at this level is false.

Two consequences:

1. **claude.ai connectors are disabled on the client side**, in the
   connector settings — not at the network. It is free, reversible, and
   removes 12 flows out of 34.
2. The useful network constraint is not "block such destination" but
   **"the agent has no outbound path, except the proxy"**. Phrased this way,
   it depends neither on IPs (which change), nor on DNS, nor on SNI.

## The target form: an absence of route, not a rule

In a containerized environment, D9 is not expressed by a filtering rule to
maintain but by a **topology**: the agent lives on a network with no route
to the outside; the proxy is the only one to have a foot on both sides.

```yaml
# docker compose — the canonical form
services:
  agent:                     # Claude Code
    networks: [interne]      # no outbound route
    environment:
      ANTHROPIC_BASE_URL: http://proxy:8090
  proxy:
    networks: [interne, externe]
    depends_on: [detecteur]
  detecteur:                 # AnonShield, GPL side
    networks: [interne]      # never needs to go out

networks:
  interne:
    internal: true           # ← this is the WHOLE policy
  externe: {}
```

It is strictly stronger than a `drop` rule: there is nothing to bypass, since
there is no route. The "same IP" problem disappears by itself — the agent
reaches neither `api.anthropic.com` nor `mcp-proxy.anthropic.com`, and the
proxy only relays what it knows how to pseudonymize.

Points of attention for this form:

- **DNS**: on an `internal` network, the agent no longer resolves public
  names. That is consistent (it has nothing to reach publicly) but some
  tools fail noisily instead of cleanly. To check case by case.
- **Remote MCP servers and `npm install`** stop working from the agent.
  That is the intended effect; if any need to be kept, they go through the
  external network via an explicit relay, which makes them visible and
  arbitrable instead of implicit.
- The **vault** must remain outside the agent's container (volume mounted
  on the proxy side only): this is what finally closes the "vault local,
  same user" gap from answer §3.5.

### Kubernetes

Same principle: `NetworkPolicy` for egress on the agent pod, only allowing
the proxy service; the proxy carries its own egress policy toward
`api.anthropic.com`. Identity separation (distinct ServiceAccount for the
proxy) gives vault isolation as a side effect.

### Integration into a system with a sandbox

If the host already has a sandbox mechanism with egress control, D9 is
reduced to a one-line policy: **declare the proxy as the sole authorized
destination** for the agent process. That is the simplest case, and the
most likely in practice.

## What remains true in the meantime

The egress harness (Phase 0) is the non-regression safeguard: it inventories
what goes out and **fails** on any unjustified destination. It detects, it
does not prevent.

That is the difference between a control and an alarm — and that is why **D9
is not held as long as the deployment is not containerized or framed by a
sandbox**. To be stated as such in the risk analysis: the proxy reduces the
surface, it does not close it.
