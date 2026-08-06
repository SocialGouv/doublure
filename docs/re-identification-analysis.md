# Re-identification risk analysis

> Deliverable expected by the DPO (plan §9). Status: **MVP** — to be
> completed with the DPO before any operation on real data.

## 1. What the proxy guarantees

No detected identifier (host, IP, e-mail, repository, image, service account,
secret) leaves the machine in clear over channel 1. Verified by mitmproxy
capture in a real session: `tests/phase3_e2e.sh` → 0 occurrences over
427 KB outbound, and by `tests/corpus_eval.py` on the annotated corpus.

## 2. ASSUMED leaks — the four preserved attributes

jo's answer §3.4: the four attributes are kept because the model needs them
to reason correctly. Each one is an information leak, documented here for
what it is.

| Preserved attribute | What Anthropic can deduce from it | Why we accept it |
|---|---|---|
| **Environment** (`-prod`, `-staging`) | The prod/staging/dev split of the infrastructure, and therefore its relative size | Without it, the model cannot calibrate the risk of an action: it would treat prod as a sandbox |
| **/24 co-membership** | The network topology: how many subnets, how many hosts per subnet, which hosts cohabit | Network reasoning (routing, firewall, blast radius) is inoperative without it |
| **Human vs service** | The ratio of human accounts / technical accounts, so an order of magnitude for team size | A service account incident is not handled like a human account incident |
| **Internal vs external** | The perimeter boundary: what is ours, what is at a third party | Distinguishing a public dependency from an internal service is the basis of attack surface analysis |

## 3. The structural limit (plan §9)

**A perfect substitution does not make anonymous.** What identifies is no
longer the name but the **structure**:

- who commits on what, at what frequency, with whom;
- which roles, what team size, what schedules;
- the shape of the dependency graph between services.

A pseudonymized graph is re-identified as soon as auxiliary information
exists: public GitHub activity, org chart, job postings, conferences. No
improvement in tokenization corrects that.

### Real mitigation: minimization at the tool boundary

This is the effective lever, and it is NOT in the proxy:

- do not send 4,000 lines of `git log` when an aggregate answers;
- do not send the nominative list when "12 principals hold this role,
  including 3 service accounts" is enough;
- prefer `kubectl get pods -o name | wc -l` to a full dump.

**Status: not implemented in the MVP.** It would be a typed tool broker
(cf. AgentWall, plan §5 Phase 4, task 3), which aggregates before sending.
To arbitrate with jo: it is the highest-yield project for privacy once the
MVP is in service.

## 4. Other residual risks

| Risk | Status | Mitigation |
|---|---|---|
| **Vault readable by the agent** (answer §3.5: local, same user) | Assumed | PreToolUse hook (`hooks/pretooluse_guard.py`) refuses any access to the vault path and to the key; tested (`test_pretooluse_hook.py`). A dedicated Unix account would close the gap. |
| **Channel 2** (Bash, WebFetch, MCP calling the network) | Partially handled | The hook blocks direct network outputs and secret dumps. It does not pseudonymize: by construction (§7), there is no return path. Definitive answer = D9 (firewall). |
| **Remote MCP servers and connectors** do not go through `ANTHROPIC_BASE_URL` | Open | Measured: `mcp-proxy.anthropic.com` ×12, `mcp.context7.com` ×11, `registry.npmjs.org` ×4, `api.githubcopilot.com` ×2 in a single session — that is 4 destinations out of 5 outside the proxy. They do not carry the conversation, but carry requests formulated by the agent. To arbitrate: `docs/d9-network-isolation.md`. |
| **Datadog telemetry** of the Claude Code binary | Cut, content unknown | Observed at ~343 KB/session on 2026-08-01; absent on 2026-08-02 after adding `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` / `DISABLE_TELEMETRY=1` / `DISABLE_ERROR_REPORTING=1` in `~/.claude/settings.json` (`tests/datadog_probe.sh`, 34 other flows captured at the same time). The cut is therefore effective. The CONTENT of the payloads has never been inspected: to do so one must launch the session with a temporary settings file without these variables — the script's environment is not enough to neutralize them. |
| **Volume and rhythm of requests** | Not mitigated | Even pseudonymized, the temporal PROFILE of activity is visible on the provider's side (number of turns, size of contexts, working hours). |
| **MCP tool names** (`payments_api__query`) | Open | The walker's `SKIP_KEYS` preserves `name`: a tool name encoding an internal service leaks. To be handled at the MCP server level (renaming in the middle would break correspondence on return). |
| **Determinism per project** (answer §3.1) | Assumed | A substitute is stable in the project: two sessions of the same project are correlatable with each other on the provider's side. This is the price of the prompt cache. Switching to `session:` removes the correlation and the cache. |

## 5. What remains to be done before real operation

1. Annotate the real corpus and re-run `tests/corpus_eval.py --real` (Phase 5).
2. Fix with jo the recall thresholds per identifier class.
3. Decide the Datadog and `mcp-proxy.anthropic.com` policy.
4. Deploy in a containerized environment or under a sandbox: this is the
   only form where D9 is held (jo's arbitration of 2026-08-02 — no firewall
   on the workstation). As long as this is not done, **the proxy reduces the
   surface, it does not close it**: cf. `docs/d9-network-isolation.md`.
5. Legal / DPO review on the basis of the present document.
6. Envelope encryption of the vault (KMS/HSM), key rotation, immutable
   access log — not implemented in the MVP.
