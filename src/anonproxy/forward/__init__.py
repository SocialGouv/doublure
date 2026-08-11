"""Forward-proxy mode — the channel that `ANTHROPIC_BASE_URL` cannot reach.

One API client's base URL setting only redirects that client's calls to that
API. Everything else an agent opens — remote MCP servers, package registries,
a vendor's tool API — ignores it, and Phase 0 measured four such destinations
against one that honours it.

They do honour an explicit forward proxy: the egress harness captured all of
them through mitmproxy. So what looked like an unreachable channel is a
question of interception mode, not of fatality.
"""
