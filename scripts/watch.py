#!/usr/bin/env python3
"""Live view of one project's chain — counters, arbitration queue, decisions.

Standard library only, and deliberately so: it refreshes once a second, and
paying for a `uv run` each time would make it useless.

What it shows and what it does NOT show is the whole point. The arbitration
queue carries only the SURROGATE — the vault, and the vault alone, can go back
to the real value, and it does so when the operator arbitrates, not here. The
audit log, on the other hand, holds refused commands in clear: that is for the
operator's eyes, which is exactly who is reading this.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

CLEAR = "\033[H\033[J"
DIM, BOLD, RESET = "\033[2m", "\033[1m", "\033[0m"
RED, GREEN, YELLOW = "\033[31m", "\033[32m", "\033[33m"


def healthz(url: str) -> dict | None:
    try:
        with urllib.request.urlopen(url + "/healthz", timeout=2) as answer:
            return json.load(answer)
    except (urllib.error.URLError, OSError, ValueError):
        return None


def tail_json(path: Path, count: int) -> list[dict]:
    """The last `count` readable JSON lines of a file, oldest first."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-count:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue  # a half-written line: the writer is still appending
    return out


def clock(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def render(project: str, state: Path, url: str, width: int) -> str:
    lines = [f"{BOLD}anonproxy{RESET}  {project}"
             f"{DIM}{time.strftime('%H:%M:%S').rjust(max(0, width - 12 - len(project)))}{RESET}",
             DIM + "─" * width + RESET]

    health = healthz(url)
    if health is None:
        lines.append(f"{RED}proxy      unreachable on {url}{RESET}")
        lines.append(f"{DIM}           the session cannot reach the API either "
                     f"— start it with `task start`{RESET}")
    else:
        p = health.get("pipeline", {})
        lines.append(
            f"proxy      {p.get('calls', 0)} call(s) · "
            f"{p.get('detected', 0)} detected · "
            f"{p.get('substituted', 0)} substituted · "
            f"{p.get('cache_hits', 0)} cache hit(s)")
        unresolved = health.get("unresolved_total", 0)
        # A surrogate the model invented is REFUSED, never guessed (D5). It is
        # counted rather than silenced: an accepted residual that nobody counts
        # is indistinguishable from one that never happens.
        colour = YELLOW if unresolved else ""
        lines.append(
            f"vault      {health.get('vault_entries', 0)} identity(ies) · "
            f"{colour}{unresolved} surrogate(s) the model invented{RESET}")
        d = health.get("detector", {})
        lines.append(f"detector   {d.get('device', '?')} · "
                     f"{'warm' if d.get('warm') else 'cold'} · "
                     f"scope {health.get('scope', '?')}")

    queue = tail_json(state / "policy" / "en-attente.jsonl", 200)
    lines.append("")
    if not queue:
        lines.append(f"{DIM}arbitration  nothing pending{RESET}")
    else:
        lines.append(f"{BOLD}arbitration{RESET}  {len(queue)} pending"
                     f"{DIM}   → task policy -- {project} -- arbitrer{RESET}")
        for entry in queue[-6:]:
            lines.append(f"   {entry.get('type', '?'):<12} "
                         f"{entry.get('substitut', '?')}")

    decisions = tail_json(Path(state, "hook-audit.jsonl"), 400)
    lines.append("")
    if not decisions:
        lines.append(f"{DIM}hook         no decision recorded yet{RESET}")
    else:
        denied = sum(1 for d in decisions if d.get("decision") == "deny")
        lines.append(f"{BOLD}hook{RESET}         {len(decisions)} decision(s), "
                     f"{denied} refused")
        for entry in decisions[-8:]:
            deny = entry.get("decision") == "deny"
            mark = f"{RED}deny {RESET}" if deny else f"{GREEN}allow{RESET}"
            detail = entry.get("reason") or ""
            if not deny:
                detail = DIM + (entry.get("digest") or "") + RESET
            room = max(20, width - 34)
            lines.append(f"   {clock(entry.get('ts', 0))}  {mark}  "
                         f"{(entry.get('tool') or '?'):<10} {detail[:room]}")
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: watch.py PROJECT STATE_DIR [PROXY_URL]", file=sys.stderr)
        return 2
    project, state = sys.argv[1], Path(sys.argv[2])
    url = sys.argv[3] if len(sys.argv) > 3 else "http://127.0.0.1:8090"
    once = os.environ.get("ANONPROXY_WATCH_ONCE") == "1"
    try:
        while True:
            width = min(os.get_terminal_size().columns, 100) if sys.stdout.isatty() else 80
            frame = render(project, state, url, width)
            print((CLEAR if not once else "") + frame, flush=True)
            if once:
                return 0
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
