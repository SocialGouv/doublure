#!/usr/bin/env python3
"""Synthèse STRUCTURELLE des corps envoyés à Datadog.

Objectif : répondre à « qu'est-ce qui part ? » sans recopier les données dans
un rapport versionné. On liste les champs, les types d'événements et les
volumes ; on signale les champs dont le NOM suggère du contenu de session
(prompt, message, contenu de fichier, chemin), et on cherche des marqueurs
de la fixture synthétique pour trancher factuellement.

Usage : datadog_report.py <capture_dir>
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

#: Marqueurs SYNTHÉTIQUES de la fixture : s'ils apparaissent, du contenu de
#: session part réellement vers Datadog.
FIXTURE_MARKERS = [
    "db-master-01-prod.acmecorp.internal",
    "acmecorp",
    "svc-payments-prod",
    "10.1.2.3",
    "synthetic_infra",
]

#: Noms de champs qui, s'ils existent, portent probablement du contenu.
SUSPECT_FIELDS = ("prompt", "message", "content", "text", "input", "output",
                  "completion", "file", "path", "cwd", "command", "query")


def walk(node, prefix=""):
    """Aplatit un JSON en (chemin_de_champ, valeur)."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from walk(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(node, list):
        for item in node[:50]:
            yield from walk(item, f"{prefix}[]")
    else:
        yield prefix, node


def main() -> int:
    out_dir = Path(sys.argv[1])
    bodies = out_dir / "bodies"
    files = sorted(p for p in bodies.glob("*.json"))

    lines = ["# Que contient le flux Claude Code → Datadog ?\n"]

    # Preuve que le harnais a bien vu passer du trafic : sans elle, « aucune
    # requête Datadog » pourrait n'être qu'une panne de capture.
    flows = out_dir / "flows.jsonl"
    hotes: Counter[str] = Counter()
    if flows.exists():
        for line in flows.read_text(encoding="utf-8").splitlines():
            rec = json.loads(line)
            if rec.get("kind") in ("http", "connect"):
                hotes[rec.get("host", "?")] += 1
    if hotes:
        lines.append(f"Harnais actif : **{sum(hotes.values())} flux** vers "
                     f"{len(hotes)} destination(s) — "
                     + ", ".join(f"`{h}` ×{n}" for h, n in hotes.most_common(8)) + "\n")
    else:
        lines.append("**Attention** : aucun flux d'aucune sorte n'a été capturé — "
                     "le résultat ci-dessous ne prouve rien sur Datadog.\n")

    if not files:
        lines.append("Aucune requête vers Datadog pendant la session.")
        lines.append("")
        lines.append("Lecture possible : la télémétrie était déjà désactivée, "
                     "le flag statsig ne l'a pas activée pour cette session, ou "
                     "la session a été trop courte pour déclencher un flush (~15 s).")
        print("\n".join(lines))
        (out_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
        return 0

    total_wire = total_plain = 0
    index = bodies / "index.jsonl"
    if index.exists():
        for line in index.read_text(encoding="utf-8").splitlines():
            rec = json.loads(line)
            total_wire += rec["bytes_wire"]
            total_plain += rec["bytes_plain"]

    lines.append(f"- requêtes capturées : **{len(files)}**")
    lines.append(f"- volume sur le fil : **{total_wire / 1024:.1f} Ko** "
                 f"(décompressé : {total_plain / 1024:.1f} Ko)")

    champs: Counter[str] = Counter()
    events: Counter[str] = Counter()
    blob = ""
    for p in files:
        raw = p.read_text(encoding="utf-8", errors="replace")
        blob += raw
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        for entry in (payload if isinstance(payload, list) else [payload]):
            for champ, valeur in walk(entry):
                champs[champ] += 1
                if champ.split(".")[-1] in ("event", "event_name", "eventName", "message"):
                    events[str(valeur)[:60]] += 1

    lines.append(f"\n## Champs rencontrés ({len(champs)} distincts)\n")
    lines.append("| champ | occurrences |")
    lines.append("|---|---|")
    for champ, n in champs.most_common(40):
        lines.append(f"| `{champ}` | {n} |")

    if events:
        lines.append(f"\n## Types d'événements ({len(events)} distincts)\n")
        for ev, n in events.most_common(25):
            lines.append(f"- `{ev}` ×{n}")

    suspects = sorted({c for c in champs if c.split(".")[-1].lower() in SUSPECT_FIELDS})
    lines.append("\n## Champs au nom évocateur de contenu\n")
    lines.append(", ".join(f"`{c}`" for c in suspects) if suspects
                 else "Aucun champ nommé `prompt`, `message`, `content`, `file`…")

    lines.append("\n## Contenu de la session synthétique dans le flux\n")
    lines.append("| marqueur de la fixture | occurrences |")
    lines.append("|---|---|")
    fuites = 0
    for marker in FIXTURE_MARKERS:
        n = blob.count(marker)
        fuites += n
        lines.append(f"| `{marker}` | {n} |")

    lines.append("\n## Conclusion\n")
    if fuites:
        lines.append(f"**Du contenu de session part vers Datadog** : {fuites} occurrence(s) "
                     "de marqueurs de la fixture dans les corps capturés.")
    else:
        lines.append("**Aucun contenu de la session** (fichier lu, hôtes, IP, "
                     "organisation) n'apparaît dans les corps capturés : le flux "
                     "observé porte de la télémétrie opérationnelle, pas la "
                     "conversation.")
    lines.append("\nCorps bruts sous `bodies/` (gitignoré) — à supprimer après lecture.")

    text = "\n".join(lines)
    (out_dir / "report.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
