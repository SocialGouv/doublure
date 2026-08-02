#!/usr/bin/env python3
"""Rapport d'inventaire d'egress (Phase 0).

Agrège un `flows.jsonl` produit par `inventory_addon.py`, confronte chaque
destination à `known_destinations.json`, et échoue (code retour 1) si une
destination n'est pas justifiée — c'est le garde-fou de non-régression exigé
par la Phase 0 du plan.

Fail-closed : une capture vide ou une session de référence en échec font
échouer le rapport ; l'absence de preuve n'est pas une preuve d'absence.

Stdlib uniquement. Utilisable en CLI ou importé par les tests.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

MODEL_HOST = "api.anthropic.com"


def load_flows(path: Path | str) -> list[dict]:
    """Charge le JSONL ; toute ligne invalide est une erreur explicite."""
    flows: list[dict] = []
    text = Path(path).read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            flows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{lineno} — ligne JSONL invalide : {exc}") from exc
    return flows


def aggregate(flows: list[dict]) -> dict[str, dict]:
    """Agrège les flux par hôte (normalisé en minuscules)."""
    agg: dict[str, dict] = defaultdict(
        lambda: {
            "http": 0,
            "connect": 0,
            "errors": 0,
            "bytes_out": 0,
            "bytes_in": 0,
            "ports": set(),
            "paths": defaultdict(int),
            "error_msgs": [],
        }
    )
    for f in flows:
        host = str(f.get("host", "?")).lower()
        a = agg[host]
        kind = f.get("kind", "http")
        if port := f.get("port"):
            a["ports"].add(port)
        if kind == "http":
            a["http"] += 1
            a["bytes_out"] += int(f.get("bytes_out", 0))
            a["bytes_in"] += int(f.get("bytes_in", 0))
            if path := f.get("path"):
                a["paths"][path] += 1
        elif kind == "connect":
            a["connect"] += 1
        elif kind == "error":
            a["errors"] += 1
            if msg := f.get("error"):
                a["error_msgs"].append(str(msg))
    return dict(agg)


def justify(host: str, known: dict[str, str]) -> str | None:
    """Justification d'un hôte : correspondance exacte puis motifs à joker.

    `*.exemple.tld` ne couvre volontairement pas `exemple.tld` : le domaine nu
    exige sa propre entrée (pas de généralisation implicite).
    """
    h = host.lower()
    for pattern, reason in known.items():
        p = pattern.lower()
        if ("*" in p or "?" in p) and fnmatch(h, p):
            return reason
        if h == p:
            return reason
    return None


def _fmt_bytes(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def build_report(
    agg: dict[str, dict],
    known: dict[str, str],
    *,
    session_rc: int,
    flow_count: int,
    generated: str,
) -> tuple[str, int]:
    """Rend le markdown du rapport et le code retour (0 = tout justifié)."""
    unjustified: list[str] = []
    rows: list[tuple[str, dict, str]] = []
    for host in sorted(agg, key=lambda h: agg[h]["bytes_out"], reverse=True):
        reason = justify(host, known)
        if reason is None:
            unjustified.append(host)
        rows.append((host, agg[host], reason or "**NON JUSTIFIÉE**"))

    total_out = sum(a["bytes_out"] for a in agg.values())
    model_out = agg.get(MODEL_HOST, {}).get("bytes_out", 0)
    ratio = (100.0 * model_out / total_out) if total_out else 0.0
    connect_only = [h for h, a in agg.items() if a["http"] == 0 and (a["connect"] or a["errors"])]

    md: list[str] = []
    md.append("# Inventaire d'egress — session Claude Code de référence")
    md.append("")
    md.append(f"- Généré : {generated}")
    md.append(f"- Flux capturés : {flow_count}")
    md.append(
        f"- Session de référence : {'OK' if session_rc == 0 else f'ÉCHEC (code {session_rc})'}"
    )
    md.append("")

    md.append("## Destinations")
    md.append("")
    if rows:
        md.append("| Hôte | Flux HTTP | Octets sortants | Octets entrants | CONNECT | Erreurs | Justification |")
        md.append("|---|---|---|---|---|---|---|")
        for host, a, reason in rows:
            md.append(
                f"| {host} | {a['http']} | {_fmt_bytes(a['bytes_out'])} | "
                f"{_fmt_bytes(a['bytes_in'])} | {a['connect']} | {a['errors']} | {reason} |"
            )
    else:
        md.append("Aucun flux capturé.")
    md.append("")

    md.append("## Ratio trafic modèle / autre")
    md.append("")
    md.append(
        f"- `{MODEL_HOST}` : {_fmt_bytes(model_out)} octets sortants sur "
        f"{_fmt_bytes(total_out)} au total → **{ratio:.1f} %** du volume sortant"
    )
    model_paths = agg.get(MODEL_HOST, {}).get("paths", {})
    if model_paths:
        for path, count in sorted(model_paths.items(), key=lambda kv: -kv[1]):
            md.append(f"  - `{path}` : {count} requête(s)")
    md.append("")

    md.append("## Connexions non déchiffrées (CONNECT/erreur sans flux HTTP)")
    md.append("")
    if connect_only:
        md.append("Destination visible mais contenu non inspecté (CA refusée par le client,")
        md.append("ou connexion interrompue). À justifier au même titre que le reste :")
        md.append("")
        for host in sorted(connect_only):
            msgs = "; ".join(sorted(set(agg[host]["error_msgs"]))[:3])
            md.append(f"- `{host}`{f' — {msgs}' if msgs else ''}")
    else:
        md.append("Aucune.")
    md.append("")

    md.append("## Limites du harnais")
    md.append("")
    md.append(
        "- Proxy explicite : seuls les processus honorant `HTTPS_PROXY` sont vus. "
        "Un outil en sockets bruts passe à côté ; la réponse définitive est le "
        "blocage pare-feu (décision D9, Phase 6)."
    )
    md.append(
        "- `NO_PROXY=localhost,127.0.0.1` : l'egress mesuré est ce qui sort de la "
        "machine ; le trafic local (cluster kind, services locaux) est exclu par "
        "définition."
    )
    md.append("")

    md.append("## Verdict")
    md.append("")
    failures: list[str] = []
    if flow_count == 0:
        failures.append(
            "❌ Aucun flux capturé — fail-closed : une capture vide ne prouve pas "
            "l'absence d'egress (proxy non traversé ?)."
        )
    if session_rc != 0:
        failures.append(
            f"❌ Session de référence en échec (code {session_rc}) : la capture "
            "n'est pas représentative."
        )
    if unjustified:
        failures.append(
            "❌ Destinations **NON JUSTIFIÉES** : "
            + ", ".join(f"`{h}`" for h in sorted(unjustified))
            + " — à identifier puis, décision de jo, ajouter à "
            "`known_destinations.json` ou bloquer."
        )
    if failures:
        md.extend(failures)
        code = 1
    else:
        md.append("✅ Toutes les destinations observées sont identifiées et justifiées.")
        code = 0
    md.append("")

    return "\n".join(md), code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("flows", help="fichier flows.jsonl produit par inventory_addon.py")
    parser.add_argument(
        "--known",
        default=str(Path(__file__).with_name("known_destinations.json")),
        help="destinations justifiées (JSON motif → justification)",
    )
    parser.add_argument("--out", help="fichier markdown de sortie (défaut : stdout)")
    parser.add_argument(
        "--session-rc",
        type=int,
        default=0,
        help="code retour de la session de référence (≠0 = rapport en échec)",
    )
    args = parser.parse_args(argv)

    flows = load_flows(args.flows)
    known = json.loads(Path(args.known).read_text(encoding="utf-8"))
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")

    md, code = build_report(
        aggregate(flows),
        known,
        session_rc=args.session_rc,
        flow_count=len(flows),
        generated=generated,
    )

    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
    else:
        print(md)

    return code


if __name__ == "__main__":
    sys.exit(main())
