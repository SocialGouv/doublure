#!/usr/bin/env python3
"""Verdict du critère de sortie Phase 3.

Cherche LITTÉRALEMENT chaque valeur sensible de la fixture synthétique dans
les corps réellement partis vers api.anthropic.com. Une occurrence = fuite.

Vérifie aussi le pendant : la réponse rendue à l'opérateur DOIT contenir les
vraies valeurs (sinon le proxy « protège » en cassant l'outil).

Usage : leak_report.py <capture_dir> <fixture> <claude_stdout>
"""
from __future__ import annotations

import json
import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote

#: Valeurs sensibles de la fixture synthétique, par catégorie.
SENSITIVE = {
    "hôte primaire": "db-master-01-prod.acmecorp.internal",
    "hôte réplica": "db-replica-02-prod.acmecorp.internal",
    "hôte standby": "db-standby-03-staging.acmecorp.internal",
    "IP primaire": "10.1.2.3",
    "IP réplica": "10.1.2.4",
    "IP standby": "10.9.9.7",
    "dépôt": "github.com/acmecorp/payments-api",
    "e-mail humain": "alice.dupont@acmecorp.example",
    "compte de service": "svc-backup-agent@acmecorp.example",
    "image": "registry.acmecorp.io/payments/api",
    "organisation": "acmecorp",
    "compte de service applicatif": "svc-payments-prod",
    "namespace": "demo-apps",
    "IP publique passerelle": "198.51.100.42",
    "version d'image": "api:4.2.1",
    "hôte standby (nom court)": "db-standby-03-staging",
}


def sensitive_from_fixture(fixture: Path) -> dict[str, str]:
    """Extrait automatiquement les valeurs sensibles de la fixture.

    Une liste maintenue à la main dérive dès que la fixture change : une
    valeur ajoutée et jamais recherchée donnerait un PASS silencieux. On
    complète donc `SENSITIVE` par tout ce que la fixture contient de
    reconnaissable (hôtes, IP, e-mails, URL de dépôt, images).
    """
    if not fixture.exists():
        return {}
    text = fixture.read_text(encoding="utf-8", errors="replace")
    found: dict[str, str] = {}
    patterns = {
        "hôte": r"\b[\w-]+(?:\.[\w-]+)+\.(?:internal|local|lan|corp)\b",
        "IP": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "e-mail": r"\b[\w.+-]+@[\w.-]+\.\w+\b",
        "dépôt": r"https://github\.com/[\w.-]+/[\w.-]+",
        "image": r"\b[\w.-]+\.(?:io|com|org)/[\w./-]+(?::[\w.-]+)?",
    }
    for label, pat in patterns.items():
        for i, m in enumerate(dict.fromkeys(re.findall(pat, text))):
            if m not in SENSITIVE.values():
                found[f"{label} (fixture #{i + 1})"] = m
    return found

#: Valeurs dont la présence dans la réponse prouve la restauration.
EXPECT_RESTORED = ["db-master-01-prod.acmecorp.internal", "10.1.2.4",
                   "payments-api"]


def normalize_blob(blob: str) -> str:
    """Rend la recherche littérale insensible aux encodages de transport.

    Une recherche brute rate une valeur réelle dès qu'elle est encodée :
    `json.dumps` avec `ensure_ascii=True` (le défaut de Python) écrit
    `caf\\u00e9-prod` et non `café-prod`, et une URL transporte `%2F` pour
    `/`. Sur des données françaises (accents, prénoms), la fuite deviendrait
    invisible. On déplie donc les échappements avant de chercher.
    """
    out = blob
    # échappements JSON \uXXXX et \/
    out = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), out)
    out = out.replace("\\/", "/")
    # pourcent-encodage
    out += "\n" + unquote(out)
    # normalisation Unicode : « café » composé vs décomposé
    return unicodedata.normalize("NFKC", out)


def main() -> int:
    out_dir = Path(sys.argv[1])
    fixture = Path(sys.argv[2])
    claude_out = Path(sys.argv[3])
    bodies = out_dir / "bodies"

    files = sorted(p for p in bodies.glob("*.json") if p.name != "index.jsonl")
    report: list[str] = []
    report.append("# Phase 3 — capture du canal 1 (corps sortants)\n")
    report.append(f"- capture : `{out_dir}`")
    report.append(f"- fixture : `{fixture}` (100 % synthétique)")
    report.append(f"- requêtes capturées vers api.anthropic.com : **{len(files)}**")

    if not files:
        report.append("\n**ÉCHEC** : aucune requête capturée — la chaîne n'a pas fonctionné.")
        print("\n".join(report))
        (out_dir / "report.md").write_text("\n".join(report), encoding="utf-8")
        return 1

    total = sum(p.stat().st_size for p in files)
    report.append(f"- volume sortant total : **{total / 1024:.1f} Ko**")
    paths = {}
    idx = bodies / "index.jsonl"
    if idx.exists():
        for line in idx.read_text(encoding="utf-8").splitlines():
            rec = json.loads(line)
            paths[rec["path"]] = paths.get(rec["path"], 0) + 1
    if paths:
        report.append("- chemins : " + ", ".join(f"`{k}` ×{v}" for k, v in sorted(paths.items())))

    blob = normalize_blob(
        "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in files)
    )

    report.append("\n## Recherche des valeurs réelles dans le corps sortant\n")
    report.append("| valeur sensible | occurrences | verdict |")
    report.append("|---|---|---|")
    leaks = 0
    searched = {**SENSITIVE, **sensitive_from_fixture(fixture)}
    for label, value in searched.items():
        # les corps JSON échappent parfois : on cherche la forme brute ET échappée
        n = blob.count(value) + blob.count(value.replace("/", "\\/"))
        if n:
            leaks += n
            report.append(f"| {label} (`{value}`) | {n} | **FUITE** |")
        else:
            report.append(f"| {label} (`{value}`) | 0 | absente |")

    answer = claude_out.read_text(encoding="utf-8", errors="replace") if claude_out.exists() else ""
    report.append("\n## Restauration côté opérateur\n")
    report.append("| valeur attendue dans la réponse | présente |")
    report.append("|---|---|")
    restored_ok = 0
    for value in EXPECT_RESTORED:
        present = value in answer
        restored_ok += int(present)
        report.append(f"| `{value}` | {'oui' if present else 'non'} |")

    # Substituts visibles côté opérateur = restauration incomplète.
    fake_hosts = set(re.findall(r"\b[\w-]+\.[\w-]+\.internal\b", answer))
    real_hosts = {v for v in SENSITIVE.values() if v.endswith(".internal")}
    residual = sorted(fake_hosts - real_hosts)
    if residual:
        report.append(f"\n**Substituts non restaurés dans la réponse** : {residual}")

    report.append("\n## Verdict\n")
    ok = leaks == 0 and restored_ok >= 1 and not residual
    if leaks:
        report.append(f"- **ÉCHEC — {leaks} occurrence(s) de valeurs réelles** dans le trafic sortant.")
    else:
        report.append("- Aucune valeur réelle dans le corps sortant.")
    report.append(f"- Valeurs restaurées côté opérateur : {restored_ok}/{len(EXPECT_RESTORED)}.")
    if residual:
        report.append("- **ÉCHEC** — des substituts subsistent dans la réponse.")
    report.append(f"\n**{'PASS' if ok else 'FAIL'}**")

    text = "\n".join(report)
    (out_dir / "report.md").write_text(text, encoding="utf-8")
    print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
