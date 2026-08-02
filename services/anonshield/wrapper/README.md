# anonshield-detect — wrapper HTTP minimal (GPL-3.0)

Service local de détection d'entités pour le proxy de pseudonymisation.
**Côté GPL de la frontière D7** : ce dossier (wrapper) + `../upstream` (clone
AnonShield) forment UN programme GPL-3.0, exécuté en processus séparé. Le
reste du dépôt ne communique avec lui que par HTTP — jamais par import.

## Lancer

```bash
services/anonshield/wrapper/install-cuda.sh # torch cu130 + fastapi/uvicorn
services/anonshield/wrapper/run.sh          # port 9000 (ANON_WRAPPER_PORT)
```

`install-cuda.sh` est à ré-exécuter après tout `uv sync`/`uv run` dans
`upstream/` (uv re-synchronise le venv sur le lock CPU). `run.sh` lance le
service via `.venv/bin/python` direct pour la même raison. Device :
`ANON_DEVICE=auto|cuda|cpu` (défaut auto ; `cuda` échoue explicitement si
CUDA est indisponible).

Premier lancement : télécharge `attack-vector/SecureModernBERT-NER` (cache HF),
génère la clé `ANON_SECRET_KEY` (persistée hors dépôt, jamais affichée).

## API

- `GET /healthz` → `{status, model, warm, loaded_in_s, entity_types}`
- `POST /detect` `{"text": "...", "strategy": "filtered"|"regex"}` →
  `{"entities": [{type, value, start, end, score}], "strategy", "elapsed_ms"}`
  - `filtered` (défaut) : NER transformer + recognizers regex — qualité max.
  - `regex` : recognizers regex seuls, sans NER — gros volumes de logs.

## Configuration

- `allowlist.txt` — anti-faux-positifs (§6 du plan) : exact ou `re:<regex>`
  (full-match). Appliquée côté presidio (exact) + post-filtre (regex).
- `custom_patterns.json` — conventions propres à l'environnement, à écrire
  avec jo (après Phase 3 de préférence). Exemples synthétiques fournis.
- Env : `ANON_TRANSFORMER_MODEL`, `ANON_SCORE_THRESHOLD` (défaut 0.4),
  `ANON_WRAPPER_PORT`, `ANONPROXY_STATE_DIR`.

## Critère de sortie Phase 1

`tests/detect_latency.py` (à la racine du dépôt) : P95 < 150 ms sur un texte
de 2 Ko, modèle chaud, aucun rechargement entre requêtes (un seul worker
uvicorn, moteur résident chargé au lifespan).
