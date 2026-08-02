# Proxy de pseudonymisation Claude Code ↔ API Anthropic

Les identifiants sensibles (hôtes, IP, dépôts, comptes, images, secrets) sont
remplacés par des substituts **plausibles** avant de quitter la machine, et
restaurés au retour. L'opérateur voit toujours le réel ; le fournisseur du
modèle n'en voit rien.

```
claude ──ANTHROPIC_BASE_URL──► proxy :8090 ──► api.anthropic.com
                                  │
                                  ├── détecteur AnonShield :9000 (GPL, processus séparé)
                                  └── coffre SQLite (hors dépôt)

Bash · WebFetch · MCP ──► hook PreToolUse ──► bloqué ou autorisé
```

## Démarrer

```bash
services/anonshield/wrapper/install-cuda.sh   # torch CUDA + fastapi (1re fois)
services/anonshield/wrapper/run.sh            # détecteur   :9000
scripts/run-proxy.sh                          # proxy       :8090
ANTHROPIC_BASE_URL=http://127.0.0.1:8090 claude
```

Le coffre et la clé maître vivent dans `~/.local/state/anonproxy/` — hors du
dépôt, jamais lus par l'agent. **Les sauvegarder : la clé + la base sont les
deux moitiés du secret ; les perdre rend la dé-anonymisation impossible.**

## Vérifier

```bash
uv run pytest tests/ --ignore=tests/egress   # 311 tests
uv run pytest tests/egress/test_report.py    # 18 tests (harnais Phase 0)

bash tests/egress_capture.sh                 # inventaire d'egress
uv run python tests/detect_latency.py        # latence de détection (<150 ms)
uv run python tests/corpus_eval.py           # métriques sur corpus annoté
bash tests/phase3_e2e.sh                     # session réelle + capture des corps
bash tests/phase4_e2e.sh                     # commande interdite bloquée
bash tests/datadog_probe.sh                  # que part-il vers la télémétrie ?
```

## Organisation

| Chemin | Rôle |
|---|---|
| `PLAN-proxy-pseudonymisation.md` | Spécification — fait autorité, ne pas modifier |
| `CLAUDE.md` | État des phases, décisions verrouillées, déviations |
| `anthropic_walker.py` | Traversée JSON/SSE (fourni ; 3 défauts corrigés, cf. CLAUDE.md) |
| `src/anonproxy/` | Proxy, moteur de substituts, coffre |
| `services/anonshield/` | **Côté GPL-3.0** : upstream + wrapper HTTP `/detect` |
| `hooks/` | Garde PreToolUse (canal 2) |
| `corpus/` | Jeu doré ; `corpus/real/` est gitignoré |
| `docs/analyse-re-identification.md` | Livrable DPO |
| `docs/d9-blocage-reseau.md` | Ce qui échappe au proxy, et la politique pare-feu |

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `ANONPROXY_SCOPE` | `project:<dossier>` | Portée du déterminisme (`session:`/`tenant:`/`global`) |
| `ANONPROXY_DETECT_URL` | `http://127.0.0.1:9000` | Service de détection |
| `ANONPROXY_VAULT` | `~/.local/state/anonproxy/vault.db` | Coffre |
| `ANONPROXY_REGEX_THRESHOLD` | `8000` | Au-delà, détection regex (gros volumes) |
| `ANON_DEVICE` | `auto` | `cuda` \| `cpu` — `cuda` échoue si indisponible |

Détection : `services/anonshield/wrapper/allowlist.txt` (§6 du plan) et
`custom_patterns.json` (conventions d'environnement, à écrire avec jo).

## Frontière GPL

`services/anonshield/**` est sous GPL-3.0 (upstream + notre wrapper).
La communication avec le reste passe **uniquement par HTTP** : `src/anonproxy/`
n'importe jamais depuis ce dossier (décision D7).

## Limites connues

Le canal 2 (Bash, MCP) n'est pas réversible : le hook bloque, il ne
pseudonymise pas. `mcp-proxy.anthropic.com` ne passe pas par
`ANTHROPIC_BASE_URL`. Un contrôle contournable n'est pas un contrôle : la
réponse définitive est le blocage pare-feu (D9). Voir
`docs/analyse-re-identification.md` pour l'inventaire complet des risques
résiduels et des fuites assumées.
