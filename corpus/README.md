# Corpus doré (Phase 5)

## Structure

```
corpus/
├── synthetic/annotations.jsonl   # versionné — exemples SYNTHÉTIQUES
└── real/annotations.jsonl        # GITIGNORÉ — matière réelle archivée
```

Format d'une ligne (JSONL) :

```json
{"id": "k8s-001", "source": "kubectl get pods", "text": "…",
 "entities": [{"start": 12, "end": 31, "type": "HOSTNAME"}],
 "must_not_leak": ["db-01.acme.internal"]}
```

- `entities` : annotations de vérité terrain (offsets en points de code).
- `must_not_leak` : sous-chaînes qui ne doivent JAMAIS survivre à la
  substitution. C'est le critère dur, indépendant du typage exact.

## Constitution du jeu réel

Réponse §3.3 de jo : **la matière première existe déjà** (logs, tickets, CI
archivés). Elle n'a pas encore été annotée.

Procédure, dans cet ordre :

1. Copier les extraits bruts dans `corpus/real/raw/` (gitignoré). 200 à 500
   exemples, représentatifs des sorties d'outils réellement utilisées.
2. Annoter avec `uv run python tests/corpus_eval.py --annotate` (pré-annotation
   par le détecteur, correction humaine — c'est la correction qui fait foi).
3. Mesurer : `uv run python tests/corpus_eval.py --real`.

**Ne pas faire lire le corpus réel à un agent tant que la revue de la §7 n'est
pas close** : tout ce que lit l'agent part chez Anthropic. La procédure
ci-dessus est faite pour être exécutée par un humain, ou par l'agent APRÈS
mise en service du proxy (le corpus transite alors pseudonymisé).

## Seuils (plan §5)

| Métrique | Seuil |
|---|---|
| Rappel sur les secrets | 100 %, non négociable |
| Rappel par classe d'identifiant | à fixer avec jo sur le jeu réel |
| Faux positifs sur chaînes techniques | < 2 % |
| Variance sur exécutions répétées | 0 |
| Collisions de substituts | 0 |
| Substitution vers la mauvaise entité | 0 |
| JSON invalide après transformation | 0 |
| Latence P95 ajoutée | mesurée par `tests/detect_latency.py` |
| Impact sur le cache de prompt | à mesurer en session réelle |
