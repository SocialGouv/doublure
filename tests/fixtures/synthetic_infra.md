# Note d'incident (SYNTHÉTIQUE — aucune valeur réelle)

Toutes les valeurs de ce fichier sont inventées pour tester le proxy de
pseudonymisation. Aucun rapport avec une infrastructure existante.

## Contexte

Le service `svc-payments-prod` héberge l'API de facturation sur
`db-master-01-prod.acmecorp.internal` (10.1.2.3). Le réplica
`db-replica-02-prod.acmecorp.internal` (10.1.2.4) accuse un retard de
réplication depuis le déploiement de `registry.acmecorp.io/payments/api:4.2.1`.

## Éléments

- Dépôt : https://github.com/acmecorp/payments-api
- Namespace Kubernetes : `demo-apps`
- Astreinte : alice.dupont@acmecorp.example
- Compte de service : svc-backup-agent@acmecorp.example
- Hôte de secours : `db-standby-03-staging.acmecorp.internal` (10.9.9.7)
- Passerelle publique : 198.51.100.42

## Question posée à l'agent

Résume l'incident en trois phrases, en citant l'hôte primaire, l'IP du
réplica et le dépôt concerné.
