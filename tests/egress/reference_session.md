Session de référence pour l'inventaire d'egress (Phase 0 — harnais mitmproxy).
Exécute EXACTEMENT ces étapes, dans l'ordre, sans en ajouter d'autres :

1. Lis le fichier tests/fixtures/synthetic_note.md et cite sa première ligne.
2. Exécute la commande : __KUBECTL_STEP__ — puis résume sa sortie en une ligne.
3. Appelle l'outil MCP context7 resolve-library-id avec libraryName="fastapi"
   et donne l'identifiant de bibliothèque retenu. Si l'outil n'est pas
   disponible, dis-le et passe à l'étape suivante.
4. Fais une recherche web (WebSearch) sur « mitmproxy addon api reference »
   et donne le titre du premier résultat.
5. Récupère https://example.com via WebFetch et donne le titre de la page.

Réponds de façon minimale à chaque étape. Termine ta réponse par la ligne :
SESSION DE RÉFÉRENCE TERMINÉE
