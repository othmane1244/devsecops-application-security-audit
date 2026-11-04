# 22 — Tri des 28 détections apparues après le 20 octobre

État au 4 novembre 2026. Ces 28 détections sont absentes du rapport initial
(`trivy-image-initial.json`, 20 octobre) et présentes dans le rescan de la
**même image** `v20.3.0` le 4 novembre : elles viennent de la mise à jour de
la base Trivy ([contre-audit, section 5](../contre-audit.md#5-pourquoi-124-détections-aujourdhui-contre-98-au-départ)).
Toutes restent présentes dans l’image corrigée, sauf mention contraire.

Ce document est un **tri**, pas une analyse complète comme les fiches 01 à
19 : trois questions par paquet, avec la preuve utilisée.

## Méthode

1. **Utilisé à l’exécution ?** L’image corrigée (`juice-shop-corrige:audit-lock`)
   a été démarrée avec `NODE_OPTIONS=--require scripts/dump-loaded.js`. Le
   script relève toutes les 10 s les paquets npm présents dans
   `require.cache` et les bibliothèques `.so` projetées dans
   `/proc/self/maps` du processus applicatif (PID 1). Les routes suivantes ont
   été sollicitées avant le relevé : `/`, recherche produit, `/api/Products`
   avec paramètres tableau, `/dataerasure`, `whoami`, panier, `/ftp`,
   `/rest/memories`, suivi de commande, `/b2b/v2/orders`, envoi de fichier,
   image de profil (fichier et URL), export de données, URL mal encodée.
   Résultat : `reports/contre-audit/modules-charges-execution.json`.
   « Non chargé » vaut pour ce scénario : un chemin non sollicité peut
   charger le paquet plus tard.
2. **Atteignable ?** Chaîne de dépendance dans `package-lock.json`, appels
   dans le code (`server.ts`, `lib/`, `routes/`), et pour `body-parser` un
   essai local.
3. **Décision**, reprise dans le `.trivyignore.yaml` du fork pour les
   CRITICAL/HIGH corrigeables.

## Paquets npm (14 détections)

| Paquet | Détections | Utilisé à l’exécution ? | Atteignable ? | Décision |
|---|---|---|---|---|
| `body-parser` 1.20.8 | CVE-2026-111181 HIGH — déni de service par erreur non gérée du flux de décompression | **Oui**, chargé au démarrage (`server.ts:18`). | **Oui, sans authentification** : `bodyParser.urlencoded` et `bodyParser.text({ type: '*/*' })` (`server.ts:335`, `:342`) acceptent `Content-Encoding` (`inflate` vrai par défaut). Essai local sur `/rest/user/login` avec corps gzip/deflate malformés : HTTP 400, processus toujours actif (0 redémarrage); le plantage décrit par l’avis **n’a pas été reproduit** avec ces entrées simples. | **Corriger en priorité** : 1.20.9 (version corrective de la même branche). Exception CI jusqu’à la mise à jour. |
| `multer` 2.4.0 | CVE-2026-113872 HIGH — déni de service par requête interrompue pendant un filtrage **asynchrone** de fichier | **Oui** (`server.ts:11`). | **Non en l’état** : les deux configurations (`uploadToMemory`, `uploadToDisk`, `server.ts:722-745`) n’ont **pas de `fileFilter`**; le filtre par défaut de multer est synchrone. Les routes d’envoi restent publiques. | Mettre à jour vers 2.5.0 avec la prochaine série (sans urgence). Exception CI. |
| `undici` 6.29.0 | CVE-2026-109383 HIGH (validation de certificat contournée), CVE-2026-109869 HIGH, CVE-2026-87018 HIGH, CVE-2026-109924 MEDIUM, CVE-2026-109932 MEDIUM (dénis de service) | **Non chargé.** Seul dépendant : `@ai-sdk/provider-utils`, qui ne le charge qu’à l’appel (`nodeRequire("undici")`). Le `fetch` de Node utilise sa propre copie interne, pas ce paquet. | **Conditionnel** : seulement par le chatbot (`routes/chat.ts`, `ai` / `@ai-sdk/openai-compatible`) quand une API LLM est configurée et joignable; par défaut `http://localhost:11434/v1`, injoignable dans l’image (avertissement au démarrage). Le contournement de certificat concerne les appels **sortants** vers cette API. | Mettre à jour vers 6.29.1 avant toute activation du chatbot. Exception CI. |
| `decode-uri-component` 0.2.2 | CVE-2026-118664 HIGH — déni de service par encodage pourcent malformé | **Oui**, chargé au démarrage. | **Peu probable** : chaîne `got@8` → `cacheable-request` → `normalize-url@2` → `query-string` ([14](14-got.md), [15](15-decode-uri-component.md)). Les URL traitées sont celles de la configuration (personnalisation au démarrage), pas des entrées utilisateur. L’URL mal encodée envoyée au serveur (`/%E0%A4%A`) passe par Express, pas par ce paquet (HTTP 400). | Accepter jusqu’à la mise à jour de `got` (fiche 14). Exception CI. |
| `qs` 6.16.0 | CVE-2026-110816 MEDIUM — exception non gérée lors de la **sérialisation** de tableaux | **Oui** (Express et `body-parser`). | **Non trouvé** : Express et `body-parser` appellent `qs.parse`, pas `qs.stringify`; les autres dépendants (`superagent`, `@cypress/request`) sont des dépendances de développement. | Accepter; suivre la mise à jour d’Express. |
| `sanitize-html` 1.4.2 | CVE-2026-113654 MEDIUM (contournement via `noscript`), CVE-2026-113661 MEDIUM (XSS via `meta refresh`) | **Oui**. | **Oui** : même chemin que la fiche [03](03-sanitize-html.md) (commentaires de feedback). | Déjà planifié : mise à jour de `sanitize-html` (feuille de route, étape 3), qui couvre aussi ces deux avis. |
| `hbs` 4.3.1 | CVE-2021-32822 MEDIUM — options du moteur mêlées aux données de rendu | **Oui**. | **Oui, authentifié** : c’est le mécanisme du champ `layout` de `POST /dataerasure`, déjà décrit dans la fiche [06](06-handlebars.md) (défi volontaire). | Aucune version corrigée publiée. Accepter (voir risques résiduels du contre-audit); corriger côté application en ne passant pas `req.body` aux options de rendu. |
| `glob` 10.5.0 | CVE-2026-118773 MEDIUM — annulation incomplète d’un parcours | **Oui**. | **Non** : deux appels au démarrage, motifs fixes et sans `AbortSignal` (`lib/startup/cleanupFtpFolder.ts:13`, `restoreOverwrittenFilesWithOriginals.ts:32`). | Accepter. |
| `minimatch` 9.0.9 (sous `glob`) | CVE-2026-118764 MEDIUM — expansion de motif coûteuse | **Oui** (via `glob`). | **Non** : mêmes motifs fixes que `glob`. Distinct de `minimatch` 3.0.5 sous `replace` ([10](10-minimatch.md)). | Accepter. |

## Paquets Debian (14 détections)

Aucun n’a de version corrigée dans Debian à cette date, sauf
`ca-certificates`.

| Paquet | Détections | Utilisé à l’exécution ? | Atteignable ? | Décision |
|---|---|---|---|---|
| `libstdc++6` 14.2.0-19 | CVE-2026-114690, -114691, -115455 MEDIUM (algorithmes parallèles `std::`, dépassement d’entier, `std::bitset`) | **Oui** : `libstdc++.so.6.0.33` est projetée dans le processus Node. | **Non démontré** : les avis visent des fonctions précises de la bibliothèque; aucun appel de Node ou des modules natifs (`sqlite3`) à ces fonctions n’a été recherché. | Accepter, pas de correctif. Revoir à la prochaine image distroless. |
| `libgcc-s1` 14.2.0-19 | mêmes trois CVE | **Oui** : `libgcc_s.so.1` projetée. | Les avis portent sur `libstdc++`; Trivy les rattache à tous les paquets issus de la source `gcc-14`. | Accepter. |
| `libgomp1` 14.2.0-19 | mêmes trois CVE | **Non** : aucune projection de `libgomp` (OpenMP). | Non. | Accepter. |
| `gcc-14-base` 14.2.0-19 | mêmes trois CVE | Paquet de métadonnées, sans code. | Non. | Accepter. |
| `libc6` 2.41-12+deb13u4 | CVE-2026-84243 MEDIUM — exécution de code via `LANGUAGE` | **Oui** (`libc.so.6`). | **Non par un attaquant distant** : il faut contrôler les variables d’environnement du processus, fixées au déploiement. | Accepter. |
| `ca-certificates` 20250419 | DSA-6572-1 (UNKNOWN), corrigé en `20250419+deb13u1` | Oui pour les connexions TLS sortantes (`got`, chatbot). | Concerne la confiance des connexions sortantes, pas une entrée attaquant. | Gardé volontairement : l’image de base est épinglée sur celle de `v20.3.0` pour la comparaison avant/après. **Mettre à jour le digest distroless après l’audit.** |

## Synthèse

| Décision | Détections |
|---|---|
| Corriger en priorité | `body-parser` (1) |
| Corriger avec une série prévue | `sanitize-html` (2), `multer` (1), `undici` (5, avant activation du chatbot), `ca-certificates` (1, après l’audit) |
| Accepter, non atteignable ou non démontré | `decode-uri-component`, `qs`, `glob`, `minimatch` 9.0.9, paquets `gcc-14` (12), `libc6` |
| Accepter sans correctif disponible | `hbs` (1) |

Limites : relevé d’exécution sur un seul scénario et sur une durée courte;
le chatbot, les commandes B2B (`POST`) et la plupart des défis n’ont pas
été exercés. Aucun avis
n’a été vérifié contre le code source exact de la version installée, à la
différence des fiches 01 à 19.
