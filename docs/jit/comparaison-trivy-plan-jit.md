# Comparaison Trivy / reproduction OSS du plan Jit

État au 5 novembre 2026. Jit étant inaccessible ([acces-bloque.md](acces-bloque.md)),
son plan « Minimal Viable Security » a été **reproduit avec les outils open
source qu’il orchestrait**. Les résultats ci-dessous sont ceux de ces outils,
**pas des résultats Jit** : ni déduplication, ni priorisation, ni backlog Jit.

## 1. Ce qui a été comparé

| | Plan Jit reproduit | Trivy (audit) |
|---|---|---|
| Exécution | Workflow `plan-jit-oss.yml` du fork, run [42073516164](https://github.com/othmane1244/juice-shop/actions/runs/42073516164) du 5 novembre 2026, sur la PR [#1 du fork](https://github.com/othmane1244/juice-shop/pull/1) | Rapports du contre-audit ([contre-audit.md](../contre-audit.md)) et de l’audit initial ([secrets](../secrets/rapport-partageable.md), [mauvaises configurations](../misconfigurations/rapport-partageable.md)) |
| Cible « référence » | Branche `audit/base-v20.3.0` = `f189f52` (code audité, sans correction) | Image `bkimminich/juice-shop:v20.3.0` |
| Cible « corrigée » | Commit de fusion de la PR #1 dans `audit/corrections` (corrections + workflow) | Image `juice-shop-corrige:audit-lock` |
| Ce qui est lu | **Le dépôt** (sources, tests, CI, IaC, lockfile) | Surtout **l’image** (paquets npm et Debian installés, fichiers livrés) |

Outils et réglages, épinglés par digest d’image :

| Contrôle | Outil | Réglages |
|---|---|---|
| SAST | Semgrep 1.183.0 | `p/javascript`, `p/typescript`, `p/owasp-top-ten`, `--metrics=off` |
| SCA | OSV-Scanner v2.7.0 | `scan source -r` (tous les lockfiles du dépôt) |
| Secrets | Gitleaks v8.30.1 | `dir`, `--redact` (valeurs remplacées par `REDACTED`) |
| IaC | KICS v2.2.0 | Dockerfile exclu (confié à Trivy, comme dans le plan Jit), détection de secrets de KICS désactivée |
| Dockerfile | Trivy 0.76.0 | `config --misconfig-scanners dockerfile` |

Données : `reports/plan-jit-oss/<cible>/<contrôle>/resultats.{json,sarif}`.
Chiffres de ce document : `reports/plan-jit-oss/synthese.json`, produit
par `node scripts/synthese-plan-jit.mjs reports/plan-jit-oss reports/trivy-image-corrige.json <fork>/package-lock.json`.
Les SARIF sont aussi dans l’onglet **Security** du fork, catégories
`<contrôle>-<cible>`.

## 2. Résultats par outil et par branche

| Contrôle | Référence `v20.3.0` | Corrigé | Ce qui change |
|---|---:|---:|---|
| SAST Semgrep | 43 | 46 | −1 : `hardcoded-jwt-secret` (`lib/insecurity.ts:54`, F-002) disparaît. +4 : `github-actions-mutable-action-tag` dans **notre** `audit-trivy.yml`. |
| SCA OSV-Scanner | **0** (aucun lockfile) | 67 avis sur 27 paquets | La référence n’a pas de `package-lock.json` : OSV ne voit **aucune** dépendance (voir § 5). |
| Secrets Gitleaks | 69 | 66 | −1 `private-key` (`lib/insecurity.ts:21`, F-002); `jwt` 12 → 10 : jetons de test signés par l’ancienne clé supprimés (`currentUser`), les autres changent de ligne. |
| IaC KICS | 219 | 219 | Aucun changement : la série de corrections ne touche pas l’IaC. |
| Dockerfile Trivy | 7 (3 fichiers) | 5 (2 fichiers) | `Dockerfile` racine : DS-0026 (pas de `HEALTHCHECK`) et DS-0001 (tag non figé) **corrigés**. |

Gravités Semgrep sur le code corrigé : 13 ERROR, 31 WARNING, 2 MEDIUM.
KICS : 20 HIGH, 110 MEDIUM, 40 LOW, 49 INFO, aucun CRITICAL.

### Où se trouvent les constats Semgrep (code corrigé)

| Emplacement | Nombre | Exemples |
|---|---:|---|
| Code applicatif | 13 | Injection SQL (`routes/login.ts:34`, `routes/search.ts:23`), `eval` (`routes/userProfile.ts:65`), redirection ouverte (`routes/redirect.ts:18`), `res.sendFile` avec chemin utilisateur (4 routes), listages de répertoires (`server.ts`, 5 dont `/encryptionkeys` et `/support/logs`) |
| Workflows GitHub | 17 | Tags d’actions non figés (11, dont 4 dans `audit-trivy.yml`), injection shell dans `run:` (5, workflows amont désactivés), `curl \| sh` (1) |
| Exemples des défis (`data/static/codefixes`) | 10 | Injections SQL et Terraform pédagogiques |
| Terraform | 4 | Sous-réseau à IP publique, TLS faible sur le load balancer |
| Configuration npm | 2 | `.npmrc` sans délai minimal de publication |

### Où se trouvent les constats Gitleaks (code corrigé)

54 `generic-api-key`, 10 `jwt`, 2 `private-key`. Par dossier : `test/api` 45,
`frontend/src` 7, `test/cypress` 5, `test/server` 4, `data/static` 2,
`terraform/` et `infrastructure/terraform/` 1 chacun (clé du défi
`iacLeakedKeyChallenge`), `routes/login.ts` 1. Toutes les valeurs sont
expurgées (`Secret = REDACTED`, contrôlé sur les JSON et SARIF).

## 3. Constats communs avec Trivy

| Domaine | Commun | Détail |
|---|---|---|
| Dépendances npm | **59 avis** | Même paquet@version et même identifiant, en tenant compte des alias CVE/GHSA : 59 des 60 détections npm de Trivy sur l’image corrigée sont aussi trouvées par OSV dans le lockfile. |
| Clé JWT codée en dur (F-002) | Oui | Trivy secrets (S-01, `lib/insecurity.ts:21`), Gitleaks (même ligne) et Semgrep (`hardcoded-jwt-secret`, ligne 54). Les trois la voient sur la référence et plus sur le code corrigé. |
| Clé du défi Terraform | Oui | Trivy (S-03) et Gitleaks : `infrastructure/terraform/networking.tf:171`. |
| Dockerfile | Oui | DS-0026 (pas de `HEALTHCHECK`) : même outil, même règle; corrigé dans le `Dockerfile` racine, toujours présent dans `infrastructure/Dockerfile`. |
| Terraform | Oui, en substance | Mêmes problèmes dans `infrastructure/terraform/networking.tf` et les exemples `codefixes` : listener HTTP, groupes de sécurité ouverts, IP publiques, en-têtes invalides non rejetés. Règles, nombres et gravités différents (§ 5). |

## 4. Constats propres à chaque côté

### Vus seulement par la reproduction du plan

1. **Vulnérabilités dans le code (Semgrep)**, qu’aucun scan Trivy ne peut
   voir, puisque Trivy compare des versions de paquets et des
   configurations, pas la logique du code :
   - **injection SQL** par concaténation dans `sequelize.query`, dans la
     connexion (`routes/login.ts:34`) et la recherche
     (`routes/search.ts:23`) : entrées utilisateur non authentifiées;
   - **exécution de code** par `eval` dans `routes/userProfile.ts:65`;
   - **redirection ouverte** (`routes/redirect.ts:18`), **lecture de
     fichiers** avec chemin issu de la requête (`res.sendFile`, 4 routes);
   - **listages de répertoires** publics, dont `/encryptionkeys` et
     `/support/logs` (`server.ts:298`, `:302`).

   Ce sont des **défis volontaires** de Juice Shop (lignes marquées
   `vuln-code-snippet`), mais ils sont réels et atteignables.
2. **Sécurité de la CI** : tags d’actions non figés, dont 4 dans notre
   propre `audit-trivy.yml` (`actions/checkout@v4`,
   `actions/upload-artifact@v4`). Le nouveau `plan-jit-oss.yml`, épinglé
   par SHA, n’est pas signalé.
3. **Dépendances de développement (OSV)** : 8 avis absents de Trivy
   (`@cyclonedx/cyclonedx-npm`, `fast-uri`, `minimatch` 10.2.6,
   `systeminformation`). Ces paquets ne sont pas dans l’image : Trivy ne
   peut pas les voir.
4. **Secrets dans les tests et le frontend (Gitleaks)** : 54
   `generic-api-key`, surtout des mots de passe et clés factices des tests
   d’API, et des jetons JWT de test. L’image ne contient pas `test/`, et la
   règle `generic-api-key`, heuristique, n’existe pas sous cette forme dans
   Trivy.
5. **IaC hors du périmètre Trivy (KICS)** : les fichiers Docker Compose
   (`infrastructure/docker-compose.yml` 14, `docker-compose.test.yml` 6,
   plus 42 dans les exemples `vulnerableDockerImageChallenge_*.yml`), la
   spécification OpenAPI `swagger.yml` (30) et le dossier `terraform/` à la
   racine du dépôt, absent de l’image.

### Vus seulement par Trivy

1. **Paquets Debian de l’image** : 45 détections (`libc6`, `libstdc++6`,
   `gcc-14`…, fiche [22](../analysis/22-nouvelles-detections.md)). Un scan
   du dépôt ne voit pas le système d’exploitation de l’image.
2. **NSWG-ECO-154** sur `sanitize-html` 1.4.2 : ancien avis du Node
   Security Working Group, absent de la base OSV.
3. **La version d’origine** : 124 détections sur l’image `v20.3.0`, contre
   **0** pour OSV sur la branche de référence, faute de lockfile.
4. **Le contenu réellement livré** : par exemple la copie compilée de la clé
   (S-02, `build/lib/insecurity.js`), qui n’existe que dans l’image.

## 5. Pourquoi ces écarts

| Cause | Effet |
|---|---|
| **Objet analysé** : dépôt contre image | Le plan voit le code, les tests, la CI et l’IaC non livrée; Trivy voit l’OS et les fichiers effectivement livrés. Aucun des deux n’est complet seul. |
| **Lockfile absent en amont** (`.npmrc` : `package-lock=false`, lock ignoré par git) | Un outil SCA de dépôt, Jit compris, est **aveugle** sur `v20.3.0`. Le fork ne devient analysable par OSV qu’avec le `package-lock.json` ajouté pendant le contre-audit. C’est un constat en soi : sans lockfile, le SCA de dépôt ne protège pas. |
| **Périmètre des dépendances** | OSV lit tout le lockfile, développement compris (8 avis en plus); Trivy dans l’image ne voit que la production. |
| **Bases d’avis** | OSV agrège GHSA et les avis par écosystème; Trivy a sa propre base, qui contient aussi les anciens avis NSWG. Une fois les alias rapprochés, l’accord est de 59 sur 60. |
| **Règles et heuristiques** | Gitleaks `generic-api-key` (54) repose sur des motifs larges et produit surtout des faux positifs de test; Trivy n’a pas de règle équivalente. |
| **Gravités** | KICS ne classe rien CRITICAL; Trivy classait CRITICAL le listener HTTP et les sorties réseau ouvertes (AWS-0054, AWS-0104). Les deux outils décrivent les mêmes défauts avec des échelles différentes. |
| **Limites du SAST** | Semgrep **ne détecte pas F-001** (acceptation d’`alg: none` et de HS256) **ni F-003** (jetons sans expiration) : ces défauts viennent du comportement de vieilles versions de bibliothèques, pas d’un motif dans le code. Ils ont été établis par la lecture des sources et prouvés par les tests dynamiques du contre-audit. |

## 6. Effet sur la décision de livraison

1. **Les corrections de l’audit sont confirmées** par un second ensemble
   d’outils. F-002 disparaît pour Semgrep, Gitleaks et Trivy. DS-0026 et
   DS-0001 disparaissent du `Dockerfile` racine. Aucun outil du plan ne
   signale de régression introduite par les corrections. Les 4 constats
   ajoutés concernent les tags non figés de `audit-trivy.yml`, une hygiène
   CI à corriger.
2. **Le plan ne change pas la conclusion sur les dépendances** : 59 avis
   communs, et les seuls avis propres à OSV portent sur des dépendances de
   développement absentes de l’image.
3. **Il renforce la conclusion « non livrable en exposition réelle »**. En
   plus des risques acceptés du contre-audit (MarsDB, `hbs`), Semgrep
   montre des vulnérabilités **atteignables sans authentification dans le
   code lui-même** : injections SQL à la connexion et à la recherche,
   `eval`, lecture de fichiers, listages de répertoires dont
   `/encryptionkeys`. Elles sont volontaires dans Juice Shop et ne relèvent
   pas d’une mise à jour de dépendance.

**Verdict proposé** :
- **Livrable comme cible d’entraînement corrigée** pour le périmètre de la
  série (JWT, `file-type`, `HEALTHCHECK`).
- **Non livrable pour une exposition réelle**. Il faudrait au minimum :
  - corriger les injections SQL et l’`eval` ;
  - supprimer les listages `/encryptionkeys`, `/ftp` et `/support/logs` ;
  - remplacer MarsDB ;
  - corriger `body-parser`.

**Actions qui découlent du plan** :
- figer par SHA les actions de `audit-trivy.yml` ;
- ajouter un délai minimal de publication npm (`.npmrc`) ;
- décider si les contrôles SAST et secrets deviennent bloquants, ce qui
  exigerait d’abord une ligne de base comme pour Trivy.

## 7. Limites

- **Ce n’est pas Jit.** Pas de déduplication entre outils, pas de
  priorisation selon le contexte d’exécution, pas de backlog centralisé ni de
  suivi des corrections, pas de PR de remédiation. Les constats sont
  dispersés entre cinq SARIF et cinq JSON par branche. Le recoupement avec
  Trivy a été fait à la main (script `synthese-plan-jit.mjs`).
- **Règles inconnues** : les jeux de règles et réglages exacts de Jit ne
  sont pas connus; les nombres obtenus ici ne prédisent pas ceux qu’aurait
  donnés Jit.
- **Analyse partielle de Semgrep** : 57 avertissements sur le code corrigé
  (38 analyses partielles, 16 erreurs de syntaxe, 3 dépassements de délai),
  surtout dans `data/static`, `frontend/src` et `.github/workflows`. Des
  constats peuvent manquer dans ces fichiers.
- **Mode non bloquant** : aucune PR n’est refusée par ce workflow.
- **Un seul run**, sans relecture manuelle de chaque constat des 54
  `generic-api-key` ni des 219 constats KICS : leur pertinence n’est pas
  établie individuellement.
- **Référence sans SCA** : la comparaison avant/après des dépendances
  repose sur Trivy, pas sur OSV.
- **Visibilité** : le fork est public; les artefacts (expurgés) et les
  alertes de l’onglet Security sont rattachés à ce dépôt public.
