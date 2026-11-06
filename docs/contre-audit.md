# Contre-audit — corrections JWT, `file-type` et `HEALTHCHECK`

État au 4 novembre 2026. Cette fiche vérifie les corrections appliquées dans
le fork Juice Shop (branche `audit/corrections`) et compare l’image corrigée
à l’image d’origine avec **les mêmes commandes et la même base Trivy**.

## 1. Ce qui a été comparé

| | Avant | Après |
|---|---|---|
| Image | `bkimminich/juice-shop:v20.3.0` | `juice-shop-corrige:audit-lock`, construite depuis le fork |
| Source | tag `v20.3.0` | `v20.3.0` + corrections + verrouillage des dépendances (section 4) |
| Identifiant | ImageID `4060…823c` (voir [identite-image.md](identite-image.md)) | index `5c810867…6080`, config `e250af15…c37d` |
| Rapport Trivy | `reports/trivy-image-v20.3.0-rescan.json` | `reports/trivy-image-corrige.json` |

Les deux scans ont été faits le 4 novembre 2026 avec Trivy `0.76.0` (image
épinglée par digest `sha256:2416d1f7…d222`) et **la même base**, téléchargée
une fois à 20 h 37 UTC puis réutilisée avec `--skip-db-update`. L’image
d’origine a été rescannée au lieu de reprendre `trivy-image-initial.json` :
voir la section 5 pour l’écart entre les deux. `trivy-image-initial.json`
n’est pas modifié.

Commande (pour chaque image, depuis la racine du dépôt) :

```sh
docker save --platform linux/amd64 --output reports/<nom>.tar <image>
docker run --rm --mount type=volume,source=trivy-cache,target=/root/.cache/trivy \
  --mount type=bind,source=<chemin>/reports,target=/reports <trivy@digest> image \
  --skip-db-update --scanners vuln --timeout 15m --format json \
  --output /reports/<nom>.json --input /reports/<nom>.tar
```

Comparaison : `node scripts/compare-trivy.mjs <avant> <après> [paquets…]`,
résultat archivé dans `reports/contre-audit/comparaison-trivy.json`.

## 2. Corrections vérifiées

| Constat | Correction dans le fork | Vérification | Résultat |
|---|---|---|---|
| [F-001](findings/F-001-jwt-algorithm-confusion.md) confusion d’algorithme | `express-jwt` 8.5.1, `jsonwebtoken` 9.0.3, `jws` 4.0.1; `algorithms: ['RS256']` partout; `jws.verify` avec algorithme fixé par le serveur | Jeton `alg: none` et jeton HS256 signé avec l’ancienne clé publique, envoyés sur `/rest/basket/1` | **Avant : HTTP 200 (accepté). Après : HTTP 401.** |
| [F-002](findings/F-002-cle-privee-jwt-codee-en-dur.md) clé privée codée en dur | Clé lue depuis `JWT_PRIVATE_KEY` / `JWT_PRIVATE_KEY_FILE`, sinon paire RSA-2048 éphémère; clé publique dérivée; secret `deluxeToken` séparé | Jeton RS256 forgé avec l’ancienne clé 1024 bits; signature du jeton émis vérifiée avec l’ancienne clé publique | **Avant : forgé accepté (200), jeton émis signé par la clé codée en dur. Après : 401, jeton émis signé par une autre clé.** |
| [F-003](findings/F-003-jetons-sans-expiration.md) jetons sans expiration | `jsonwebtoken` 9 applique `expiresIn: '6h'` | Décodage du jeton émis; jeton expiré signé avec la clé injectée | **Avant : pas de `exp`. Après : `exp − iat = 6 h`; jeton expiré refusé (401), jeton valide accepté (200).** |
| [13](analysis/13-file-type.md) CVE-2026-31808 | `file-type` 21.3.4 (`fileTypeFromBuffer`) | Trivy; envoi d’une image de profil | CVE absente après correction. PNG valide accepté (302), texte déguisé refusé (500 « Illegal file type »), comme avant. |
| DS-0026 `HEALTHCHECK` absent | `HEALTHCHECK` via `/nodejs/bin/node` (image distroless sans shell) | `docker inspect` | Conteneur `healthy`. |

Le script `scripts/contre-audit-jwt.mjs` produit les lignes F-001 à F-003 et le
parcours fonctionnel. Il lit l’ancienne clé depuis un fichier local passé en
argument (extrait de l’historique git du fork) et **n’écrit aucune clé**.
Résultats : `reports/contre-audit/jwt-fonctionnel-origine.json` (4/9
contrôles réussis) et `jwt-fonctionnel-corrige.json` (9/9).

Le test du jeton expiré a été fait sur un conteneur démarré avec
`JWT_PRIVATE_KEY_FILE` (clé RSA-2048 générée pour le test, montée en lecture
seule, supprimée ensuite). Il confirme aussi que ce mode de chargement
fonctionne : le jeton émis par le serveur est signé par la clé injectée.

## 3. Non-régression fonctionnelle

| Contrôle | Avant | Après |
|---|---|---|
| Connexion `admin@juice-sh.op` | 200 | 200 |
| `GET /rest/user/whoami` avec le jeton | e-mail renvoyé | e-mail renvoyé |
| Ajout au panier (produit 24) puis lecture | 200, 3 → 4 produits | 200, 3 → 4 produits |
| Envoi d’une image de profil PNG | 302 | 302 |
| Tests unitaires serveur (`npm run test:server`) | — | 417 réussis, 0 échec, 3 ignorés |
| Tests d’intégration (`npm run test:api`) | — | 545 réussis, 0 échec, 6 ignorés |
| `tsc`, ESLint sur les fichiers modifiés | — | sans erreur |

Les tests ont tourné sous Windows, sur les dépendances installées avec
`npm ci` depuis le `package-lock.json` du fork. `test:api` exige
`build/server.js` (`npm run build:server`) et `frontend/dist` (copié depuis
l’image construite, le frontend n’étant pas modifié).

Sept tests vérifiaient que les attaques JWT **réussissaient** ou dépendaient
de l’ancienne clé : `jwtUnsignedChallenge` (2), `jwtForgedChallenge` (2),
`deluxeToken`, `currentUser`, et `GET basket should accept forged JWTs` dans
`test/api/basket.test.ts`. Ils ont été inversés ou réécrits. Les deux tests
HS256 étaient ignorés sous Windows; ils s’exécutent maintenant partout. Les
tests Cypress n’ont pas été exécutés.

## 4. Trivy avant / après

### Verrouillage des dépendances et de l’image de base

Un premier contre-audit construisait l’image sans `package-lock.json`
(`.npmrc` amont : `package-lock=false`) et avec l’image de base distroless
du jour. La baisse mesurée mélangeait alors les corrections et des mises à
jour sans rapport (`handlebars`, `undici`, `multer`, `qs`, `body-parser`,
`ca-certificates`). Pour isoler les corrections, le fork fige maintenant :

- **les dépendances npm** : `package-lock.json` repris de l’image
  `v20.3.0` elle-même (`/juice-shop/package-lock.json`, 1 351 paquets), puis
  mis à jour par `npm install --package-lock-only`. Par rapport au lock
  d’origine, seules **36 entrées** changent, toutes liées aux paquets
  corrigés (`express-jwt`, `jsonwebtoken`, `jws`, `jwa`, `file-type`,
  `strtok3`, `token-types`, leurs dépendances et types). `.npmrc` passe à
  `package-lock=true` et le lock n’est plus exclu par `.gitignore`;
- **l’image de base** : `gcr.io/distroless/nodejs24-debian13@sha256:96df910f…66c6`,
  publiée le 1er octobre 2026. Ses 22 couches (`diff_ids`) sont identiques
  aux 22 premières couches de `v20.3.0`, d’après le registre gcr.io.

Contrôle dans l’image corrigée : `hbs` 4.3.1, `handlebars` 4.7.9, `undici`
6.29.0, `multer` 2.4.0, `qs` 6.16.0, `body-parser` 1.20.8, comme dans
`v20.3.0`.

### Résultat

Unité : couple (vulnérabilité, paquet, version installée), même méthode des
deux côtés.

| Sévérité | Avant | Après | Écart |
|---|---:|---:|---:|
| CRITICAL | 11 | 9 | −2 |
| HIGH | 32 | 22 | −10 |
| MEDIUM | 69 | 62 | −7 |
| LOW | 11 | 11 | 0 |
| UNKNOWN | 1 | 1 | 0 |
| **Total** | **124** | **105** | **−19** |

**19 disparitions, aucun ajout, toutes dues aux corrections :**

| Paquet retiré ou remplacé | Détections |
|---|---|
| `jsonwebtoken` 0.4.0 et 0.1.0 (sous `express-jwt`) | CVE-2015-9235 (CRITICAL), CVE-2022-23539, NSWG-ECO-17, CVE-2022-23540, CVE-2022-23541 — ×2 |
| `jws` 0.2.6 | CVE-2016-1000223, CVE-2025-65945 |
| `express-jwt` 0.1.3 | CVE-2020-15084 |
| `file-type` 16.5.4 | CVE-2026-31808 |
| `moment` 2.0.0 (dépendance de l’ancien `express-jwt`) | CVE-2017-18214, CVE-2022-24785, CVE-2016-4055 |
| `base64url` 0.0.6 (dépendance de `jws` 0.2.x) | NSWG-ECO-428, GHSA-rvg8-pwq2-xj7q |

Les 9 CRITICAL et 22 HIGH restantes sont hors du périmètre de cette série de
corrections. Les 28 qui ont une version corrigée sont listées et justifiées
dans le `.trivyignore.yaml` du fork; les 3 sans correctif sont traitées à
la section 6.

## 5. Pourquoi 124 détections aujourd’hui contre 98 au départ

Le rapport initial (`trivy-image-initial.json`, `CreatedAt`
2026-10-20T11:28Z) et le rescan du 4 novembre portent sur **la même image**
(ImageID `4060…823c`) avec **la même version de Trivy** (0.76.0). Seule la
base de vulnérabilités a changé entre les deux dates. Comparaison ligne à
ligne (`scripts/compare-trivy.mjs`) :

- **28 détections nouvelles** :
  - 14 sur les paquets Debian (`gcc-14-base`, `libgcc-s1`, `libgomp1`,
    `libstdc++6` : CVE-2026-114690, -114691, -115455; `libc6` :
    CVE-2026-84243; `ca-certificates` : DSA-6572-1);
  - 14 sur les paquets npm : `undici` 6.29.0 (5), `sanitize-html` 1.4.2 (2),
    `body-parser`, `decode-uri-component`, `glob`, `minimatch`, `multer`,
    `qs`, et `hbs` 4.3.1 (CVE-2021-32822, avis ancien nouvellement associé
    à ce paquet dans la base).
- **2 détections retirées** : CVE-2026-93748 (`http-cache-semantics`
  3.8.1, HIGH) et CVE-2026-2950 (`lodash` 2.4.2, MEDIUM). Elles ne figurent
  plus dans la base du 4 novembre; la raison (rejet ou requalification de
  l’avis) n’a pas été vérifiée.
- **Aucune sévérité modifiée** sur les détections communes.

98 + 28 − 2 = 124. Les fiches 01 à 21 restent fondées sur les 98 détections
du 20 octobre; les 28 nouvelles sont triées (exécution, atteignabilité,
décision) dans la fiche [22](analysis/22-nouvelles-detections.md).
Détail : `reports/contre-audit/comparaison-initial-vs-rescan.json`.

## 6. Contrôle CI : ne bloquer que les nouvelles CRITICAL/HIGH

Le workflow `.github/workflows/audit-trivy.yml` du fork bloque une PR si
`trivy fs` (dépôt) ou `trivy image` (image construite) trouve une
vulnérabilité CRITICAL/HIGH **corrigeable** (`--ignore-unfixed`) ou un
secret, **en dehors** de la ligne de base `.trivyignore.yaml`.

Ligne de base : **28 couples (avis, paquet@version)** et une clé.

- Ce sont les CRITICAL/HIGH corrigeables trouvées par les deux scans sur
  l’image et le dépôt verrouillés (identiques des deux côtés) : 6 CRITICAL
  et 22 HIGH. Les 31 CRITICAL/HIGH de la section 4 comprennent en plus
  3 CRITICAL **sans version corrigée publiée** (`decompress@4.2.1` :
  CVE-2026-101894, CVE-2026-53486; `marsdb@0.6.11` : GHSA-5mrr-rgp6-x4gr,
  fiches 05 et 07). `--ignore-unfixed` ne les fait pas bloquer, et ne
  bloquerait pas non plus une nouvelle CRITICAL sans correctif : ces cas
  restent à suivre dans les fiches, pas dans la CI.
- Il ne suffisait pas d’ignorer les CRITICAL restantes : les 22 HIGH
  corrigeables auraient fait échouer chaque PR.
- Chaque entrée vise un **purl** (`pkg:npm/tar@6.2.1`…), pas seulement un
  identifiant : la même CVE sur un autre paquet ou une autre version bloque.
- Chaque entrée renvoie à sa fiche (02 à 15). Les avis apparus après le
  20 octobre (`body-parser`, `multer`, `undici`, `decode-uri-component`)
  portent le tri de la fiche [22](analysis/22-nouvelles-detections.md) :
  utilisé à l’exécution, atteignable, décision. Toutes les entrées
  **expirent le 31 décembre 2026**.
- Secret : la clé du défi `iacLeakedKeyChallenge` (`private-key`, deux
  fichiers Terraform et sa copie dans l’image), distincte de la clé JWT.

Vérification locale (Trivy 0.76.0, même base, mêmes options que la CI) :

| Ignore utilisé | `trivy fs` | `trivy image` |
|---|---|---|
| `.trivyignore.yaml` | sortie 0 | sortie 0 |
| même fichier sans l’entrée `multer` CVE-2026-113872 | **sortie 1**, 1 HIGH signalée | **sortie 1**, 1 HIGH signalée |

Limite : la base Trivy est téléchargée à chaque exécution. Un avis publié
demain sur un paquet existant fera échouer des PR qui n’y sont pour rien; il
faudra alors le corriger ou l’ajouter à la ligne de base avec sa
justification. Comparer au scan de la branche cible éviterait cet effet,
mais n’est pas mis en place.

Premier passage sur GitHub : run
[41918462043](https://github.com/othmane1244/juice-shop/actions/runs/41918462043)
du 4 novembre 2026 sur `f99357b`, les deux jobs réussis (fichiers 25 s,
image 3 min 10 s).

### Workflows hérités du projet amont

Le fork contient 16 workflows : `audit-trivy.yml` et les 15 du dépôt
`juice-shop/juice-shop`. Au premier push, quatre se sont lancés : « Audit Trivy », « CodeQL Scan »,
« CI/CD Pipeline » et « Let me lint:fix that for you ». Le 4 novembre
2026, seuls **Audit Trivy** et **CodeQL Scan** sont gardés actifs :

| Workflow | État | Raison |
|---|---|---|
| `audit-trivy.yml` | actif | Contrôle de l’audit. |
| `codeql-analysis.yml` | actif | SAST complémentaire. Lecture du code; écrit seulement des alertes dans l’onglet Security (`security-events: write`). |
| `ci.yml` (CI/CD Pipeline) | **désactivé** (`gh workflow disable`), run en cours annulé | Pipeline amont : tests, publication et déploiement prévus pour `juice-shop/juice-shop`; ses tests de défis JWT échouent par construction. |
| `lint-fixer.yml` | **désactivé** | Peut **committer** sur la branche poussée (`git-auto-commit-action`). |

Le 4 novembre, les 12 autres fichiers n’étaient pas enregistrés par GitHub,
et l’API ne permet pas de désactiver un workflow non enregistré. Ce
document indiquait alors que leurs déclencheurs ne surviendraient pas et que
les planifications étaient désactivées sur un fork. **C’était faux** :

- le 5 novembre, le passage de la branche par défaut à `audit/corrections`
  (préparation de Jit) a enregistré **tous** les workflows hérités;
- les workflows planifiés « Close stale issues and PR » et « Lock Threads »
  se sont **exécutés** (sans effet constaté : aucune issue ni PR verrouillée
  ou marquée périmée);
- à l’ouverture de la PR [#1 du fork](https://github.com/othmane1244/juice-shop/pull/1),
  « PR Compliance Check » (`pull_request_target`) l’a **fermée**, lui a
  ajouté les labels `invalid` et `spam` et a posté un commentaire de refus.
  La PR a été rouverte et les labels retirés; le commentaire du bot est
  conservé comme trace.

Le 5 novembre 2026, **tous les workflows hérités sauf CodeQL sont
désactivés** (`gh workflow disable`, 14 workflows sur 15). Restent actifs :

| Workflow | Rôle |
|---|---|
| `audit-trivy.yml` | Contrôle bloquant de l’audit (Trivy). |
| `codeql-analysis.yml` | SAST complémentaire, alertes dans l’onglet Security. |
| `plan-jit-oss.yml` | Reproduction open source du plan Jit, non bloquante ([comparaison](jit/comparaison-trivy-plan-jit.md)). |

Contrôle : `gh api repos/othmane1244/juice-shop/actions/workflows --jq '.workflows[] | [.state,.name] | @tsv'`.

## 7. Risques résiduels acceptés

Le 4 novembre 2026, le responsable de l’audit a accepté la ligne de base de
28 exceptions du `.trivyignore.yaml`. S’y ajoutent les risques suivants,
que la CI **ne bloque pas** par construction.

### Règle « pas de correctif = pas de blocage »

Les contrôles bloquants utilisent `--ignore-unfixed` : une vulnérabilité
sans version corrigée publiée ne fait jamais échouer une PR, quelle que soit
sa sévérité, **y compris une nouvelle CRITICAL**. Raison : l’auteur d’une PR
ne peut pas la corriger par une mise à jour, et un blocage permanent rendrait
la CI inutilisable. Contrepartie : ces vulnérabilités restent visibles dans
les rapports complets (artefacts `trivy-fs` et `trivy-image` de chaque run)
et doivent être suivies dans les fiches, pas dans la CI.

### Les 3 CRITICAL sans correctif

| Paquet | Avis | Fiche | Pourquoi le risque est accepté pour l’instant | Condition de réexamen |
|---|---|---|---|---|
| `decompress` 4.2.1 | CVE-2026-101894, CVE-2026-53486 | [05](analysis/05-archives.md) | Chargé au démarrage (relevé de la fiche 22) par le téléchargement des fichiers de personnalisation; aucune extraction observée et aucun import ni appel depuis une route (fiche 05). | Version corrigée publiée, ou extraction d’une archive d’origine externe. |
| `marsdb` 0.6.11 | GHSA-5mrr-rgp6-x4gr | [07](analysis/07-marsdb.md) | **Atteignable** : MarsDB reçoit des paramètres de routes et construit des sélecteurs `$where` passés au constructeur `Function` (fiche 21, P2). C’est le mécanisme des défis NoSQL volontaires de Juice Shop. L’avis couvre toutes les versions et le dépôt MarsDB est archivé : **aucun correctif n’existera**. Risque accepté **uniquement** parce que l’application est une cible d’entraînement non exposée. | Remplacement de MarsDB ou suppression des routes concernées; à planifier hors de cette série. Bloquant pour tout déploiement exposé. |

Également accepté sans correctif : `hbs` 4.3.1, CVE-2021-32822 (MEDIUM,
atteignable authentifié par le champ `layout` de `/dataerasure`, fiche
[22](analysis/22-nouvelles-detections.md)), et les avis Debian `gcc-14` et
`libc6` de la même fiche.

### Révision

Toutes les exceptions expirent le **31 décembre 2026** : la CI échoue alors
et chaque entrée doit être corrigée ou prolongée avec un motif daté. Les
risques sans correctif ci-dessus sont réexaminés à la même date.

## 8. Limites et risques résiduels

- **Défis Juice Shop désactivés** : « Unsigned JWT » et « Forged Signed JWT »
  ne peuvent plus être résolus, et le test Cypress
  `test/cypress/e2e/forgedJwt.spec.ts` échouera. C’est l’effet attendu dans
  un fork d’audit; ce n’est pas proposable tel quel au projet amont.
- **Clé éphémère par défaut** : sans `JWT_PRIVATE_KEY(_FILE)`, la clé change à
  chaque démarrage et tous les jetons sont invalidés; avec plusieurs
  instances, chacune aurait sa clé. En production, fournir la clé par un
  secret d’exécution.
- **Pas de révocation** : un jeton volé reste valide jusqu’à 6 h.
- **Étape de build non épinglée** : l’image `node:24` du stade `installer`
  n’est pas figée par digest. Elle n’entre pas dans l’image finale, mais sa
  version de npm pourrait influencer `npm dedupe`.
- **Clés dans l’historique** : le commit de base `v20.3.0` contient
  l’ancienne clé JWT (`lib/insecurity.ts`), publique depuis des années dans
  le dépôt amont, retirée par les corrections et désormais refusée (401).
  `terraform/networking.tf` et `infrastructure/terraform/networking.tf`
  contiennent une autre clé, volontaire (défi `iacLeakedKeyChallenge`),
  distincte de la clé JWT. Les commits de l’audit n’ajoutent aucune clé.
