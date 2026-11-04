# Contre-audit — corrections JWT, `file-type` et `HEALTHCHECK`

État au 4 novembre 2026. Cette fiche vérifie les corrections appliquées dans
le fork Juice Shop (branche `audit/corrections`) et compare l’image corrigée
à l’image d’origine avec **les mêmes commandes et la même base Trivy**.

## 1. Ce qui a été comparé

| | Avant | Après |
|---|---|---|
| Image | `bkimminich/juice-shop:v20.3.0` | `juice-shop-corrige:audit`, construite depuis le fork |
| Source | tag `v20.3.0` | commit `d629292` (corrections) sur `v20.3.0` |
| Identifiant | ImageID `4060…823c` (voir [identite-image.md](identite-image.md)) | index `08bc8bb3…a8a`, config `5f700edc…7232` |
| Rapport Trivy | `reports/trivy-image-v20.3.0-rescan.json` | `reports/trivy-image-corrige.json` |

Les deux scans ont été faits le 4 novembre 2026, à quelques secondes
d’intervalle, avec Trivy `0.76.0` (image épinglée par digest
`sha256:2416d1f7…d222`) et une base téléchargée une seule fois juste avant
(`--skip-db-update` ensuite). L’image d’origine a été **rescannée** au lieu
de reprendre `trivy-image-initial.json` (29 octobre) : la base a changé
depuis, et la comparer à un scan du jour mélangerait deux bases.
`trivy-image-initial.json` n’est pas modifié.

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

Le test du jeton expiré a été fait sur un troisième conteneur démarré avec
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
| Tests unitaires serveur (`npm run test:server`, Windows) | — | 417 réussis, 0 échec, 3 ignorés |
| `tsc --noEmit`, ESLint sur les fichiers modifiés | — | sans erreur |

Quatre tests unitaires vérifiaient que les attaques JWT **réussissaient**
(défis `jwtUnsignedChallenge`, `jwtForgedChallenge`), un autre utilisait un
jeton signé par l’ancienne clé, un dernier un HMAC fixe dérivé de cette clé.
Ils ont été inversés ou réécrits (commit `11976c4` du fork). Les deux tests
HS256 étaient ignorés sous Windows; ils s’exécutent maintenant partout.

## 4. Trivy avant / après

Unité : couple (vulnérabilité, paquet, version installée), même méthode des
deux côtés. Ce décompte n’est pas celui des « 98 détections » de
[20](analysis/20-bilan-scan-initial.md), qui portait sur le scan initial.

| Sévérité | Avant | Après | Écart |
|---|---:|---:|---:|
| CRITICAL | 11 | 7 | −4 |
| HIGH | 32 | 17 | −15 |
| MEDIUM | 69 | 58 | −11 |
| LOW | 11 | 11 | 0 |
| UNKNOWN | 1 | 0 | −1 |
| **Total** | **124** | **93** | **−31** |

En couples (vulnérabilité, paquet) sans la version : 119 → 93, 26
disparitions, **aucune nouvelle vulnérabilité**. Le seul « ajout » brut est
CVE-2021-32822 sur `hbs`, déjà présente avant : `hbs` passe de 4.3.1 à 4.4.0,
non corrigé dans les deux cas.

### Ce qui revient aux corrections, et ce qui n’y revient pas

Le fork n’a pas de `package-lock.json` : `npm install` résout les plages `^`
au jour du build. Une partie de la baisse vient donc de mises à jour qui ne
sont **pas** des corrections de l’audit. Sur les 26 disparitions :

- **14 sont dues aux corrections** :
  - `jsonwebtoken` 0.4.0 et 0.1.0 (CVE-2015-9235 CRITICAL, CVE-2022-23539,
    NSWG-ECO-17, CVE-2022-23540, CVE-2022-23541);
  - `jws` 0.2.6 (CVE-2016-1000223, CVE-2025-65945);
  - `express-jwt` 0.1.3 (CVE-2020-15084);
  - `file-type` 16.5.4 (CVE-2026-31808);
  - dépendances transitives des anciennes bibliothèques JWT, vérifiées dans
    l’image d’origine : `moment@2.0.0` sous `express-jwt/node_modules`
    (CVE-2017-18214, CVE-2022-24785, CVE-2016-4055) et `base64url@0.0.6`
    utilisé par `jws` 0.2.x (NSWG-ECO-428, GHSA-rvg8-pwq2-xj7q).
- **12 viennent de la résolution du jour** (non attribuables à l’audit) :
  `handlebars` 4.7.9 (deux CRITICAL), `undici` 6.29.0 (cinq), `multer`,
  `qs`, `body-parser`, et `ca-certificates` (DSA-6572-1) de l’image
  distroless de base, téléchargée à nouveau.

Les 7 CRITICAL restantes n’étaient pas dans le périmètre de cette série de
corrections (voir [21](analysis/21-synthese-des-risques.md)).

## 5. Limites et risques résiduels

- **Build non reproductible** : sans fichier de verrouillage, deux builds du
  même commit peuvent différer. Il faut committer un `package-lock.json` dans
  le fork pour que les contre-audits suivants mesurent seulement les
  corrections.
- **Défis Juice Shop désactivés** : « Unsigned JWT » et « Forged Signed JWT »
  ne peuvent plus être résolus, et le test Cypress
  `test/cypress/e2e/forgedJwt.spec.ts` échouera. C’est l’effet attendu dans
  un fork d’audit; ce n’est pas proposable tel quel au projet amont.
- **Clé éphémère par défaut** : sans `JWT_PRIVATE_KEY(_FILE)`, la clé change à
  chaque démarrage et tous les jetons sont invalidés; avec plusieurs
  instances, chacune aurait sa clé. En production, fournir la clé par un
  secret d’exécution.
- **Pas de révocation** : un jeton volé reste valide jusqu’à 6 h.
- Les tests unitaires ont tourné sous Windows; les tests d’intégration
  `test/api` et Cypress n’ont pas été exécutés.
- Le workflow `.github/workflows/audit-trivy.yml` du fork n’a pas encore
  tourné : le fork n’est pas publié sur GitHub (son `origin` pointe encore
  vers le dépôt amont).
