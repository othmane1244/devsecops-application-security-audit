# Suivi des détections Trivy

## Sources et totaux recalculés

Les nombres ci-dessous ont été recalculés à partir des objets `Results[].Vulnerabilities[]`, sans modification des JSON.

| Rapport | Date `CreatedAt` | Détections | CRITICAL | HIGH | MEDIUM | LOW | Identifiants textuels distincts |
|---|---|---:|---:|---:|---:|---:|---:|
| Initial — `reports/trivy-image-initial.json`, conservé sur `docs/project-readme` | `2026-10-20T11:28:17.521956103Z` | **98** | 11 | 27 | 49 | 11 | **87** |
| Filtre HIGH/CRITICAL — `reports/trivy-image-high-critical.json` | `2026-10-21T14:42:43.231675625Z` | **38** | 11 | 27 | 0 | 0 | **35** |

Le rapport initial compte 29 installations signalées : 6 paquets du système Debian et 23 installations Node.js. Les entrées Debian n’ont pas de `PkgPath` de fichier dans le JSON; leur chemin est donc consigné comme absent et leur `Target` est fourni. Pour les dépendances Node.js, le chemin est celui du rapport.

### Identifiants et alias

Les totaux de la table comptent les **détections**, puis les **chaînes d’identifiant distinctes** telles qu’elles figurent dans le rapport. Des mêmes identifiants peuvent apparaître sur plusieurs installations (par exemple les deux copies de jsonwebtoken, ou des paquets Debian partageant un avis); ces occurrences ne sont pas des alias.

Les analyses confirment trois paires d’alias dans le rapport initial :

- `NSWG-ECO-17` = `CVE-2015-9235` pour jsonwebtoken, sur chacune de ses deux installations;
- `NSWG-ECO-154` = `CVE-2017-16016` pour sanitize-html;
- `NSWG-ECO-428` = `GHSA-rvg8-pwq2-xj7q` pour base64url.

Le filtre HIGH/CRITICAL ne contient que la première paire. À titre de rapprochement des libellés, ces alias donnent 84 identifiants d’avis canoniques dans le rapport initial et 34 dans le filtre. Ce ne sont pas des comptes de vulnérabilités exploitables ni de scénarios indépendants; les détections d’origine restent conservées dans les JSON.

## Inventaire par installation

Comptage par gravité dans le rapport initial : `C/H/M/L` = `CRITICAL/HIGH/MEDIUM/LOW`. La colonne « Filtre H/C » donne le nombre de détections conservées par le rapport HIGH/CRITICAL. « Analysé » décrit l’avancement documentaire et statique; cela ne signifie pas qu’une vulnérabilité exploitable a été confirmée.

| Installation signalée (version) | Chemin / cible rapportée | Initial C/H/M/L | Filtre H/C | Document associé | Statut | Question ouverte / prochaine vérification utile |
|---|---|---:|---:|---|---|---|
| gcc-14-base 14.2.0-19 | Debian 13.7; `PkgPath` absent | 0/0/2/0 | 0 | — | À examiner | Rapprocher CVE-2026-102010 et CVE-2026-95619 des avis Debian 13.7 et de l’état du paquet dans cette image. |
| libc6 2.41-12+deb13u4 | Debian 13.7; `PkgPath` absent | 0/0/13/8 | 0 | — | À examiner | Vérifier les 21 avis dans les données Debian et distinguer les versions corrigées rétroportées. |
| libgcc-s1 14.2.0-19 | Debian 13.7; `PkgPath` absent | 0/0/2/0 | 0 | — | À examiner | Même avis gcc-14-base; confirmer les métadonnées de paquet et les correctifs Debian. |
| libgomp1 14.2.0-19 | Debian 13.7; `PkgPath` absent | 0/0/2/0 | 0 | — | À examiner | Même avis gcc-14-base; confirmer les métadonnées de paquet et les correctifs Debian. |
| libstdc++6 14.2.0-19 | Debian 13.7; `PkgPath` absent | 0/0/2/0 | 0 | — | À examiner | Même avis gcc-14-base; confirmer les métadonnées de paquet et les correctifs Debian. |
| zlib1g 1:1.3.dfsg+really1.3.1-1+b1 | Debian 13.7; `PkgPath` absent | 0/0/2/0 | 0 | — | À examiner | Examiner CVE-2026-27171 et CVE-2026-85091 avec les avis Debian et le paquet binaire concerné. |
| @tootallnate/once 1.1.2 | `juice-shop/node_modules/@tootallnate/once/package.json` | 0/0/0/1 | 0 | — | À examiner | Identifier le consommateur, puis vérifier si CVE-2026-3449 dépend d’un usage observable. |
| base64url 0.0.6 | `juice-shop/node_modules/base64url/package.json` | 0/1/1/0 | 1 | [01-authentification.md](01-authentification.md) | Partiellement analysé | Le runtime v24.21.0 écarte le prérequis Node 4 ou antérieur; documenter encore les arguments réellement passés au paquet. |
| basic-ftp 5.3.1 | `juice-shop/node_modules/basic-ftp/package.json` | 0/1/0/0 | 1 | [05-archives.md](05-archives.md) — famille voisine, paquet non couvert | À examiner | Rechercher consommateurs, origine des paramètres de connexion, TLS et chemins liés à CVE-2026-102990. |
| crypto-js 3.3.0 | `juice-shop/node_modules/crypto-js/package.json` | 2/0/0/0 | 2 | [04-crypto-js.md](04-crypto-js.md) | Analysé | Deux alertes rapprochées aux usages indirects PDFKit; garder ouverte la possibilité d’autres consommateurs hors périmètre inspecté. |
| decode-uri-component 0.2.2 | `juice-shop/node_modules/decode-uri-component/package.json` | 0/0/1/0 | 0 | — | À examiner | Trouver les appels et déterminer si des URI contrôlées atteignent CVE-2026-45822. |
| decompress 4.2.1 | `juice-shop/node_modules/decompress/package.json` | 2/0/2/0 | 2 | [05-archives.md](05-archives.md) | Analysé | L’usage d’extraction n’a pas été observé dans les appels applicatifs; confirmer si d’autres scripts runtime l’appellent hors du périmètre parcouru. |
| express-jwt 0.1.3 | `juice-shop/node_modules/express-jwt/package.json` | 0/1/0/0 | 1 | [01-authentification.md](01-authentification.md) | Analysé | L’avis exige un fournisseur dynamique de clés; aucun n’a été trouvé. Une éventuelle configuration runtime hors image reste à exclure. |
| file-type 16.5.4 | `juice-shop/node_modules/file-type/package.json` | 0/0/1/0 | 0 | — | À examiner | Identifier les appels, la provenance des octets et les contrôles de type associés à CVE-2026-31808. |
| got 8.3.2 | `juice-shop/node_modules/got/package.json` | 0/0/1/0 | 0 | — | À examiner | Identifier consommateurs et destinations HTTP; vérifier les conditions de CVE-2022-33987 dans les options réellement utilisées. |
| handlebars 4.7.9 | `juice-shop/node_modules/handlebars/package.json` | 2/0/1/0 | 2 | [06-handlebars.md](06-handlebars.md) | Analysé | CVE-2026-106445 : établir si un autre chemin permet de contrôler le contenu du fichier sélectionné par `layout` et le contexte requis; le contrôle du chemin seul est observé. |
| http-cache-semantics 3.8.1 | `juice-shop/node_modules/http-cache-semantics/package.json` | 0/2/0/0 | 2 | — | À examiner | Identifier les consommateurs et vérifier les en-têtes/options atteignables pour CVE-2022-25881 et CVE-2026-93748. |
| jsonwebtoken 0.1.0 | `juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json` | 1/2/2/0 | 3 | [01-authentification.md](01-authentification.md) | Partiellement analysé | L’analyse couvre les avis HIGH/CRITICAL; approfondir CVE-2022-23540 et CVE-2022-23541, détectées MEDIUM dans le rapport initial. |
| jsonwebtoken 0.4.0 | `juice-shop/node_modules/jsonwebtoken/package.json` | 1/2/2/0 | 3 | [01-authentification.md](01-authentification.md) | Partiellement analysé | L’analyse couvre les avis HIGH/CRITICAL; approfondir CVE-2022-23540 et CVE-2022-23541, détectées MEDIUM dans le rapport initial. |
| jws 0.2.6 | `juice-shop/node_modules/jws/package.json` | 0/2/0/0 | 2 | [01-authentification.md](01-authentification.md) | Analysé | Aucun consommateur `createVerify()` n’a été trouvé; maintenir cette conclusion limitée au périmètre inspecté. |
| lodash 2.4.2 | `juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json` | 1/2/1/1 | 3 | [02-lodash.md](02-lodash.md) | Analysé | Vérifier que l’absence d’appels concernés dans les consommateurs inspectés couvre bien toutes les extensions de code chargées par l’image. |
| marsdb 0.6.11 | `juice-shop/node_modules/marsdb/package.json` | 1/0/0/0 | 1 | [07-marsdb.md](07-marsdb.md) | Analysé | Les expressions contrôlables dépendent des challenges; confirmer le mode effectif du service si l’applicabilité à l’instance est requise. |
| messageformat 2.3.0 | `juice-shop/node_modules/messageformat/package.json` | 0/0/0/1 | 0 | — | À examiner | Identifier les modèles/locales contrôlables et vérifier les conditions de CVE-2025-57349. |
| minimatch 3.0.5 | `juice-shop/node_modules/replace/node_modules/minimatch/package.json` | 0/3/0/0 | 3 | [05-archives.md](05-archives.md) — famille voisine, paquet non couvert | À examiner | Identifier les consommateurs, les motifs de glob et leur provenance pour les trois CVE signalées. |
| moment 2.0.0 | `juice-shop/node_modules/express-jwt/node_modules/moment/package.json` | 0/2/1/0 | 2 | [01-authentification.md](01-authentification.md) — dépendance imbriquée, non couverte | À examiner | Repérer les consommateurs de cette copie précise et rapprocher les trois avis des formats/entrées utilisés. |
| notevil 1.3.3 | `juice-shop/node_modules/notevil/package.json` | 0/0/1/0 | 0 | — | À examiner | Rechercher les appels à l’évaluateur et vérifier la provenance de l’expression pour CVE-2021-23771. |
| sanitize-html 1.4.2 | `juice-shop/node_modules/sanitize-html/package.json` | 0/1/8/0 | 1 | [03-sanitize-html.md](03-sanitize-html.md) | Analysé | Le chemin ReDoS et les options sont documentés; l’impact runtime n’a volontairement pas été testé. |
| tar 6.2.1 | `juice-shop/node_modules/sqlite3/node_modules/tar/package.json` | 1/8/3/0 | 9 | [05-archives.md](05-archives.md) | Analysé | Les appels connus sont au build; la branche de construction et les archives effectivement utilisées à la création de l’image ne sont pas toutes établies. |
| uuid 8.3.2 | `juice-shop/node_modules/uuid/package.json` | 0/0/1/0 | 0 | — | À examiner | Identifier les appels, versions d’API et données affectées par CVE-2026-41907. |

## Avancement et ordre utile

Les documents 01–07 couvrent les familles authentification, lodash, sanitize-html, crypto-js, decompress/tar, Handlebars et MarsDB. Les analyses sont statiques et peuvent être marquées « analysé » même lorsque l’applicabilité demeure conditionnelle ou inconnue. Les installations sans document dédié et les alertes omises par le périmètre HIGH/CRITICAL restent à traiter.

Prochaine vérification documentaire utile : traiter les paquets HIGH/CRITICAL sans analyse dédiée (`basic-ftp`, `http-cache-semantics`, `minimatch`, `moment`), puis les alertes restantes du rapport initial et les six paquets Debian. Les rapports JSON originaux sont préservés; ce suivi ne recommande ni n’applique de correction.
