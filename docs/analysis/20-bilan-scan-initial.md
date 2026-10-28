# 20 — Bilan du scan initial

## Portée et résultat du rapprochement

Le rapport initial `reports/trivy-image-initial.json` a été créé le **20 octobre 2026 à 11:28:17 UTC** par Trivy 0.76.0. Il contient **98 occurrences de détection**, réparties entre 29 installations (6 paquets Debian et 23 installations Node.js). Chaque occurrence est identifiée ci-dessous par son numéro d’ordre dans le rapport et son numéro de ligne source; elle est rattachée à la fiche d’analyse qui examine le paquet et l’avis. Ce rapprochement mesure la couverture documentaire, pas l’exposition ni l’exploitabilité.

Le rapport filtré `reports/trivy-image-high-critical.json`, créé le 21 octobre, contient exactement les **38 occurrences CRITICAL/HIGH** du rapport initial. La comparaison des clés (installation, version et identifiant) ne révèle ni doublon, ni finding supplémentaire, ni finding H/C omis. Il comporte 11 CRITICAL et 27 HIGH; il ne prétend pas couvrir les 60 occurrences MEDIUM/LOW.

| Rapport initial | Occurrences | CRITICAL | HIGH | MEDIUM | LOW | Identifiants textuels distincts |
|---|---:|---:|---:|---:|---:|---:|
| Initial | 98 | 11 | 27 | 49 | 11 | 87 |
| Filtre HIGH/CRITICAL | 38 | 11 | 27 | 0 | 0 | 35 |

Les 87 identifiants textuels ne sont pas 87 avis canoniques indépendants. Le rapport contient trois alias établis dans les fiches : `NSWG-ECO-17` / `CVE-2015-9235` (deux installations jsonwebtoken), `NSWG-ECO-154` / `CVE-2017-16016` (sanitize-html) et `NSWG-ECO-428` / `GHSA-rvg8-pwq2-xj7q` (base64url). Après ce rapprochement de libellés : 84 identifiants canoniques dans le rapport initial, 34 dans le filtre H/C. Les 98 occurrences d’origine restent toutefois distinctes dans le tableau de rapprochement.

## Totaux par installation

`C/H/M/L` signifie CRITICAL/HIGH/MEDIUM/LOW. `H/C filtré` est le nombre d’occurrences de cette installation présentes dans le rapport HIGH/CRITICAL. Le statut documentaire signifie qu’une fiche est associée; il ne signifie pas que les conditions de l’avis sont réunies.

| Installation (version) | C/H/M/L | H/C filtré | Analyse associée |
|---|---:|---:|---|
| gcc-14-base 14.2.0-19 | 0/0/2/0 | 0 | [19](19-paquets-debian.md) |
| libc6 2.41-12+deb13u4 | 0/0/13/8 | 0 | [19](19-paquets-debian.md) |
| libgcc-s1 14.2.0-19 | 0/0/2/0 | 0 | [19](19-paquets-debian.md) |
| libgomp1 14.2.0-19 | 0/0/2/0 | 0 | [19](19-paquets-debian.md) |
| libstdc++6 14.2.0-19 | 0/0/2/0 | 0 | [19](19-paquets-debian.md) |
| zlib1g 1:1.3.dfsg+really1.3.1-1+b1 | 0/0/2/0 | 0 | [19](19-paquets-debian.md) |
| @tootallnate/once 1.1.2 | 0/0/0/1 | 0 | [18](18-once.md) |
| base64url 0.0.6 | 0/1/1/0 | 1 | [01](01-authentification.md) |
| basic-ftp 5.3.1 | 0/1/0/0 | 1 | [08](08-basic-ftp.md) |
| crypto-js 3.3.0 | 2/0/0/0 | 2 | [04](04-crypto-js.md) |
| decode-uri-component 0.2.2 | 0/0/1/0 | 0 | [15](15-decode-uri-component.md) |
| decompress 4.2.1 | 2/0/2/0 | 2 | [05](05-archives.md) |
| express-jwt 0.1.3 | 0/1/0/0 | 1 | [01](01-authentification.md) |
| file-type 16.5.4 | 0/0/1/0 | 0 | [13](13-file-type.md) |
| got 8.3.2 | 0/0/1/0 | 0 | [14](14-got.md) |
| handlebars 4.7.9 | 2/0/1/0 | 2 | [06](06-handlebars.md) |
| http-cache-semantics 3.8.1 | 0/2/0/0 | 2 | [09](09-http-cache-semantics.md) |
| jsonwebtoken 0.1.0 | 1/2/2/0 | 3 | [01](01-authentification.md) |
| jsonwebtoken 0.4.0 | 1/2/2/0 | 3 | [01](01-authentification.md) |
| jws 0.2.6 | 0/2/0/0 | 2 | [01](01-authentification.md) |
| lodash 2.4.2 | 1/2/1/1 | 3 | [02](02-lodash.md) |
| marsdb 0.6.11 | 1/0/0/0 | 1 | [07](07-marsdb.md) |
| messageformat 2.3.0 | 0/0/0/1 | 0 | [17](17-messageformat.md) |
| minimatch 3.0.5 | 0/3/0/0 | 3 | [10](10-minimatch.md) |
| moment 2.0.0 | 0/2/1/0 | 2 | [11](11-moment.md) |
| notevil 1.3.3 | 0/0/1/0 | 0 | [12](12-notevil.md) |
| sanitize-html 1.4.2 | 0/1/8/0 | 1 | [03](03-sanitize-html.md) |
| tar 6.2.1 | 1/8/3/0 | 9 | [05](05-archives.md) |
| uuid 8.3.2 | 0/0/1/0 | 0 | [16](16-uuid.md) |

## Rapprochement individuel des 98 occurrences

Chaque ligne correspond à une occurrence `Results[].Vulnerabilities[]` du rapport initial. Le lien de ligne pointe vers son enregistrement source JSON. Le lien d’analyse identifie le document qui traite cette installation et son ou ses avis; lorsque plusieurs CVE figurent dans une fiche, la fiche les distingue dans sa propre section de détections.

| N° | Sévérité | Installation et version | Identifiant rapporté | Filtre H/C | Ligne JSON | Fiche |
|---:|---|---|---|---|---:|---|
| 001 | MEDIUM | gcc-14-base 14.2.0-19 | CVE-2026-102010 | — | [2215](../../reports/trivy-image-initial.json#L2215) | [19](19-paquets-debian.md) |
| 002 | MEDIUM | gcc-14-base 14.2.0-19 | CVE-2026-95619 | — | [2262](../../reports/trivy-image-initial.json#L2262) | [19](19-paquets-debian.md) |
| 003 | MEDIUM | libc6 2.41-12+deb13u4 | CVE-2026-18374 | — | [2311](../../reports/trivy-image-initial.json#L2311) | [19](19-paquets-debian.md) |
| 004 | MEDIUM | libc6 2.41-12+deb13u4 | CVE-2026-19499 | — | [2383](../../reports/trivy-image-initial.json#L2383) | [19](19-paquets-debian.md) |
| 005 | MEDIUM | libc6 2.41-12+deb13u4 | CVE-2026-19542 | — | [2446](../../reports/trivy-image-initial.json#L2446) | [19](19-paquets-debian.md) |
| 006 | MEDIUM | libc6 2.41-12+deb13u4 | CVE-2026-5435 | — | [2518](../../reports/trivy-image-initial.json#L2518) | [19](19-paquets-debian.md) |
| 007 | MEDIUM | libc6 2.41-12+deb13u4 | CVE-2026-6238 | — | [2588](../../reports/trivy-image-initial.json#L2588) | [19](19-paquets-debian.md) |
| 008 | MEDIUM | libc6 2.41-12+deb13u4 | CVE-2026-6368 | — | [2658](../../reports/trivy-image-initial.json#L2658) | [19](19-paquets-debian.md) |
| 009 | MEDIUM | libc6 2.41-12+deb13u4 | CVE-2026-6791 | — | [2727](../../reports/trivy-image-initial.json#L2727) | [19](19-paquets-debian.md) |
| 010 | MEDIUM | libc6 2.41-12+deb13u4 | CVE-2026-77117 | — | [2795](../../reports/trivy-image-initial.json#L2795) | [19](19-paquets-debian.md) |
| 011 | MEDIUM | libc6 2.41-12+deb13u4 | CVE-2026-80489 | — | [2867](../../reports/trivy-image-initial.json#L2867) | [19](19-paquets-debian.md) |
| 012 | MEDIUM | libc6 2.41-12+deb13u4 | CVE-2026-8674 | — | [2939](../../reports/trivy-image-initial.json#L2939) | [19](19-paquets-debian.md) |
| 013 | MEDIUM | libc6 2.41-12+deb13u4 | CVE-2026-86805 | — | [2988](../../reports/trivy-image-initial.json#L2988) | [19](19-paquets-debian.md) |
| 014 | MEDIUM | libc6 2.41-12+deb13u4 | CVE-2026-89092 | — | [3034](../../reports/trivy-image-initial.json#L3034) | [19](19-paquets-debian.md) |
| 015 | MEDIUM | libc6 2.41-12+deb13u4 | CVE-2026-95818 | — | [3083](../../reports/trivy-image-initial.json#L3083) | [19](19-paquets-debian.md) |
| 016 | LOW | libc6 2.41-12+deb13u4 | CVE-2010-4756 | — | [3129](../../reports/trivy-image-initial.json#L3129) | [19](19-paquets-debian.md) |
| 017 | LOW | libc6 2.41-12+deb13u4 | CVE-2018-20796 | — | [3186](../../reports/trivy-image-initial.json#L3186) | [19](19-paquets-debian.md) |
| 018 | LOW | libc6 2.41-12+deb13u4 | CVE-2019-1010022 | — | [3245](../../reports/trivy-image-initial.json#L3245) | [19](19-paquets-debian.md) |
| 019 | LOW | libc6 2.41-12+deb13u4 | CVE-2019-1010023 | — | [3298](../../reports/trivy-image-initial.json#L3298) | [19](19-paquets-debian.md) |
| 020 | LOW | libc6 2.41-12+deb13u4 | CVE-2019-1010024 | — | [3354](../../reports/trivy-image-initial.json#L3354) | [19](19-paquets-debian.md) |
| 021 | LOW | libc6 2.41-12+deb13u4 | CVE-2019-1010025 | — | [3414](../../reports/trivy-image-initial.json#L3414) | [19](19-paquets-debian.md) |
| 022 | LOW | libc6 2.41-12+deb13u4 | CVE-2019-9192 | — | [3473](../../reports/trivy-image-initial.json#L3473) | [19](19-paquets-debian.md) |
| 023 | LOW | libc6 2.41-12+deb13u4 | CVE-2026-97399 | — | [3529](../../reports/trivy-image-initial.json#L3529) | [19](19-paquets-debian.md) |
| 024 | MEDIUM | libgcc-s1 14.2.0-19 | CVE-2026-102010 | — | [3576](../../reports/trivy-image-initial.json#L3576) | [19](19-paquets-debian.md) |
| 025 | MEDIUM | libgcc-s1 14.2.0-19 | CVE-2026-95619 | — | [3623](../../reports/trivy-image-initial.json#L3623) | [19](19-paquets-debian.md) |
| 026 | MEDIUM | libgomp1 14.2.0-19 | CVE-2026-102010 | — | [3672](../../reports/trivy-image-initial.json#L3672) | [19](19-paquets-debian.md) |
| 027 | MEDIUM | libgomp1 14.2.0-19 | CVE-2026-95619 | — | [3719](../../reports/trivy-image-initial.json#L3719) | [19](19-paquets-debian.md) |
| 028 | MEDIUM | libstdc++6 14.2.0-19 | CVE-2026-102010 | — | [3768](../../reports/trivy-image-initial.json#L3768) | [19](19-paquets-debian.md) |
| 029 | MEDIUM | libstdc++6 14.2.0-19 | CVE-2026-95619 | — | [3815](../../reports/trivy-image-initial.json#L3815) | [19](19-paquets-debian.md) |
| 030 | MEDIUM | zlib1g 1:1.3.dfsg+really1.3.1-1+b1 | CVE-2026-27171 | — | [3864](../../reports/trivy-image-initial.json#L3864) | [19](19-paquets-debian.md) |
| 031 | MEDIUM | zlib1g 1:1.3.dfsg+really1.3.1-1+b1 | CVE-2026-85091 | — | [3933](../../reports/trivy-image-initial.json#L3933) | [19](19-paquets-debian.md) |
| 032 | LOW | @tootallnate/once 1.1.2 | CVE-2026-3449 | — | [16870](../../reports/trivy-image-initial.json#L16870) | [18](18-once.md) |
| 033 | HIGH | base64url 0.0.6 | NSWG-ECO-428 | Oui | [16934](../../reports/trivy-image-initial.json#L16934) | [01](01-authentification.md) |
| 034 | MEDIUM | base64url 0.0.6 | GHSA-rvg8-pwq2-xj7q | — | [16969](../../reports/trivy-image-initial.json#L16969) | [01](01-authentification.md) |
| 035 | HIGH | basic-ftp 5.3.1 | CVE-2026-102990 | Oui | [17008](../../reports/trivy-image-initial.json#L17008) | [08](08-basic-ftp.md) |
| 036 | CRITICAL | crypto-js 3.3.0 | CVE-2023-46233 | Oui | [17068](../../reports/trivy-image-initial.json#L17068) | [04](04-crypto-js.md) |
| 037 | CRITICAL | crypto-js 3.3.0 | CVE-2026-71851 | Oui | [17136](../../reports/trivy-image-initial.json#L17136) | [04](04-crypto-js.md) |
| 038 | MEDIUM | decode-uri-component 0.2.2 | CVE-2026-45822 | — | [17197](../../reports/trivy-image-initial.json#L17197) | [15](15-decode-uri-component.md) |
| 039 | CRITICAL | decompress 4.2.1 | CVE-2026-101894 | Oui | [17261](../../reports/trivy-image-initial.json#L17261) | [05](05-archives.md) |
| 040 | CRITICAL | decompress 4.2.1 | CVE-2026-53486 | Oui | [17322](../../reports/trivy-image-initial.json#L17322) | [05](05-archives.md) |
| 041 | MEDIUM | decompress 4.2.1 | CVE-2026-10732 | — | [17389](../../reports/trivy-image-initial.json#L17389) | [05](05-archives.md) |
| 042 | MEDIUM | decompress 4.2.1 | CVE-2026-39243 | — | [17452](../../reports/trivy-image-initial.json#L17452) | [05](05-archives.md) |
| 043 | HIGH | express-jwt 0.1.3 | CVE-2020-15084 | Oui | [17509](../../reports/trivy-image-initial.json#L17509) | [01](01-authentification.md) |
| 044 | MEDIUM | file-type 16.5.4 | CVE-2026-31808 | — | [17567](../../reports/trivy-image-initial.json#L17567) | [13](13-file-type.md) |
| 045 | MEDIUM | got 8.3.2 | CVE-2022-33987 | — | [17625](../../reports/trivy-image-initial.json#L17625) | [14](14-got.md) |
| 046 | CRITICAL | handlebars 4.7.9 | CVE-2026-106445 | Oui | [17727](../../reports/trivy-image-initial.json#L17727) | [06](06-handlebars.md) |
| 047 | CRITICAL | handlebars 4.7.9 | CVE-2026-106446 | Oui | [17789](../../reports/trivy-image-initial.json#L17789) | [06](06-handlebars.md) |
| 048 | MEDIUM | handlebars 4.7.9 | CVE-2026-106444 | — | [17851](../../reports/trivy-image-initial.json#L17851) | [06](06-handlebars.md) |
| 049 | HIGH | http-cache-semantics 3.8.1 | CVE-2022-25881 | Oui | [17912](../../reports/trivy-image-initial.json#L17912) | [09](09-http-cache-semantics.md) |
| 050 | HIGH | http-cache-semantics 3.8.1 | CVE-2026-93748 | Oui | [18011](../../reports/trivy-image-initial.json#L18011) | [09](09-http-cache-semantics.md) |
| 051 | CRITICAL | jsonwebtoken 0.1.0 | CVE-2015-9235 | Oui | [18073](../../reports/trivy-image-initial.json#L18073) | [01](01-authentification.md) |
| 052 | HIGH | jsonwebtoken 0.1.0 | CVE-2022-23539 | Oui | [18139](../../reports/trivy-image-initial.json#L18139) | [01](01-authentification.md) |
| 053 | HIGH | jsonwebtoken 0.1.0 | NSWG-ECO-17 | Oui | [18204](../../reports/trivy-image-initial.json#L18204) | [01](01-authentification.md) |
| 054 | MEDIUM | jsonwebtoken 0.1.0 | CVE-2022-23540 | — | [18239](../../reports/trivy-image-initial.json#L18239) | [01](01-authentification.md) |
| 055 | MEDIUM | jsonwebtoken 0.1.0 | CVE-2022-23541 | — | [18305](../../reports/trivy-image-initial.json#L18305) | [01](01-authentification.md) |
| 056 | CRITICAL | jsonwebtoken 0.4.0 | CVE-2015-9235 | Oui | [18372](../../reports/trivy-image-initial.json#L18372) | [01](01-authentification.md) |
| 057 | HIGH | jsonwebtoken 0.4.0 | CVE-2022-23539 | Oui | [18438](../../reports/trivy-image-initial.json#L18438) | [01](01-authentification.md) |
| 058 | HIGH | jsonwebtoken 0.4.0 | NSWG-ECO-17 | Oui | [18503](../../reports/trivy-image-initial.json#L18503) | [01](01-authentification.md) |
| 059 | MEDIUM | jsonwebtoken 0.4.0 | CVE-2022-23540 | — | [18538](../../reports/trivy-image-initial.json#L18538) | [01](01-authentification.md) |
| 060 | MEDIUM | jsonwebtoken 0.4.0 | CVE-2022-23541 | — | [18604](../../reports/trivy-image-initial.json#L18604) | [01](01-authentification.md) |
| 061 | HIGH | jws 0.2.6 | CVE-2016-1000223 | Oui | [18671](../../reports/trivy-image-initial.json#L18671) | [01](01-authentification.md) |
| 062 | HIGH | jws 0.2.6 | CVE-2025-65945 | Oui | [18718](../../reports/trivy-image-initial.json#L18718) | [01](01-authentification.md) |
| 063 | CRITICAL | lodash 2.4.2 | CVE-2019-10744 | Oui | [18781](../../reports/trivy-image-initial.json#L18781) | [02](02-lodash.md) |
| 064 | HIGH | lodash 2.4.2 | CVE-2018-16487 | Oui | [18857](../../reports/trivy-image-initial.json#L18857) | [02](02-lodash.md) |
| 065 | HIGH | lodash 2.4.2 | CVE-2021-23337 | Oui | [18922](../../reports/trivy-image-initial.json#L18922) | [02](02-lodash.md) |
| 066 | MEDIUM | lodash 2.4.2 | CVE-2026-2950 | — | [19007](../../reports/trivy-image-initial.json#L19007) | [02](02-lodash.md) |
| 067 | LOW | lodash 2.4.2 | CVE-2018-3721 | — | [19075](../../reports/trivy-image-initial.json#L19075) | [02](02-lodash.md) |
| 068 | CRITICAL | marsdb 0.6.11 | GHSA-5mrr-rgp6-x4gr | Oui | [19146](../../reports/trivy-image-initial.json#L19146) | [07](07-marsdb.md) |
| 069 | LOW | messageformat 2.3.0 | CVE-2025-57349 | — | [19182](../../reports/trivy-image-initial.json#L19182) | [17](17-messageformat.md) |
| 070 | HIGH | minimatch 3.0.5 | CVE-2026-26996 | Oui | [19232](../../reports/trivy-image-initial.json#L19232) | [10](10-minimatch.md) |
| 071 | HIGH | minimatch 3.0.5 | CVE-2026-27903 | Oui | [19319](../../reports/trivy-image-initial.json#L19319) | [10](10-minimatch.md) |
| 072 | HIGH | minimatch 3.0.5 | CVE-2026-27904 | Oui | [19379](../../reports/trivy-image-initial.json#L19379) | [10](10-minimatch.md) |
| 073 | HIGH | moment 2.0.0 | CVE-2017-18214 | Oui | [19461](../../reports/trivy-image-initial.json#L19461) | [11](11-moment.md) |
| 074 | HIGH | moment 2.0.0 | CVE-2022-24785 | Oui | [19535](../../reports/trivy-image-initial.json#L19535) | [11](11-moment.md) |
| 075 | MEDIUM | moment 2.0.0 | CVE-2016-4055 | — | [19613](../../reports/trivy-image-initial.json#L19613) | [11](11-moment.md) |
| 076 | MEDIUM | notevil 1.3.3 | CVE-2021-23771 | — | [19688](../../reports/trivy-image-initial.json#L19688) | [12](12-notevil.md) |
| 077 | HIGH | sanitize-html 1.4.2 | CVE-2022-25887 | Oui | [19745](../../reports/trivy-image-initial.json#L19745) | [03](03-sanitize-html.md) |
| 078 | MEDIUM | sanitize-html 1.4.2 | CVE-2016-1000237 | — | [19811](../../reports/trivy-image-initial.json#L19811) | [03](03-sanitize-html.md) |
| 079 | MEDIUM | sanitize-html 1.4.2 | CVE-2017-16016 | — | [19870](../../reports/trivy-image-initial.json#L19870) | [03](03-sanitize-html.md) |
| 080 | MEDIUM | sanitize-html 1.4.2 | CVE-2019-25225 | — | [19928](../../reports/trivy-image-initial.json#L19928) | [03](03-sanitize-html.md) |
| 081 | MEDIUM | sanitize-html 1.4.2 | CVE-2021-26539 | — | [19988](../../reports/trivy-image-initial.json#L19988) | [03](03-sanitize-html.md) |
| 082 | MEDIUM | sanitize-html 1.4.2 | CVE-2021-26540 | — | [20052](../../reports/trivy-image-initial.json#L20052) | [03](03-sanitize-html.md) |
| 083 | MEDIUM | sanitize-html 1.4.2 | CVE-2024-21501 | — | [20114](../../reports/trivy-image-initial.json#L20114) | [03](03-sanitize-html.md) |
| 084 | MEDIUM | sanitize-html 1.4.2 | CVE-2026-63670 | — | [20186](../../reports/trivy-image-initial.json#L20186) | [03](03-sanitize-html.md) |
| 085 | MEDIUM | sanitize-html 1.4.2 | NSWG-ECO-154 | — | [20240](../../reports/trivy-image-initial.json#L20240) | [03](03-sanitize-html.md) |
| 086 | CRITICAL | tar 6.2.1 | CVE-2026-59873 | Oui | [20274](../../reports/trivy-image-initial.json#L20274) | [05](05-archives.md) |
| 087 | HIGH | tar 6.2.1 | CVE-2026-23745 | Oui | [20362](../../reports/trivy-image-initial.json#L20362) | [05](05-archives.md) |
| 088 | HIGH | tar 6.2.1 | CVE-2026-23950 | Oui | [20461](../../reports/trivy-image-initial.json#L20461) | [05](05-archives.md) |
| 089 | HIGH | tar 6.2.1 | CVE-2026-24842 | Oui | [20558](../../reports/trivy-image-initial.json#L20558) | [05](05-archives.md) |
| 090 | HIGH | tar 6.2.1 | CVE-2026-26960 | Oui | [20650](../../reports/trivy-image-initial.json#L20650) | [05](05-archives.md) |
| 091 | HIGH | tar 6.2.1 | CVE-2026-29786 | Oui | [20717](../../reports/trivy-image-initial.json#L20717) | [05](05-archives.md) |
| 092 | HIGH | tar 6.2.1 | CVE-2026-31802 | Oui | [20786](../../reports/trivy-image-initial.json#L20786) | [05](05-archives.md) |
| 093 | HIGH | tar 6.2.1 | CVE-2026-59874 | Oui | [20851](../../reports/trivy-image-initial.json#L20851) | [05](05-archives.md) |
| 094 | HIGH | tar 6.2.1 | CVE-2026-73566 | Oui | [20939](../../reports/trivy-image-initial.json#L20939) | [05](05-archives.md) |
| 095 | MEDIUM | tar 6.2.1 | CVE-2026-53655 | — | [21001](../../reports/trivy-image-initial.json#L21001) | [05](05-archives.md) |
| 096 | MEDIUM | tar 6.2.1 | CVE-2026-59871 | — | [21066](../../reports/trivy-image-initial.json#L21066) | [05](05-archives.md) |
| 097 | MEDIUM | tar 6.2.1 | CVE-2026-59875 | — | [21133](../../reports/trivy-image-initial.json#L21133) | [05](05-archives.md) |
| 098 | MEDIUM | uuid 8.3.2 | CVE-2026-41907 | — | [21195](../../reports/trivy-image-initial.json#L21195) | [16](16-uuid.md) |

## Couverture documentaire et applicabilité

Les **98/98 occurrences** sont rattachées aux fiches 01 à 19. Les fiches traitent les paquets et les avis signalés, mais leur profondeur varie : certains avis sont analysés à partir du code d’une version exacte et d’appels statiques; d’autres restent à un niveau de version, de prérequis ou de Tracker. Les nombres ci-dessus ne sont donc pas un taux d’applicabilité.

**Aucune exploitation n’est démontrée.** Pour plusieurs avis, les fonctions ou conditions sont effectivement observées dans le code sans que cela prouve leur déclenchement dans l’instance. Pour d’autres, un prérequis précis n’a pas été observé dans le chemin examiné. Une telle absence de preuve ne prouve pas l’absence d’un chemin hors du périmètre. En particulier, les 31 findings Debian expriment le statut de paquet rapporté par Trivy et les statuts de suites du Tracker, pas l’exécution dans l’application d’une fonction système vulnérable.

Les principaux états statiques consignés dans les fiches sont :

- **Prérequis absents ou non observés dans les appels inspectés :** PBKDF2 et usage sensible de `WordArray.random` dans les flux étudiés (04); fonctions/motifs précis lodash non atteints dans les consommateurs inspectés (02); AST non fiable et sortie `precompile()` injectée non observés dans les chemins Handlebars étudiés (06); entrée de date/localisation hostile non observée dans les appels Moment documentés (11); `AbortSignal` absent de l’API publiée once 1.1.2 et de l’appel consommateur identifié (18); `buffer`/`offset` absents des appels UUID retrouvés (16). Cela qualifie ces chemins, pas tous les chargements ou usages possibles.
- **Mécanisme ou appel disponible, chaîne conditionnelle :** appels `tar.extract` présents dans la construction/dépendances natives, mais nature et exécution des archives de build non vérifiées (05); analyse de politique `Cache-Control` présente même avec `cache: false`, tandis que la réutilisation de réponses en cache n’a pas lieu dans le chemin d’appel observé (09); expressions évaluées par notevil uniquement si la branche de challenge est active, configuration runtime inconnue (12); l’upload et la limite mémoire de file-type sont documentés, mais l’appel exact du handler au parseur reste non confirmé (13); Got est appelé pour des URL de personnalisation issues de configuration, mais la configuration distante/redirection requise par l’avis n’est pas établie (14–15).
- **Applicabilité explicitement conditionnelle ou contestée :** basic-ftp dépend d’une configuration PAC `pac+ftp` et d’un serveur FTP correspondant, non établis (08); plusieurs vulnérabilités de challenge dépendent des réglages runtime (03, 06–07, 12); le mécanisme GHSA de cache lié à `Set-Cookie` est contesté dans l’analyse, même si le parsing regex séparé est présent (09); CVE-2026-3449 est signalée par Trivy pour once, mais son mécanisme AbortSignal n’est pas confirmé dans le consommateur publié résolu (18).
- **Version/installations, sans confirmation applicative :** pour Debian, plusieurs états `vulnerable` Trixie sont corroborés par le Security Tracker (19), mais cela ne démontre pas qu’un chemin vulnérable est déclenché par l’application. Deux avis glibc restent non vérifiés dans ce Tracker; voir la fiche 19.

## Analyses partielles et vérifications bloquées

| Fiche | Travail documentaire effectué | Vérification restante / limite explicitement conservée |
|---|---|---|
| [01 — authentification](01-authentification.md) | Rapproche les installations imbriquées de jsonwebtoken, express-jwt, jws et base64url et ajoute l’analyse des deux avis MEDIUM jsonwebtoken sur les versions 0.1.0 et 0.4.0. | Fiche marquée partielle : arguments réels de base64url à compléter; conditions complètes de certains anciens avis et configuration de vérification JWT restent inconnues ou limitées au code publié. |
| [03 — sanitize-html](03-sanitize-html.md) | Suit plusieurs appels, options et flux de données, dont les conditions de challenges. | Profil/configuration réellement chargés au runtime et état des challenges non établis; certaines conclusions dépendent des options. |
| [05 — archives](05-archives.md) | Distingue decompress des appels `tar.extract` de build, et suit options et contrôles connus. | Les archives réellement consommées lors du build, leur provenance et les branches d’installation exécutées ne sont pas toutes vérifiées; pas de flux d’archive d’upload observé dans les chemins examinés. |
| [06 — Handlebars](06-handlebars.md) et [07 — MarsDB](07-marsdb.md) | Compare les appels, modèles, entrées et prérequis des avis. | Configuration runtime des challenges/safety mode inconnue; le contrôle d’un chemin ne prouve pas le contrôle du texte du modèle ou de l’AST. |
| [08 — basic-ftp](08-basic-ftp.md) | Suit statiquement le chemin indirect jusqu’à `Client.list()`. | Configuration proxy/PAC effective, URL `pac+ftp` et contrôle du serveur FTP inconnus. |
| [09 — http-cache-semantics](09-http-cache-semantics.md) | Confirme la construction de `CachePolicy` et le parsing d’en-têtes dans le chemin `cache: false`; distingue ce parsing de la lecture/réutilisation d’une entrée. | Pas d’exploitation ReDoS démontrée; l’origine/la contrôlabilité runtime des réponses de téléchargement reste conditionnelle. La conclusion d’avis CVE-2026-93748 reste contestée. |
| [11 — moment](11-moment.md) | Analyse les trois avis, dont la copie 2.0.0 sous express-jwt, et les appels `moment.lang()` / `moment.locale()` publiés. | Docker indisponible : les fichiers exacts embarqués et la configuration runtime n’ont pas été extraits; la preuve d’appel applicatif repose sur les sources publiées versionnées. |
| [12 — notevil](12-notevil.md) | Suit l’expression vers l’évaluateur, les objets accessibles, validations, challenge et limite de temps. | Docker indisponible et activation effective du challenge inconnue; expression contrôlée seulement dans la branche concernée, pas d’exploitation démontrée. |
| [13 — file-type](13-file-type.md) | Compare le parseur ASF et ses prérequis à l’upload documenté et à sa limite mémoire. | Docker indisponible; appel précis du handler au parseur et traitement d’erreur dans les fichiers de l’image non confirmés. |
| [14 — Got](14-got.md), [15 — decode-uri-component](15-decode-uri-component.md), [16 — uuid](16-uuid.md), [17 — messageformat](17-messageformat.md) | Retracent appels et arguments à partir des sources versionnées disponibles et distinguent leur provenance. | Les rapports n’embarquent pas les sources installées; le démon Docker étant indisponible dans ces analyses, certaines conclusions reposent sur des tags/archives publiés et ne vérifient pas bit à bit l’image. Contrôles runtime/configuration restent parfois inconnus. |
| [18 — once](18-once.md) | Examine le code publié exact 1.1.2 et l’appel consommateur publié résolu. | Sources extraites de l’image et branche d’installation SQLite réellement suivie inconnues; la détection reste présente sans mécanisme AbortSignal confirmé. |
| [19 — paquets Debian](19-paquets-debian.md) | Rapproche les 31 occurrences avec les versions Debian complètes et les statuts Trixie consultés. | Tracker mutable : pas d’état historique reconstitué au 20 octobre. CVE-2026-8674 n’a pas de fiche retrouvée; la fiche CVE-2026-89092 ne donne pas le statut de suite utilisé. |

Les autres fiches couvrent statiquement les détections et les chemins étudiés, mais gardent des limites de portée : appels indirects/dynamiques non parcourus, extensions ou consommateurs hors périmètre, données et configuration effectives au runtime, et absence d’une preuve d’exploitation.

## Divergences entre Trivy, avis officiels et code examiné

1. **Comptage et alias.** Les rapports comptent les occurrences, pas des causes indépendantes. Les trois alias cités plus haut doivent être rapprochés pour compter les avis canoniques, sans supprimer aucune des 98 lignes.
2. **Statuts Trivy et version installée.** Un statut `fixed` dans un finding peut signaler l’existence d’une version corrigée, pas que la version installée l’est : les fiches file-type (16.5.4), Got (8.3.2) et messageformat (2.3.0) explicitent cette différence. Pour messageformat, la borne publiée de l’avis `<2.3.0` exclut précisément la copie signalée 2.3.0, contrairement à la lecture simplifiée du finding; voir 17.
3. **`http-cache-semantics`.** Trivy signale CVE-2022-25881 / CVE-2026-93748; 09 distingue le mécanisme regex de parsing (observé avec cache désactivé) de la réutilisation de réponses et rapporte la contestation du mécanisme de fuite décrit par l’avis. Ni parsing présent ni réponse en cache ne valent démonstration d’exploitation.
4. **`once`.** L’avis mentionne l’annulation par AbortSignal; le code publié exact 1.1.2 et l’appel de `http-proxy-agent@4.0.1` examinés n’exposent pas cette option. La détection Trivy est conservée, le mécanisme vulnérable n’est pas confirmé dans cet appel.
5. **`uuid`.** La version publiée 8.3.2 expose aussi des paramètres buffer/offset pour `v4` sans garde de borne explicite selon l’analyse, alors que l’avis se focalise sur les API et conditions décrites. Aucun appel avec buffer/offset n’a été retrouvé; l’écart n’élargit pas à lui seul le périmètre du CVE.
6. **Debian et rétroportages.** Trivy marque les 31 findings Debian `affected` sans `FixedVersion`. Le Tracker utilise des versions sources/révisions Debian et des statuts par suite; il classe sept anciens avis glibc « unimportant », traite CVE-2026-97399 séparément comme vulnérable mineure sans DSA et ne permet pas de conclure pour deux avis glibc. La fiche 19 signale aussi des vues Tracker glibc montrant des révisions différentes; aucun état du 20 octobre ne peut être inféré d’une page actuelle.
7. **Code publié et image.** Plusieurs analyses ont pu vérifier les versions/chemins d’installation dans les rapports et consulter les tags/commits publiés, sans extraction des fichiers exacts de l’image. Ces deux catégories de preuve ne sont pas interchangeables; les références de 11–18 indiquent cette limite.

## Ordre de priorité pour les vérifications restantes

Cette liste est un ordre de réduction d’incertitude, pas une conclusion d’exposition. Les vérifications doivent rester en lecture seule et respecter l’interdiction de nouveau scan, requête de test ou exploitation.

1. **Rendre vérifiables les points runtime bloquants**, si le support d’image existant devient lisible sans lancer l’application : configuration effective des challenges/safety mode (03, 06, 07, 12), contrôles/handler de l’upload file-type (13), paramètres de proxy/PAC (08), et configuration distante des URL (14–15). Conserver distincts fichiers de l’image, sources publiées et état d’exécution.
2. **Rapprocher les chemins HIGH/CRITICAL de leurs prérequis**, en priorité les neuf findings `tar` filtrés de construction, les six jsonwebtoken filtrés sur deux versions, les findings Handlebars, lodash, minimatch et sanitize-html. Vérifier uniquement appels, formats/arguments et contrôles statiques restant ouverts; ne pas déclencher les routes.
3. **Compléter les points explicitement partiels** : arguments base64url et conditions résiduelles de 01; provenance et branche de build des archives 05; portée des consommateurs indirects 04; origine runtime des réponses/en-têtes et différence parsing/cache 09.
4. **Clore les incertitudes de sources Debian**, en recherchant la trace officielle de CVE-2026-8674, un statut de suite exploitable pour CVE-2026-89092 et une photographie/version horodatée du Tracker au 20 octobre si elle existe. En l’absence d’archive historique, conserver l’incertitude.
5. **Maintenir les limites documentaires des copies npm** : si l’image devient consultable de manière non exécutante, comparer les fichiers embarqués aux versions/commits publiés pour 11–18 et documenter les différences; sinon ne pas présenter les sources publiées comme preuve des octets exacts de l’image.

Ces actions ne ferment pas l’audit. Les détections restent inventoriées même lorsqu’un prérequis est absent dans un chemin étudié ou qu’un avis est contesté; aucune absence de preuve n’est convertie en preuve d’absence.

## Sources et méthode de recalcul

- `reports/trivy-image-initial.json`, créé le 20 octobre 2026 : source des 98 lignes et des numéros de ligne ci-dessous.
- `reports/trivy-image-high-critical.json`, créé le 21 octobre 2026 : comparaison des 38 lignes HIGH/CRITICAL.
- Fiches `docs/analysis/01` à `19` : rapprochements techniques cités dans les colonnes et sections précédentes. Les JSON n’ont pas été modifiés. Aucun nouveau scan, test d’exploitation ou requête applicative n’a été réalisé pour ce bilan.

