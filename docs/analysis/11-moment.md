# Analyse statique de moment

## Détections dans les rapports

L’installation concernée est `moment@2.0.0`, chemin `juice-shop/node_modules/express-jwt/node_modules/moment/package.json`.

| CVE | Sévérité rapport initial | Filtre HIGH/CRITICAL | Sujet et seuil corrigé rapporté |
|---|---:|---:|---|
| `CVE-2017-18214` | HIGH | HIGH, conservée | ReDoS en analysant une chaîne de date; corrigé à partir de `2.19.3`. |
| `CVE-2022-24785` | HIGH | HIGH, conservée | Traversée de chemin via `moment.locale()` côté serveur; corrigé à partir de `2.29.2`. |
| `CVE-2016-4055` | MEDIUM | Exclue du filtre | ReDoS dans `moment.duration()` avec une longue chaîne; corrigé à partir de `2.11.2`. |

Ainsi, le rapport initial contient **3 détections** sur cette copie, dont 2 HIGH et 1 MEDIUM; le rapport filtré en contient **2**, toutes deux HIGH. Chaque avis apparaît une fois par rapport où le niveau de filtre le conserve. Les JSON n’ont pas été modifiés.

## Installations et consommateurs résolus

| Version et chemin Trivy | Relation de dépendance établie | Avis applicables par version |
|---|---|---|
| `moment@2.0.0`, `node_modules/express-jwt/node_modules/moment` | Juice Shop déclare `express-jwt@0.1.3`; ce paquet dépend de `jsonwebtoken: ~0.1.0`; `jsonwebtoken@0.1.0` déclare `moment: ~2.0.0`. Sa source importe Moment et l’appelle dans `sign()` et `verify()`. `express-jwt` utilise `jsonwebtoken.verify()` sur le token Bearer reçu. | Dans les plages signalées pour les trois CVE. |
| `moment@2.31.0`, `node_modules/moment` | Copie racine de l’image. `moment-timezone@0.5.48` est aussi dans l’inventaire et son manifeste publié dépend de Moment (`^2.29.4`); Trivy résout la copie racine en `2.31.0`. Trivy n’attribue pas d’autre arête de consommateur à cette copie. | Au-delà des versions corrigées pour ces trois avis; aucun finding Moment attaché à cette installation. |

Le lien `express-jwt → jsonwebtoken → moment` est confirmé par les manifestes exacts publiés, et concorde avec le chemin d’installation du rapport. La présence de `moment-timezone` confirme un consommateur au niveau paquet pour la copie racine; l’appel applicatif à `moment-timezone` et les autres parents éventuels de cette copie ne sont pas établis par les rapports ou le code consulté. Aucun import applicatif direct de `moment` n’a été relevé dans les sources Juice Shop examinées.

## Avis officiels et prérequis

### CVE-2017-18214

L’avis GitHub officiel indique les versions antérieures à `2.19.3` comme affectées et `2.19.3` comme corrigée. Le défaut décrit un ReDoS lorsqu’une **chaîne de date forgée** est analysée par Moment côté Node.js. Le prérequis d’usage est donc que cette chaîne atteigne une API de parsing Moment; la seule présence de la version vulnérable ne suffit pas.

### CVE-2022-24785

L’avis officiel couvre Moment npm avant `2.29.2` utilisé côté serveur. Le scénario concerne un **nom de locale fourni par l’utilisateur**, transmis au setter global de locale, qui s’appelle `moment.locale()` dans les versions récentes. Dans la copie auditée `2.0.0`, cette API s’appelle `moment.lang(key)`; `moment.locale()` n’y est pas défini. Le setter legacy peut charger `./lang/` avec la clé reçue. L’avis recommande de valider/assainir ce nom. Une locale fixe ou l’absence d’appel à ce setter avec une valeur externe ne satisfait pas ce prérequis.

### CVE-2016-4055

NVD et le signalement mainteneur Red Hat précisent que le défaut concerne `moment.duration()` avant `2.11.2`, appelé avec une **longue chaîne non validée**; le scénario d’avis est un parsing regex coûteux. Le rapport initial classe cette détection MEDIUM; elle n’est donc pas présente dans le rapport filtré HIGH/CRITICAL. Le prérequis est distinct des chaînes de date de CVE-2017-18214. Nuance sur le mécanisme dans la version exacte : `moment@2.0.0/moment.js` L970–L990 construit une durée depuis les champs de l’argument et L207–L216 lit les champs numériques; ce code ne montre pas le parsing regex de la chaîne décrit par l’avis. La version reste bien celle signalée, mais le mécanisme précis n’est pas confirmé dans cette source ancienne.

## Chemin d’appel et provenance des arguments

Dans `express-jwt@0.1.3`, le middleware extrait les credentials du header `Authorization: Bearer …` puis appelle `jwt.verify(token, options.secret, options, callback)`. `jsonwebtoken@0.1.0` vérifie d’abord la signature, décode ensuite le payload et, s’il contient `exp`, compare celui-ci avec `moment().utc().unix()`.

Les appels exacts observés dans cette version de `jsonwebtoken` sont :

- `sign()` : si `options.expiresInMinutes` est présent, `moment().add('minutes', options.expiresInMinutes)`; puis `moment().utc().unix()` pour `iat`.
- `verify()` : `moment().utc().unix()` sans argument d’entrée; `exp` venant du JWT est comparé comme valeur numérique après la vérification et le décodage.
- Aucun appel à `moment.duration(...)`, à `moment(dateString)` ou à `moment.locale(...)` n’existe dans `jsonwebtoken@0.1.0`.

Dans le code applicatif publié v20.3.0, `security.isAuthorized()` fournit une clé publique lue du fichier fixe `encryptionkeys/jwt.pub` à `express-jwt`; `server.ts` attache ce middleware à plusieurs routes API. Le token Bearer et son payload viennent de la requête de l’utilisateur, mais l’appel Moment de `verify()` ne lui passe ni sa chaîne de date ni son champ `exp` comme argument : Moment obtient l’heure courante. Les middlewares `denyAll()` configurent aussi `express-jwt` avec une clé aléatoire fixe par instance. `security.authorize()` signe les tokens applicatifs avec l’import racine `jsonwebtoken` et les options fixes `{ expiresIn: '6h', algorithm: 'RS256' }`; le rapport d’image inventorie cette copie racine en `jsonwebtoken@0.4.0`, tandis que la copie `0.1.0` est imbriquée sous `express-jwt`. Ce chemin de signature ne passe donc pas par `jsonwebtoken@0.1.0`.

| Valeur | Provenance dans le chemin de la copie vulnérable | Atteint-elle une entrée vulnérable de Moment ? |
|---|---|---|
| Token / payload `exp` | Header Bearer contrôlé par le client; signature exigée avant la lecture `exp`. | `exp` est comparé à l’heure courante, mais n’est pas fourni à `moment()` comme chaîne à analyser. |
| Date de parsing | Aucune date de requête n’est passée aux appels Moment visibles dans `jsonwebtoken.verify()`. | Non observé. |
| Locale | Aucun appel de setter global (`moment.lang()` pour la version 2.0.0) dans `express-jwt` ou `jsonwebtoken@0.1.0`. La source Moment appelle son setter au chargement avec la clé littérale `'en'` et un objet de définition intégré. | Non observé depuis l’application; aucun nom de locale issu d’une requête/configuration n’atteint le chargement dynamique. |
| Durée | `jsonwebtoken@0.1.0.sign()` accepte `expiresInMinutes` et le passe à `.add('minutes', value)`; ce signataire n’est pas appelé par le middleware `express-jwt`. L’application utilise pour ses signatures le `jsonwebtoken` racine avec `expiresIn: '6h'`. | Aucun appel à `moment.duration()` avec une chaîne non validée observé dans le consommateur imbriqué. |
| Heure courante et clé de vérification | `moment()` sans argument; clé publique issue d’un fichier fixe, ou secret aléatoire fixe pour `denyAll()`. | Les arguments n’ont pas les formes requises par les avis. |

## Extraits numérotés et qualification

Les lignes ci-dessous sont numérotées à partir des sources publiées exactes des versions de la chaîne vulnérable et du tag Juice Shop v20.3.0.

| Preuve | Chemin et lignes | Extrait / constat |
|---|---|---|
| Installation Moment dans l’image auditée | `reports/trivy-image-initial.json`, L11873–L11884 et `reports/trivy-image-high-critical.json`, L10113–L10124 | Preuve image : Trivy inventorie `moment@2.0.0` au chemin imbriqué sous `express-jwt`; ces lignes prouvent version et chemin, pas le contenu de `moment.js`. |
| Installation des consommateurs dans l’image auditée | Rapports Trivy initial L8177–L8188, L10757–L10771; filtre L6417–L6428, L8997–L9011 | Preuve image : installations déclarées `express-jwt@0.1.3` et `jsonwebtoken@0.1.0` aux chemins racine/imbriqués correspondants. Les arêtes de dépendance proviennent des manifestes publiés ci-dessous, pas des champs du finding. |
| Dépendance déclarée par Juice Shop | Source publiée v20.3.0 `package.json`, L111, L128 | Déclare `express-jwt: 0.1.3` et l’import racine `jsonwebtoken: 0.4.0`; source publiée, non extraite du conteneur audité pendant cette vérification. |
| Express-jwt vers jsonwebtoken | Archive npm publiée `express-jwt@0.1.3/package.json`, `dependencies` | `"jsonwebtoken": "~0.1.0"`. |
| Jsonwebtoken vers Moment | Archive npm publiée `jsonwebtoken@0.1.0/package.json`, `dependencies` | `"moment": "~2.0.0"`. |
| Import et signature de l’archive publiée | `jsonwebtoken@0.1.0/index.js`, L1–L24 | Importe `moment`; `sign()` fait une addition en minutes optionnelle et appelle `moment().utc().unix()` pour `iat`. |
| Parsing/duration non observés dans le signataire publié | `jsonwebtoken@0.1.0/index.js`, L4–L24 | L’option est un nombre de minutes transmis à `.add()`; aucun `moment.duration()` ni parsing d’une date fournie n’est appelé explicitement. |
| Vérification du bearer dans l’archive publiée | `express-jwt@0.1.3/lib/index.js`, L24–L45 | Extrait le token de `Authorization`, puis appelle `jwt.verify()`; l’adaptateur ne signe pas de token et n’appelle pas Moment directement. |
| Appel Moment à la vérification publiée | `jsonwebtoken@0.1.0/index.js`, L27–L47 | Après vérification de signature, lit `jwt.payload.exp`, puis compare avec `moment().utc().unix()` sans transmettre le payload à Moment. |
| Parseur de date disponible dans l’archive publiée | `moment@2.0.0/moment.js`, L747–L828 | `makeDateFromString()` gère les formes ISO/parseur formaté puis `new Date(string)`; aucun appel de ce chemin depuis `jsonwebtoken.verify()` publié n’est observé. |
| API locale réellement disponible dans Moment 2.0.0 | `moment@2.0.0/moment.js`, L502–L509, L999–L1014, L1365–L1367 | Pas de méthode globale `moment.locale()` dans cette version; l’API setter est `moment.lang(key)`, avec chargement `require('./lang/' + key)` si la locale manque. Le seul setter exécuté à l’initialisation de cette archive passe la clé fixe `'en'` et un objet intégré. Les occurrences internes `this.lang()` sans argument sont des accès à la locale courante, pas un setter alimenté par l’utilisateur. |
| Appels applicatifs publiés et options de signature | Juice Shop v20.3.0 `lib/insecurity.ts`, L8–L9, L17, L46–L49 | Importe séparément `express-jwt` et le `jsonwebtoken` racine; `isAuthorized()` passe la clé publique fixe, `denyAll()` un secret aléatoire; `authorize()` signe avec `expiresIn: '6h'`, `algorithm: 'RS256'`. Ce code est publié/tagué, non extrait de l’image. |
| Exposition du middleware dans le code applicatif publié | Juice Shop v20.3.0 `server.ts`, L349–L397 et L421–L434 | `security.isAuthorized()` protège plusieurs routes; les tokens viennent des requêtes. Il s’agit de la source publiée correspondant au tag, non d’une lecture directe des fichiers applicatifs de l’image. |
| Parent de Moment racine | `moment-timezone@0.5.48/package.json`, L29–L31; inventaire Trivy | Source publiée de Moment Timezone déclare `moment: ^2.29.4`; Trivy inventorie la copie racine en `2.31.0`, non signalée pour ces trois avis. Le finding ne prouve pas à lui seul le lien parent dans l’image. |

## Conclusions par avis

| Avis | Version signalée / code disponible | Appel concerné observé | Conclusion statique |
|---|---|---|---|
| `CVE-2017-18214` | `2.0.0` dans l’intervalle `<2.19.3`; code de parsing Moment disponible. | `verify()` appelle `moment()` sans chaîne; les dates/tokens client ne sont pas passés au parsing Moment dans ce chemin. | Détection de version confirmée; prérequis de chaîne de date malveillante non observé. Exploitation non démontrée. |
| `CVE-2022-24785` | `2.0.0` dans l’intervalle `<2.29.2`; l’archive publiée 2.0.0 expose `moment.lang(key)` avec chargement dynamique de locale, mais pas `moment.locale()`. | Aucun appel de setter global `moment.lang(key)` avec une valeur externe dans les sources publiées de `express-jwt`/`jsonwebtoken`; le seul appel setter Moment interne fourni au chargement est `moment.lang('en', {…})`. | Détection de version confirmée par Trivy; prérequis d’une locale contrôlée atteignant le setter non observé dans les sources publiées consultées. Exploitation non démontrée. |
| `CVE-2016-4055` | `2.0.0` est antérieur au seuil Trivy `2.11.2`; finding MEDIUM uniquement dans le rapport initial. | Aucun appel `moment.duration()` avec chaîne non fiable dans `verify()`; `sign()` optionnel reçoit les minutes via `.add()` avec coercition numérique et n’est pas appelé par ce middleware. La source exacte Moment 2.0.0 ne confirme pas le parsing regex décrit par l’avis. | Détection de version confirmée; mécanisme de l’avis non confirmé dans le code exact 2.0.0 et prérequis de chaîne longue non observé dans le consommateur. Exploitation non démontrée. |

La conclusion combine deux niveaux de preuve : Trivy établit les paquets/versions présents dans l’image; les comportements d’appel décrits ici sont ceux des archives npm publiées et des sources Juice Shop taguées v20.3.0. Le démon Docker n’étant pas disponible lors de cette vérification, les fichiers exécutables extraits de l’image n’ont pas pu être comparés octet pour octet aux archives et sources publiées. Sous cette limite, le chemin documenté est l’appel runtime de `express-jwt` vers `jsonwebtoken.verify()`; aucun parsing de date fourni, setter global de locale contrôlé, ni durée utilisateur n’est observé dans cette chaîne publiée. Aucun nouveau scan ou test n’a servi à établir ces constats. La copie racine `2.31.0` est au-delà des seuils correctifs répertoriés.

## Références

- [Avis officiel GHSA-446m-mv8f-q348 / CVE-2017-18214](https://github.com/advisories/GHSA-446m-mv8f-q348) — versions `<2.19.3` et parsing de chaînes de date.
- [NVD CVE-2017-18214](https://nvd.nist.gov/vuln/detail/CVE-2017-18214) — précise le scénario de chaîne de date forgée.
- [Avis officiel GHSA-8hfj-j24r-96c4 / CVE-2022-24785](https://github.com/advisories/GHSA-8hfj-j24r-96c4) — versions serveur npm `<2.29.2`, locale fournie par l’utilisateur et `moment.locale()`.
- [NVD CVE-2016-4055](https://nvd.nist.gov/vuln/detail/CVE-2016-4055) et [signalement Red Hat](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-4055) — `moment.duration()` et chaîne longue, correction `2.11.2`.
- [Code Juice Shop v20.3.0 `lib/insecurity.ts`](https://github.com/juice-shop/juice-shop/blob/v20.3.0/lib/insecurity.ts) et [`server.ts`](https://github.com/juice-shop/juice-shop/blob/v20.3.0/server.ts).
- [Archives npm exactes `express-jwt@0.1.3`](https://registry.npmjs.org/express-jwt/-/express-jwt-0.1.3.tgz), [`jsonwebtoken@0.1.0`](https://registry.npmjs.org/jsonwebtoken/-/jsonwebtoken-0.1.0.tgz) et [`moment@2.0.0`](https://registry.npmjs.org/moment/-/moment-2.0.0.tgz) — manifestes et sources cités avec numéros de lignes dans les tableaux ci-dessus.
- [Manifeste Moment Timezone v0.5.48](https://github.com/moment/moment-timezone/blob/0.5.48/package.json) — dépendance au paquet Moment.
- [Rapport Trivy initial](../../reports/trivy-image-initial.json) et [rapport HIGH/CRITICAL](../../reports/trivy-image-high-critical.json) — seuls les chemins et versions d’installation de l’image, sans source JavaScript des paquets.

## Limites

Les chemins et versions proviennent des rapports Trivy; les arêtes et comportements viennent des manifestes/archives npm publiés et du code source Juice Shop v20.3.0. Ce code source publié correspond au tag applicatif visé mais ne constitue pas une extraction des fichiers du conteneur. Le démon Docker était indisponible (pipe `dockerDesktopLinuxEngine` absent), donc aucun fichier JavaScript réellement contenu dans l’image n’a été lu ou comparé. Le contenu/configuration runtime et les modules chargés dynamiquement ne sont pas établis. Aucun changement applicatif, nouveau scan, requête de test ni test d’exploitation n’a été effectué.

## Complément Docker postérieur — 28 octobre 2026

Le moteur Docker est désormais accessible; les 24 empreintes de couches de l’image locale Juice Shop correspondent à celles du rapport initial, bien que l’ID d’image diffère. Le conteneur correspondant est arrêté. Cette vérification ciblée n’a pas extrait les fichiers Moment de l’image ni établi une configuration/runtime passé; les conclusions ci-dessus sur Moment restent fondées sur les rapports et sources publiées, non sur le code Moment réellement chargé.
