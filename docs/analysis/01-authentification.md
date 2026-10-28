# Analyse de la famille authentification

## Périmètre et méthode

Cette analyse porte sur les entrées HIGH/CRITICAL du rapport Trivy conservé dans `reports/trivy-image-high-critical.json` (Trivy 0.76.0, créé le 21 octobre 2026). Le rapport décrit l’image exportée `juice-shop-image.tar`; la cible Node.js inventorie 718 paquets et présente les alertes détaillées ci-dessous. Le JSON original est préservé et n’a pas été modifié.

Le rapport fait apparaître **10 détections** pour les quatre paquets de cette famille :

| Paquet | Détections dans le rapport |
|---|---:|
| `jsonwebtoken`, version 0.1.0 | 3 |
| `jsonwebtoken`, version 0.4.0 | 3 |
| `express-jwt` | 1 |
| `jws` | 2 |
| `base64url` | 1 |
| **Total** | **10** |

Ces dix lignes de détection ne représentent pas dix problèmes indépendants. `NSWG-ECO-17` est un alias de `CVE-2015-9235` pour le contournement de vérification de `jsonwebtoken`; les deux identifiants sont rapportés pour chaque installation. En rapprochant cet alias, les six lignes `jsonwebtoken` correspondent à quatre couples installation/avis distincts (deux avis pour chacune des deux installations). Ce décompte est propre à ce rapport et ne préjuge pas de l’applicabilité à l’exécution.

Les chemins ci-dessous sont les chemins de fichiers embarqués dans l’image, tels que rapportés par Trivy. Les références de code déjà recueillies lors de l’analyse antérieure F-001 sont reprises ici comme preuves documentaires; les sources applicatives de l’image ne sont pas présentes dans ce dépôt pour une nouvelle inspection indépendante. Aucun numéro de ligne supplémentaire n’est avancé.

## 1. `jsonwebtoken@0.1.0` — installation imbriquée sous `express-jwt`

**Emplacement :** `juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json`.

### 1. Observation issue du scan

Trivy signale trois lignes : `CVE-2015-9235` (CRITICAL, version corrigée indiquée `4.2.2`), `CVE-2022-23539` (HIGH, version corrigée `9.0.0`) et `NSWG-ECO-17` (HIGH, version corrigée `>=4.2.2`). La version installée est `0.1.0`.

### 2. Conditions décrites par les avis

- L’avis [GHSA-c7hr-j4mj-j2w6 / CVE-2015-9235](https://github.com/advisories/GHSA-c7hr-j4mj-j2w6) couvre `jsonwebtoken` antérieur à 4.2.2 et décrit un contournement lorsque l’attaquant peut choisir arbitrairement l’algorithme JWT. Le scénario historique consiste notamment à faire vérifier avec HMAC un jeton alors que le serveur utilise une clé asymétrique.
- Le rapport présente `NSWG-ECO-17` avec le même titre, le même descriptif, le même seuil de correction et les mêmes références de correctif. Il s’agit d’un alias d’avis pour le même défaut que `CVE-2015-9235`, et non d’une vulnérabilité supplémentaire. La référence mainteneur commune est le [correctif de node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken/commit/1bb584bc382295eeb7ee8c4452a673a77a68b687).
- L’avis mainteneur [GHSA-8cf7-32gw-wr33 / CVE-2022-23539](https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-8cf7-32gw-wr33) concerne les versions jusqu’à 8.5.1 lorsque la vérification utilise une combinaison non sûre de type de clé et d’algorithme. Les combinaisons documentées comme sûres incluent une clé RSA avec RS256. Le rapport de scan indique un intervalle affecté qui inclut la version installée; il reste nécessaire de distinguer cet intervalle de la condition concrète décrite par l’avis.

### 3. Preuves déjà trouvées dans le code

Les observations précédemment consignées dans F-001 et reprises ici pour le chemin examiné sont :

- `juice-shop/lib/insecurity.ts` charge une clé publique RSA depuis `encryptionkeys/jwt.pub` et configure `isAuthorized()` avec `{ secret: publicKey }`, sans option `algorithms` explicite. La fiche source place ces observations aux lignes 20 et 52.
- `authorize()` signe les jetons avec `RS256` et une clé privée RSA (ligne 54 selon cette fiche). La clé privée elle-même n’est pas reproduite.
- `express-jwt@0.1.3` transmet les options à `jwt.verify()` (`juice-shop/node_modules/express-jwt/lib/index.js`, lignes 40–41 selon F-001). L’installation imbriquée `jsonwebtoken@0.1.0` appelle ensuite `jws.verify()` (`.../jsonwebtoken/index.js`, lignes 27–40 selon F-001).
- La fiche consigne des routes montées avec `security.isAuthorized()` dans `juice-shop/server.ts`. Cette observation établit un usage du middleware sur ces routes, pas leur exploitation.

Les chemins et numéros de lignes ci-dessus sont ceux consignés dans F-001 et correspondent à l’image auditée; ils n’ont pas été recalculés à partir des fichiers applicatifs, absents du dépôt courant.

### 4. Informations restant à vérifier

- Confirmer la correspondance entre cette copie imbriquée et le chemin de vérification effectivement exécuté pour chaque route considérée.
- Vérifier le comportement exact de l’ancienne implémentation `jsonwebtoken@0.1.0` et de `jws@0.2.6` avec cette clé RSA et des algorithmes différents, sans effectuer de test d’exploitation dans le cadre de cette analyse.
- Pour `CVE-2022-23539`, confirmer si cette version ancienne présente le comportement couvert par l’avis et si le type de clé/algorithme effectivement fourni sort des combinaisons sûres. Les éléments consignés décrivent au contraire une clé RSA avec RS256 pour l’émission; la configuration de vérification reste à établir entièrement.
- Garder `NSWG-ECO-17` et `CVE-2015-9235` fusionnés dans les statistiques de problèmes distincts, tout en conservant les deux identifiants dans la trace du scan.

### 5. Conclusion provisoire sur l’applicabilité

Pour `CVE-2015-9235`, la version est affectée selon l’avis et le chemin de code consigné présente une clé RSA, un algorithme d’émission RS256 et aucune restriction explicite des algorithmes dans la configuration de vérification examinée. Cela constitue une **configuration préoccupante compatible avec le scénario décrit**. L’acceptation effective d’un jeton forgé et l’impact sur l’autorisation ne sont pas démontrés. `NSWG-ECO-17` est compté comme alias de cette même alerte.

Pour `CVE-2022-23539`, la version est dans la plage de versions signalée, mais les preuves actuelles ne démontrent pas l’emploi d’une combinaison clé/algorithme interdite par l’avis. L’applicabilité est **indéterminée et non établie par les éléments disponibles**.

## 2. `jsonwebtoken@0.4.0` — installation à la racine de `node_modules`

**Emplacement :** `juice-shop/node_modules/jsonwebtoken/package.json`.

### 1. Observation issue du scan

Trivy signale `CVE-2015-9235` (CRITICAL), `CVE-2022-23539` (HIGH) et `NSWG-ECO-17` (HIGH), pour la version installée `0.4.0`. Les versions corrigées rapportées sont respectivement `4.2.2`, `9.0.0` et `>=4.2.2`. `NSWG-ECO-17` est l’alias de `CVE-2015-9235` décrit plus haut.

### 2. Conditions décrites par les avis

Les conditions des avis sont les mêmes que pour `jsonwebtoken@0.1.0` : choix arbitraire de l’algorithme pour `CVE-2015-9235`, et combinaison non sûre de type de clé et d’algorithme pour `CVE-2022-23539` ([GHSA-c7hr-j4mj-j2w6](https://github.com/advisories/GHSA-c7hr-j4mj-j2w6), [GHSA-8cf7-32gw-wr33](https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-8cf7-32gw-wr33)). La version `0.4.0` est antérieure aux versions corrigées indiquées dans le rapport.

### 3. Preuve déjà trouvée dans le code

Une inspection statique des sources de l’image a confirmé que l’installation racine est réellement importée. Depuis chacun des fichiers suivants, la résolution Node.js aboutit à `/juice-shop/node_modules/jsonwebtoken/index.js`, dont le `package.json` déclare la version `0.4.0` :

- Sources TypeScript : `/juice-shop/lib/insecurity.ts`, `/juice-shop/routes/authenticatedUsers.ts` et `/juice-shop/routes/verify.ts`.
- Sources JavaScript compilées : `/juice-shop/build/lib/insecurity.js`, `/juice-shop/build/routes/authenticatedUsers.js` et `/juice-shop/build/routes/verify.js`. Ce sont les copies compilées des modules correspondants, pas trois installations supplémentaires.

La résolution a été calculée depuis le répertoire de chaque fichier avec le mécanisme de résolution Node.js (`Module.createRequire(...).resolve(...)`); le module n’a pas été chargé ni exécuté.

La copie imbriquée `jsonwebtoken@0.1.0` reste distincte : elle est résolue par `express-jwt` depuis `/juice-shop/node_modules/express-jwt/`. Dans `lib/insecurity.ts`, le symbole importé `jwt` et le middleware `expressJwt` sont donc deux chemins de dépendance différents.

#### Appels directs à `jsonwebtoken@0.4.0`

| Fonction | Preuve dans les sources de l’image | Algorithme et clé | Fonctionnalité concernée |
|---|---|---|---|
| `sign` | `lib/insecurity.ts:54` | `RS256` est explicitement défini. La clé privée vient d’une constante RSA codée dans ce fichier (`:21`); son contenu n’est pas reproduit ici. | Fonction `security.authorize()`, appelée par les routes et fonctionnalités listées ci-dessous. |
| `verify` | `lib/insecurity.ts:189` | Appel `jwt.verify(token, publicKey, callback)` sans option `algorithms`. `publicKey` est chargé depuis `encryptionkeys/jwt.pub` (`:20`). | Middleware `updateAuthenticatedUsers()`, monté globalement dans `server.ts:382`; il examine le jeton cookie ou Bearer et, s’il n’est pas déjà en mémoire, vérifie le jeton avant de l’ajouter à la table des utilisateurs authentifiés. |
| `decode` | `routes/authenticatedUsers.ts:7,20` | `decode(userToken, { json: true })`; cette opération ne vérifie pas la signature. | Route `GET /rest/user/authentication-details`, montée dans `server.ts:629`; elle lit notamment `iat` pour produire `lastLoginTime`. Le jeton est obtenu depuis le registre `authenticatedUsers`. |
| `decode`, puis `verify` | `routes/verify.ts:119,125` | Le décodage ne vérifie pas la signature. L’appel `jwt.verify(token, security.publicKey, callback)` n’a pas d’option `algorithms`; `security.publicKey` provient de `encryptionkeys/jwt.pub` (`lib/insecurity.ts:20`). | `jwtChallenges()` est monté globalement dans `server.ts:381`. Le chemin examine les défis JWT unsigned/forged et IaC leaked key; après vérification, il contrôle également l’algorithme et l’identité liés au défi. Ce middleware de défis n’est pas à lui seul un contrôle d’autorisation de route. |

#### Appels indirects à la signature

Les routes suivantes appellent `security.authorize()`, qui utilise `jsonwebtoken@0.4.0` et la signature RS256 de `lib/insecurity.ts:54` :

- `routes/login.ts:24,41` — `POST /rest/user/login` (`server.ts:624`) : jeton d’authentification après connexion et jeton temporaire lorsque la validation à deux facteurs est requise.
- `routes/2fa.ts:42,73` — `POST /rest/2fa/verify` et `GET /rest/2fa/status` (`server.ts:486-493`) : jeton de session après vérification du second facteur et jeton de configuration 2FA.
- `routes/deluxe.ts:48` — `POST /rest/deluxe-membership` (`server.ts:657`) : nouveau jeton après mise à jour de l’état utilisateur.
- `routes/updateUserProfile.ts:40` — `POST /profile` (`server.ts:695`) : nouveau jeton après modification du profil.

Les fonctions `security.verify()` et `security.decode()` de `lib/insecurity.ts:55-56` délèguent à `jws`, pas à `jsonwebtoken`; elles ne sont pas comptées comme appels à la version `0.4.0`.

### 4. Informations restant à vérifier

- L’inspection statique établit la résolution et les appels décrits, mais ne démontre pas qu’une requête donnée atteint effectivement chaque branche conditionnelle.
- Pour `CVE-2022-23539`, déterminer si un appel de vérification utilise réellement une combinaison de type de clé et d’algorithme autre que celles documentées comme sûres. Les preuves relevées montrent RS256 à la signature et une clé publique RSA à la vérification; elles ne prouvent pas une combinaison interdite.
- Évaluer la portée fonctionnelle des jetons acceptés par les middlewares, sans inférer qu’un jeton forgé serait accepté sur la seule base de l’absence d’une option `algorithms`.

### 5. Conclusion provisoire sur l’applicabilité

L’installation racine `0.4.0` est **effectivement utilisée** dans des chemins de signature, de vérification et de décodage. Les deux appels `jwt.verify()` observés utilisent une clé publique RSA sans liste `algorithms` explicite; la fonction de signature fixe RS256 et utilise une clé privée définie dans le code. Pour `CVE-2015-9235`, les versions détectées et les appels de vérification observés rendent le scénario d’algorithme non restreint **pertinent et compatible avec la configuration constatée**, mais l’acceptation effective d’un jeton forgé n’a pas été démontrée. `NSWG-ECO-17` reste un alias de cette même alerte.

Pour `CVE-2022-23539`, le paquet est dans l’intervalle de versions rapporté, mais les éléments présents ne démontrent pas l’emploi d’une combinaison clé/algorithme non sûre visée par l’avis. Son applicabilité demeure **indéterminée**. Les appels à `decode()` ne vérifient pas la signature et ne doivent pas être présentés comme des usages de validation cryptographique.

## 3. `express-jwt@0.1.3`

**Emplacement :** `juice-shop/node_modules/express-jwt/package.json`.

### 1. Observation issue du scan

Trivy signale une détection `CVE-2020-15084` de sévérité HIGH pour `express-jwt@0.1.3`, avec `6.0.0` comme version corrigée indiquée.

### 2. Conditions décrites par l’avis

L’avis mainteneur [GHSA-6g6m-m6h5-w9gf / CVE-2020-15084](https://github.com/auth0/express-jwt/security/advisories/GHSA-6g6m-m6h5-w9gf) concerne `express-jwt` jusqu’à 5.3.3. Il requiert les trois conditions suivantes : `express-jwt` est utilisé, `algorithms` n’est pas configuré et une bibliothèque telle que `jwks-rsa` est utilisée comme `secret`. L’avis recommande de configurer explicitement les algorithmes. La version `0.1.3` est dans la plage affectée.

### 3. Preuves déjà trouvées dans le code

La source applicative importe `express-jwt` dans `/juice-shop/lib/insecurity.ts:10`; sa copie compilée l’importe dans `/juice-shop/build/lib/insecurity.js:46`. Les deux fabriques de middleware configurées dans le code sont :

| Fabrique | Configuration observée | Usage et portée |
|---|---|---|
| `isAuthorized()` — `lib/insecurity.ts:52` | `secret: publicKey`; aucune option `algorithms`. `publicKey` est lu depuis `encryptionkeys/jwt.pub` (`:20`); F-001 consigne son type RSA. | Appelée sur les routes protégées, dont `/rest/basket`, `/api/BasketItems`, `/api/Users`, `/api/Complaints`, `/api/Recycles`, `/b2b/v2`, `/api/PrivacyRequests` et plusieurs routes 2FA. Les montages sont dans `server.ts:384-393,397,409-410,414,426-428,452,463-464,472,491,495,501,662-663`. |
| `denyAll()` — `lib/insecurity.ts:53` | `secret: '' + Math.random()`; aucune option `algorithms`. La valeur est créée comme chaîne lors de la création du middleware. Aucun callback de résolution de clé n’est fourni. | Montée sur des méthodes et routes API qui doivent être refusées, par exemple `server.ts:394-424,457-474`. |

Une recherche dans les sources, les fichiers compilés, les manifestes JSON et les dépendances de l’image n’a trouvé aucune référence à `jwks-rsa` ni `jwksRsa`. Aucun fournisseur dynamique de clés n’a été repéré. Dans `express-jwt` (`node_modules/express-jwt/lib/index.js:40`), le middleware transmet `options.secret` et `options` à `jwt.verify()`. Cette version imbriquée de `jsonwebtoken@0.1.0` appelle ensuite `jws.verify()` sans appliquer de liste d’algorithmes : `node_modules/express-jwt/node_modules/jsonwebtoken/index.js:27-34`.

### 4. Informations restant à vérifier

- La recherche statique couvre les sources et dépendances présentes dans l’image et les formes habituelles d’import/configuration. Une fabrique de secret reconstruite dynamiquement ou masquée par génération de code n’a pas été observée; l’analyse statique ne peut exclure une construction indirecte non textuelle.
- Aucune configuration d’algorithmes n’est présente dans les deux fabriques relevées. Les éventuels contrôles en amont ou dans des couches d’infrastructure ne sont pas couverts par cette inspection de code.

### 5. Conclusion provisoire sur l’applicabilité

La version détectée et l’absence de `algorithms` sont confirmées. L’avis [GHSA-6g6m-m6h5-w9gf / CVE-2020-15084](https://github.com/auth0/express-jwt/security/advisories/GHSA-6g6m-m6h5-w9gf) requiert aussi l’usage de `jwks-rsa` (ou d’une bibliothèque similaire) comme `secret`. Les configurations observées utilisent une clé publique lue depuis un fichier ou une chaîne aléatoire; aucune dépendance ni configuration `jwks-rsa` n’a été trouvée. **Statut : prérequis fournisseur de clés absent; le scénario précis de CVE-2020-15084 n’est pas applicable aux configurations observées.** L’absence d’une liste `algorithms` demeure pertinente pour l’analyse distincte du contournement de vérification traité avec `jsonwebtoken` et `jws`.

## 4. `jws@0.2.6`

**Emplacement :** `juice-shop/node_modules/jws/package.json`.

### 1. Observation issue du scan

Trivy signale deux détections HIGH : `CVE-2016-1000223` (version corrigée `>=3.0.0`) et `CVE-2025-65945` (versions corrigées `3.2.3` ou `4.0.1`). La version installée est `0.2.6`.

### 2. Conditions décrites par les avis

- L’avis [GHSA-gjcw-v447-2w7q / CVE-2016-1000223](https://github.com/advisories/GHSA-gjcw-v447-2w7q) couvre les versions de `jws` antérieures à 3.0.0 et décrit la possibilité de choisir l’algorithme de vérification, avec falsification de jeton, notamment dans le scénario RSA/HMAC. Le descriptif du rapport mentionne aussi l’algorithme `none` pour les versions antérieures à 3.0.0.
- L’avis mainteneur [GHSA-869p-cjfg-cm3x / CVE-2025-65945](https://github.com/auth0/node-jws/security/advisories/GHSA-869p-cjfg-cm3x) requiert `jws.createVerify()` avec HMAC et une recherche du secret influencée par des données utilisateur du header protégé ou du payload. L’avis précise que les consommateurs utilisant l’interface `jws.verify()` — dont `node-jsonwebtoken` — ne sont pas affectés par **cette** vulnérabilité.

### 3. Preuve déjà trouvée dans le code

La version `0.2.6` est située à `/juice-shop/node_modules/jws/`. La résolution depuis les deux fichiers applicatifs qui importent directement `jws` (`lib/insecurity.ts` et `routes/verify.ts`), ainsi que depuis les deux installations de `jsonwebtoken`, aboutit à `/juice-shop/node_modules/jws/index.js` version `0.2.6`.

Dans l’implémentation de `jws`, `algoFromJWS()` lit le champ `alg` du header fourni avec le jeton (`node_modules/jws/index.js:58-75`). `jwsVerify()` choisit ensuite l’algorithme correspondant via `jwa(algoFromJWS(...))` (`:95-100`); cet appel ne reçoit pas de liste d’algorithmes autorisés. L’API exporte `verify`, `sign`, `decode` et `createVerify` aux lignes 215-223.

| Consommateur et méthode | Preuve numérotée dans l’image | Clé, algorithme et fonctionnalité |
|---|---|---|
| Wrapper `security.verify()` → `jws.verify()` | `lib/insecurity.ts:55` | Passe `publicKey`, lue depuis `encryptionkeys/jwt.pub` (`:20`); le choix de l’algorithme vient du header du jeton selon l’implémentation `jws`. |
| Appel du wrapper sur jeton fourni dans le corps | `routes/2fa.ts:17,20` | `tmpToken` vient de `req.body`; il est vérifié puis décodé pour lire `userId` et `type`. Route `POST /rest/2fa/verify` (`server.ts:486-488`). Une validation TOTP suit le contrôle du type dans `routes/2fa.ts:31-36`. |
| Appel du wrapper sur jeton de configuration | `routes/2fa.ts:105,115-120` | `setupToken` vient de `req.body`; il est vérifié puis décodé pour lire le secret et le type, puis le code TOTP initial est validé. Route `POST /rest/2fa/setup` (`server.ts:493-496`). |
| Appel du wrapper sur cookie | `routes/currentUser.ts:17` | Vérifie `req.cookies.token` avec la même clé publique avant de récupérer l’utilisateur en mémoire. Route `GET /rest/user/whoami` (`server.ts:628`). |
| Appel du wrapper dans le contrôle du défi Deluxe | `routes/deluxe.ts:44-46` | Vérifie le jeton Bearer obtenu par `utils.jwtFrom(req)` avec la clé publique; sert à évaluer le défi `freeDeluxeChallenge` durant `POST /rest/deluxe-membership` (`server.ts:657`). |
| Wrapper `security.decode()` → `jws.decode()` | `lib/insecurity.ts:56` | Décode le payload sans vérifier sa signature. Utilisé après vérification dans les deux chemins 2FA ci-dessus. |
| Décodage direct dans le chat | `routes/chat.ts:42-46,222-225` | Décode les claims du jeton Bearer reçu par `utils.jwtFrom(req)` pour obtenir un identifiant ou un rôle. Ces appels `security.decode()` ne font pas de vérification de signature à cet endroit. Fonctionnalité montée sur `POST /rest/chat` (`server.ts:666`). |
| Décodage JWS de forme avant JWT | `routes/verify.ts:119` | `jws.decode(token)` vérifie que le jeton est décodable avant les appels `jsonwebtoken.decode()` et `jsonwebtoken.verify()` décrits plus haut; la validation cryptographique de ce chemin est le `jwt.verify()` à `routes/verify.ts:125`. |
| `jsonwebtoken@0.4.0` → `jws.sign/verify/decode` | `node_modules/jsonwebtoken/index.js:3-4,7-10,28,33-48` | Le code applicatif utilise `sign` avec `RS256` (`lib/insecurity.ts:54`) et utilise `verify` dans `lib/insecurity.ts:189` et `routes/verify.ts:125`. Les clés sont la constante privée RSA du code (ligne 21, valeur omise) et la clé publique `encryptionkeys/jwt.pub` (ligne 20). |
| `jsonwebtoken@0.1.0` imbriqué sous `express-jwt` → `jws.sign/verify/decode` | `node_modules/express-jwt/node_modules/jsonwebtoken/index.js:1,4-7,22,27-42` | Le chemin observé par `express-jwt` est `jwt.verify()` (`node_modules/express-jwt/lib/index.js:40`), puis `jws.verify()` (`.../jsonwebtoken/index.js:27-34`) avec le `secret` configuré par `isAuthorized()`. Aucun appel applicatif à `sign()` ou `decode()` de cette copie imbriquée n’a été trouvé. |

Le chemin `jws.createVerify()` n’a pas été trouvé dans les sources applicatives, les fichiers compilés ni les fichiers des modules qui importent `jws`. La fonction est exportée par la bibliothèque (`node_modules/jws/index.js:222-223`), mais l’export seul ne démontre pas son utilisation.

### 4. Informations restant à vérifier

- L’inspection statique couvre les consommateurs repérés par leurs imports et références textuelles usuelles; elle ne démontre pas l’absence de chargement construit dynamiquement ou de code injecté après compilation.
- La vérification ne démontre pas qu’un jeton forgé est effectivement accepté, ni l’impact précis sur chaque route. Aucune requête forgée ni test d’exploitation n’a été exécuté.
- Les appels `decode()` utilisés dans le chat ne valident pas l’identité signataire. Leur influence sur les fonctionnalités est consignée; leur impact n’a pas été évalué au-delà de cette observation.
- Aucun avis consulté ne déclare `CVE-2016-1000223` comme alias de `CVE-2015-9235`. Les deux alertes partagent un chemin et un mécanisme d’algorithme non restreint, mais restent distinctes dans les données du scan tant qu’un rapprochement documentaire formel n’est pas établi.

### 5. Conclusion provisoire sur l’applicabilité

Pour `CVE-2016-1000223`, la version `0.2.6` est antérieure à 3.0.0. Le code réel appelle `jws.verify()` avec une clé publique RSA et laisse l’implémentation choisir l’algorithme depuis le header du jeton; les jetons incluent des valeurs provenant du corps de requêtes et de cookies. **Statut : scénario applicable au chemin de vérification observé**, notamment les vérifications 2FA; l’acceptation effective d’un jeton forgé et son impact ne sont pas démontrés.

Pour `CVE-2025-65945`, la version est dans la plage affectée, mais son prérequis `jws.createVerify()` avec HMAC et résolution de secret à partir de données contrôlées par l’utilisateur est absent des consommateurs inspectés. Les appels constatés utilisent `jws.verify()`, interface que l’avis mainteneur exclut explicitement. **Statut : prérequis `createVerify()` absent; le scénario de CVE-2025-65945 n’est pas applicable aux chemins observés.**

## 5. `base64url@0.0.6`

**Emplacement :** `juice-shop/node_modules/base64url/package.json`.

### 1. Observation issue du scan

Trivy signale `NSWG-ECO-428` de sévérité HIGH pour `base64url@0.0.6`, avec `>=3.0.0` comme version corrigée indiquée. La cible du rapport est Node.js.

### 2. Conditions décrites par l’avis

Le rapport décrit l’allocation de tampons non initialisés lorsqu’un nombre est fourni à `base64url`, sur Node.js 4.x ou antérieur. L’avis GitHub [GHSA-rvg8-pwq2-xj7q](https://github.com/advisories/GHSA-rvg8-pwq2-xj7q) décrit le même paquet, le même comportement, les versions antérieures à 3.0.0 et indique **qu’aucun CVE n’est connu**. `NSWG-ECO-428` et `GHSA-rvg8-pwq2-xj7q` sont donc à rapprocher comme deux identifiants du même avis, pas comme deux détections séparées dans le rapport fourni. Les références mainteneur sont le [PR #25 de base64url](https://github.com/brianloveswords/base64url/pull/25) et le [rapport HackerOne 321687](https://hackerone.com/reports/321687).

### 3. Preuve déjà trouvée dans le code

Le rapport confirme que `base64url@0.0.6` est présent à `juice-shop/node_modules/base64url/package.json`. Le lien entre l’image locale et l’image analysée a été établi en lecture seule :

- L’image locale porte le tag `bkimminich/juice-shop:v20.3.0`, le digest de dépôt `sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27` et la plateforme `linux/amd64` (`docker image inspect`). Le champ local `.Id` renvoyé par Docker est également `cea5…`; il est consigné ici séparément du digest de configuration déclaré dans le manifeste OCI.
- La consultation de `bkimminich/juice-shop@sha256:cea5…` avec `docker manifest inspect --verbose` a renvoyé le manifeste de plateforme `linux/amd64` `sha256:590a451634fe564eff575ecb353a0e67ed6b3abef77005b223281663abda867e`. Son descripteur de configuration déclare `sha256:40606cfb23b8937b60c1cab5a5980362e0a372223c1f86f6c3e68c1b003a823c`.
- Le rapport Trivy indique précisément cette dernière empreinte comme `ArtifactID` et `Metadata.ImageID`. Les 24 `RootFS.Layers` (DiffIDs) de l’image locale correspondent, dans le même ordre, aux 24 `Metadata.DiffIDs` du rapport.
- La version **Node.js `v24.21.0`** a été observée en exécutant le binaire `/nodejs/bin/node` dans un conteneur éphémère basé sur l’image locale identifiée ci-dessus. Le conteneur `juice-shop-audit` était arrêté; il n’a pas été démarré ni modifié.

Ces éléments relient le digest de dépôt `cea5…`, le manifeste enfant `linux/amd64` `590a…` et l’identifiant de configuration `4060…` du rapport. Ils montrent que la version Node.js relevée provient du même contenu d’image que celui inventorié par Trivy. Les empreintes désignent des niveaux différents de la chaîne d’image et ne sont donc pas à comparer comme si elles étaient le même type d’identifiant.

### 4. Informations restant à vérifier

- Confirmer par inspection statique si le code transmet une valeur numérique à `base64url`; ce point n’est pas nécessaire pour écarter le prérequis de runtime, mais il complète l’analyse de l’usage du paquet.
- Vérifier le rapprochement de `NSWG-ECO-428` avec `GHSA-rvg8-pwq2-xj7q` dans la base de vulnérabilités utilisée par Trivy; l’avis GHSA précise qu’aucun CVE n’est attribué.

### 5. Conclusion provisoire sur l’applicabilité

La version `0.0.6` est dans l’intervalle détecté, mais le runtime de l’image liée au rapport est Node.js `v24.21.0`, et non Node.js 4.x ou antérieur. Le prérequis de runtime décrit par l’avis n’est donc pas satisfait dans l’image auditée. **L’alerte reste une observation valide du scan, mais le scénario `NSWG-ECO-428` / `GHSA-rvg8-pwq2-xj7q` décrit par l’avis ne paraît pas applicable à ce runtime.** Aucun appel avec argument numérique n’a été vérifié; ce point d’usage reste à documenter, sans modifier cette conclusion sur le prérequis de runtime.

## Détections MEDIUM de `jsonwebtoken` dans le rapport initial

Le rapport initial contient quatre détections MEDIUM supplémentaires, absentes du filtre HIGH/CRITICAL : `CVE-2022-23540` et `CVE-2022-23541` pour chacune des deux installations. Les chemins et versions sont des preuves issues de l’image rapportées par Trivy : copie imbriquée `0.1.0` (vulnérabilités dans `reports/trivy-image-initial.json` à partir des lignes 18239, chemin `juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json`) et copie racine `0.4.0` (lignes 18538, chemin `juice-shop/node_modules/jsonwebtoken/package.json`). Elles prouvent la détection des versions, pas l’exécution d’un scénario vulnérable.

Les extraits numérotés ci-dessous sont issus des archives publiées npm de [`jsonwebtoken@0.1.0`](https://registry.npmjs.org/jsonwebtoken/-/jsonwebtoken-0.1.0.tgz) et [`jsonwebtoken@0.4.0`](https://registry.npmjs.org/jsonwebtoken/-/jsonwebtoken-0.4.0.tgz), pas d’une nouvelle extraction de l’image. Les implémentations exactes déclarent respectivement `verify(jwtString, secretOrPublicKey, options, callback)` dans `package/index.js:27–40` et `:33–46`. Elles appellent `jws.verify(jwtString, secretOrPublicKey)`, sans appliquer d’option `algorithms` et sans invoquer une fonction de récupération de clé.

### `CVE-2022-23540` — algorithme par défaut `none`

L’avis officiel [GHSA-qwph-4952-7xr6](https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-qwph-4952-7xr6) indique les versions affectées `<=8.5.1`, corrigées en `9.0.0`. Il exige **simultanément** la réception d’un jeton sans signature, l’absence d’algorithmes spécifiés et le passage d’une clé/secrète falsy (`null`, `false` ou `undefined`, par exemple).

| Installation (preuve de l’image) | Source publiée exacte et usage déjà relevé | Prérequis comparés à l’avis |
|---|---|---|
| `jsonwebtoken@0.1.0` imbriqué sous `express-jwt` | `index.js:27–40` délègue à `jws.verify(jwtString, secretOrPublicKey)`. `express-jwt@0.1.3` transmet la configuration à ce `verify()` (F-001, `express-jwt/lib/index.js:40–41`); `isAuthorized()` fournit la clé publique RSA issue de `encryptionkeys/jwt.pub`. | Version : **présente**. Pas d’allowlist : **observé** (cette ancienne API ne l’applique pas). Jeton sans signature : **inconnu**. Clé falsy : **non observée** dans la configuration RSA; valeur effectivement chargée au runtime : **non vérifiée séparément**. |
| `jsonwebtoken@0.4.0` racine | `index.js:33–46` délègue de même à `jws.verify()`. Les appels applicatifs relevés dans `lib/insecurity.ts:189` et `routes/verify.ts:125` passent `publicKey`, provenant de `encryptionkeys/jwt.pub`, sans `algorithms`. | Version : **présente**. Pas d’allowlist : **observé**. Jeton sans signature : **inconnu**. Clé falsy : **non observée** dans la configuration RSA; valeur runtime : **non vérifiée séparément**. |

**Conclusion CVE-2022-23540 :** versions détectées et absence de restriction d’algorithme observée, mais ni jeton sans signature ni clé falsy ne sont établis dans les appels applicatifs relevés. Le mécanisme précis de l’avis n’est **pas confirmé**. Cela ne remplace pas les constats séparés sur l’algorithme provenant du jeton dans les anciennes dépendances `jws`.

### `CVE-2022-23541` — récupération de clé mal implémentée

L’avis officiel [GHSA-hjrf-2m68-5959](https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-hjrf-2m68-5959) indique `<=8.5.1`, corrigé en `9.0.0`. Il requiert que l’application prenne en charge les clés symétriques et asymétriques dans `jwt.verify()` à l’aide de **la même fonction de récupération de clé**, mal implémentée au point de permettre une confusion RSA/HMAC (par exemple vérifier HS256 avec une clé publique asymétrique).

| Installation (preuve de l’image) | Source publiée exacte et usage déjà relevé | Prérequis comparés à l’avis |
|---|---|---|
| `jsonwebtoken@0.1.0` imbriqué sous `express-jwt` | `index.js:27–40` transmet directement la valeur `secretOrPublicKey` à `jws.verify()`; aucune fonction de récupération n’est appelée. L’usage recensé fournit une clé publique RSA statique. | Version : **présente**. Fonction de récupération commune : **absente** de l’API et des appels observés. Support conjoint des deux types via cette fonction : **non observé**. |
| `jsonwebtoken@0.4.0` racine | `index.js:33–46` transmet la valeur à `jws.verify()` sans résoudre de fonction. Les appels relevés utilisent la clé RSA statique; l’émission documentée est RS256 avec clé privée RSA. | Version : **présente**. Fonction de récupération commune : **absente** des appels observés. Validation symétrique et asymétrique via cette même fonction : **absente des éléments relevés**. |

**Conclusion CVE-2022-23541 :** les versions sont signalées, mais le prérequis central de l’avis n’apparaît ni dans les implémentations exactes ni dans les consommateurs recensés. Le mécanisme n’est **pas confirmé** dans ces chemins. Conclusion limitée à l’inspection statique; aucun essai de jeton n’a été effectué.

### Synthèse des quatre détections MEDIUM

| Avis | `jsonwebtoken@0.1.0` imbriqué | `jsonwebtoken@0.4.0` racine | Conclusion |
|---|---|---|---|
| `CVE-2022-23540` | Version et vérification présentes; aucun algorithme autorisé appliqué; signature entrante inconnue; clé falsy non observée, valeur runtime inconnue. | Même constat; clé RSA configurée, mais valeur runtime non vérifiée. | Conditions cumulatives de l’avis non établies; mécanisme non confirmé. |
| `CVE-2022-23541` | Version présente; clé RSA statique; pas de fonction de récupération recensée. | Version présente; appels RSA statiques; pas de fonction de récupération recensée. | Prérequis spécifique absent des consommateurs observés; mécanisme non confirmé. |

Le rapport initial comporte **quatre lignes MEDIUM** (deux avis × deux installations); le filtre HIGH/CRITICAL n’en comporte aucune. Elles s’ajoutent aux dix lignes de ce filtre synthétisées ci-dessous et ne démontrent pas une exploitation.

## Références complémentaires sur les avis

- [NVD — CVE-2020-15084](https://nvd.nist.gov/vuln/detail/CVE-2020-15084) complète les conditions de l’avis `express-jwt` et indique une plage affectée jusqu’à 5.3.3.
- [GHSA-c7hr-j4mj-j2w6 — `jsonwebtoken` / CVE-2015-9235](https://github.com/advisories/GHSA-c7hr-j4mj-j2w6).
- [GHSA-8cf7-32gw-wr33 — `jsonwebtoken` / CVE-2022-23539](https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-8cf7-32gw-wr33).
- [GHSA-6g6m-m6h5-w9gf — `express-jwt` / CVE-2020-15084](https://github.com/auth0/express-jwt/security/advisories/GHSA-6g6m-m6h5-w9gf).
- [GHSA-gjcw-v447-2w7q — `jws` / CVE-2016-1000223](https://github.com/advisories/GHSA-gjcw-v447-2w7q).
- [GHSA-869p-cjfg-cm3x — `jws` / CVE-2025-65945](https://github.com/auth0/node-jws/security/advisories/GHSA-869p-cjfg-cm3x).
- [GHSA-rvg8-pwq2-xj7q — `base64url`, sans CVE attribué](https://github.com/advisories/GHSA-rvg8-pwq2-xj7q).

## Résumé des incertitudes restantes

1. Pour `jsonwebtoken@0.1.0`, la configuration documentée correspond au scénario d’algorithme non restreint de `CVE-2015-9235`, mais l’acceptation effective d’un jeton forgé n’a pas été vérifiée. L’applicabilité de `CVE-2022-23539` n’est pas démontrée par la paire RSA/RS256 observée.
2. L’usage de `jsonwebtoken@0.4.0` est confirmé dans les sources et les copies compilées. L’applicabilité de `CVE-2022-23539` à une combinaison clé/algorithme précise reste à établir; aucun test d’acceptation de jeton n’a été effectué.
3. Pour `express-jwt`, aucune configuration dynamique ni référence `jwks-rsa` n’a été trouvée dans l’image inspectée. Le prérequis fournisseur de clés de `CVE-2020-15084` est absent des configurations observées; les limites d’une recherche statique demeurent.
4. Les consommateurs observés de `jws@0.2.6` sont recensés. `CVE-2016-1000223` correspond à un chemin de vérification applicatif avec algorithme déterminé par le header; l’acceptation d’un jeton forgé n’a pas été vérifiée. Les prérequis de `CVE-2025-65945` ne sont pas présents dans les appels observés.
5. Pour `base64url`, le runtime `v24.21.0` est relié au contenu de l’image auditée par le digest de manifeste, l’ImageID du rapport et les 24 DiffIDs concordants. Le type d’arguments transmis par le code reste à documenter.

## Limites de cette analyse

Cette section documente le rapport et des éléments statiques déjà consignés. Elle ne met à jour aucune dépendance, ne modifie pas l’application et ne réalise aucun test d’exploitation. Les conclusions distinguent la détection d’une version vulnérable de l’applicabilité démontrée dans le chemin applicatif.

## Synthèse finale des 10 détections

Le tableau ci-dessous conserve une ligne par entrée de détection Trivy. Un alias compte dans ces dix lignes, même lorsqu’il décrit le même problème qu’un identifiant CVE. De même, plusieurs paquets peuvent participer à une chaîne commune de vérification JWT; les lignes ne représentent donc pas automatiquement dix problèmes indépendants.

### `jsonwebtoken@0.1.0` — installation imbriquée

Chemin pour les trois détections : `juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json`.

1. **`CVE-2015-9235` — CRITICAL.** Preuves : la copie `0.1.0` est résolue par `express-jwt`; `isAuthorized()` lui transmet une clé publique RSA sans restriction `algorithms`, et son implémentation appelle `jws.verify()`. Prérequis de version et chemin de vérification présents. **Conclusion : configuration compatible avec le scénario de confusion d’algorithmes; exploitation non démontrée.**
2. **`CVE-2022-23539` — HIGH.** Preuves : version dans l’intervalle signalé; le chemin observé vérifie avec la clé publique RSA. L’avis vise une combinaison non sûre de type de clé et d’algorithme; aucune combinaison interdite n’a été établie dans cette installation. **Conclusion : à approfondir; applicabilité non établie.**
3. **`NSWG-ECO-17` — HIGH.** Preuves et prérequis identiques à `CVE-2015-9235`; le rapport donne le même descriptif, le même seuil de correction et le même correctif amont. **Conclusion : alias de `CVE-2015-9235`, pas un problème indépendant; conserver cette ligne pour la traçabilité des dix détections.**

### `jsonwebtoken@0.4.0` — installation racine

Chemin pour les trois détections : `juice-shop/node_modules/jsonwebtoken/package.json`.

4. **`CVE-2015-9235` — CRITICAL.** Preuves : imports applicatifs résolus vers la version racine; appels `verify()` utilisent la clé publique RSA sans option `algorithms`, dans les middlewares `updateAuthenticatedUsers()` et `jwtChallenges()`. Prérequis de version et vérifications applicatives présents. **Conclusion : configuration compatible avec le scénario de confusion d’algorithmes; exploitation non démontrée.**
5. **`CVE-2022-23539` — HIGH.** Preuves : installation utilisée dans l’application; la signature observée fixe RS256 avec une clé RSA et les vérifications utilisent la clé publique RSA. Les éléments disponibles ne montrent pas une combinaison clé/algorithme interdite par l’avis. **Conclusion : à approfondir; applicabilité non établie.**
6. **`NSWG-ECO-17` — HIGH.** Preuves et prérequis identiques à `CVE-2015-9235` pour l’installation racine. **Conclusion : alias de `CVE-2015-9235`, pas un problème indépendant; conserver cette ligne dans le décompte du scan.**

### `express-jwt@0.1.3`

Chemin : `juice-shop/node_modules/express-jwt/package.json`.

7. **`CVE-2020-15084` — HIGH.** Preuves : deux fabriques `express-jwt` existent; aucune ne définit `algorithms`. `isAuthorized()` utilise la clé publique chargée depuis `encryptionkeys/jwt.pub`; `denyAll()` reçoit une chaîne aléatoire. Aucune référence ou dépendance `jwks-rsa` ni fournisseur dynamique de clés n’a été trouvé dans l’image. L’avis exige aussi un fournisseur de type `jwks-rsa` comme `secret`. **Conclusion : ce prérequis est absent des configurations inspectées; scénario de l’avis non applicable à ces configurations.** Limite : conclusion issue de l’analyse statique des fichiers de l’image.

### `jws@0.2.6`

Chemin pour les deux détections : `juice-shop/node_modules/jws/package.json`.

8. **`CVE-2016-1000223` — HIGH.** Preuves : `jws.verify()` est appelé directement par `security.verify()` pour les jetons 2FA, le cookie de session et un contrôle de défi; les deux versions de `jsonwebtoken` utilisent également ce même `jws@0.2.6`. La clé provient de `encryptionkeys/jwt.pub`; la bibliothèque choisit l’algorithme depuis le header du jeton, sans allowlist fournie par ces appels. Prérequis de version, vérification et algorithme contrôlé par le jeton présents dans les chemins observés. **Conclusion : scénario applicable au chemin statique observé; acceptation d’un jeton forgé et impact non démontrés.** Ce chemin commun avec les constats `jsonwebtoken` doit être pris en compte lors de la déduplication, sans supprimer les détections originales.
9. **`CVE-2025-65945` — HIGH.** Preuves : version dans l’intervalle affecté, mais aucun consommateur de `jws.createVerify()` n’a été trouvé; les appels observés utilisent `jws.verify()`, explicitement exclu par l’avis mainteneur. Aucun usage HMAC avec recherche de secret dépendant de données utilisateur du header ou du payload n’a été observé. **Conclusion : prérequis absents dans le périmètre inspecté; scénario de cet avis non applicable aux appels observés.**

### `base64url@0.0.6`

Chemin : `juice-shop/node_modules/base64url/package.json`.

10. **`NSWG-ECO-428` — HIGH.** Preuves : l’image liée au rapport utilise Node.js `v24.21.0`; l’ImageID de configuration et les 24 DiffIDs concordent avec le rapport. L’avis décrit une condition de runtime Node.js 4.x ou antérieur et une entrée numérique. Le prérequis de runtime ancien est absent; l’usage numérique n’a pas été vérifié. **Conclusion : scénario décrit non applicable au runtime observé; la détection Trivy est conservée pour la traçabilité.** L’avis GHSA correspondant est `GHSA-rvg8-pwq2-xj7q` et ne possède pas de CVE connu.

### Rapprochements et limites de comptage

- `NSWG-ECO-17` et `CVE-2015-9235` se recoupent pour chacune des deux installations `jsonwebtoken`. Cela représente quatre lignes Trivy, mais deux couples installation/avis après rapprochement de l’alias.
- `CVE-2016-1000223` sur `jws` et `CVE-2015-9235` sur `jsonwebtoken` passent par `jws.verify()` dans des chemins communs. Les avis restent des détections distinctes; le rapport ne fournit pas une équivalence d’identifiants entre ces deux CVE.
- `NSWG-ECO-428` correspond au même avis documenté par `GHSA-rvg8-pwq2-xj7q`; cette référence GHSA sert au rapprochement, sans ajouter une onzième détection au rapport.
- Le total demeure **10 détections Trivy**. L’analyse statique établit des configurations compatibles ou des prérequis absents; elle ne démontre pas l’exploitation ni l’impact final sur l’application.
