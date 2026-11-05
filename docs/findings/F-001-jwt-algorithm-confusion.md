# F-001 — Confusion d’algorithmes JWT dans le chemin jsonwebtoken

## Résumé

Trivy a détecté **CVE-2015-9235** sur la dépendance jsonwebtoken version
0.1.0, installée sous express-jwt dans l’image OWASP Juice Shop v20.3.0.
L’inspection du code montre que le middleware d’autorisation configure
une clé publique RSA sans fournir de liste explicite d’algorithmes
autorisés. La vérification est déléguée à la version affectée de
jsonwebtoken.

**Statut : configuration affectée identifiée ; exploitation effective
non démontrée.**

## Actif et preuve du scan

- Application : OWASP Juice Shop v20.3.0.
- Image : bkimminich/juice-shop@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27.
- Plateforme : linux/amd64.
- Scanner : Trivy 0.76.0.
- Rapport initial : reports/trivy-image-initial.json, entrée
  CVE-2015-9235, sévérité CRITICAL.
- Référence CVE du rapport : https://avd.aquasec.com/nvd/cve-2015-9235.
- Valeurs rapportées pour l’entrée examinée : version installée 0.1.0,
  version corrigée indiquée par Trivy 4.2.2.
- Chemin de dépendance rapporté :
  juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json.

Le rapport initial a été conservé sur la branche docs/project-readme au
moment de la rédaction de cette fiche.

## Observations vérifiées

Les chemins ci-dessous sont ceux de l’application dans le conteneur
Juice Shop. Les numéros de ligne correspondent aux sources de l’image
auditée.

### Dépendances

- /juice-shop/node_modules/express-jwt/package.json:3 déclare
  express-jwt@0.1.3.
- /juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json:3
  indique jsonwebtoken@0.1.0.
- L’entrée résolue de cette copie est
  /juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/index.js.

### Configuration JWT

Dans /juice-shop/lib/insecurity.ts :

- Ligne 20 : la clé publique est chargée depuis
  encryptionkeys/jwt.pub.
- Ligne 52 : isAuthorized() configure express-jwt avec
  { secret: publicKey }. Aucune option algorithms n’est définie dans cet
  appel.
- Ligne 54 : authorize() signe les jetons avec algorithm: 'RS256' et une
  clé privée RSA. La valeur de la clé privée n’est pas reproduite dans
  cette fiche.

La clé configurée a été inspectée sans afficher son contenu : son type
est une clé publique RSA.

Dans /juice-shop/node_modules/express-jwt/lib/index.js:40-41,
express-jwt appelle jwt.verify(token, options.secret, options, callback).
Les options passées sont celles fournies lors de la création du
middleware.

Dans
/juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/index.js:27-40,
verify() appelle jws.verify(jwtString, secretOrPublicKey). Le chemin
examiné ne vérifie pas une liste d’algorithmes autorisés avant cette
opération.

### Exemples de routes utilisant ce middleware

Dans /juice-shop/server.ts :

- Ligne 384 : préfixe /rest/basket.
- Lignes 386-387 : /api/BasketItems et /api/BasketItems/:id.
- Lignes 391-393 : lecture de /api/Users et /api/Users/:id.
- Ligne 397 : création via POST /api/Products.
- Lignes 409-410 : GET et POST /api/Complaints.
- Ligne 414 : POST /api/Recycles.
- Lignes 426-428 : /rest/user/authentication-details et des routes de
  panier.
- Ligne 452 : préfixe /b2b/v2.
- Lignes 463-464 : préfixes /api/PrivacyRequests.
- Lignes 491, 493-502 : routes d’état, d’activation et de désactivation
  de la 2FA.
- Lignes 662-663 : PATCH et POST /rest/products/reviews.

Cette liste donne des exemples de montages avec security.isAuthorized().
Elle ne signifie pas que tous ces endpoints ont été exploités ni que
toutes leurs opérations sont compromises.

## Interprétation et impact potentiel

Les jetons légitimes sont signés avec RS256, ce qui correspond à une clé
privée RSA pour la signature et une clé publique RSA pour la vérification.
Or, dans le chemin observé, l’algorithme n’est pas explicitement limité à
RS256 et la version vulnérable de jsonwebtoken délègue la vérification à
jws.verify avec la clé configurée. C’est une configuration concernée par
le scénario de confusion d’algorithmes de CVE-2015-9235.

Si un attaquant peut soumettre un jeton Bearer forgé à une route protégée
et si la bibliothèque accepte le changement vers un algorithme HMAC avec
la clé publique comme secret, il pourrait faire accepter des claims JWT
choisis et contourner l’authentification de cette route. La clé publique
n’est pas un secret ; l’enjeu est qu’elle soit réutilisable comme secret
HMAC par le vérificateur.

L’inspection statique ne démontre toutefois pas qu’un tel jeton est
accepté dans l’exécution de l’application, ni quels rôles ou autorisations
seraient accessibles. Les routes ont d’autres traitements et contrôles,
et l’impact doit être confirmé par une vérification contrôlée dans le
laboratoire. Aucune tentative d’exploitation n’a été effectuée pour cette
fiche.

## Correction à envisager

Trivy indique 4.2.2 comme version corrigée pour cette seule CVE, mais
cette version reste affectée par CVE-2022-23539, CVE-2022-23540 et
CVE-2022-23541 (corrigées en 9.0.0). De plus, la copie 0.1.0 est imbriquée
parce que `express-jwt@0.1.3` fige `jsonwebtoken ~0.1.0` : il faut donc
mettre à jour **`express-jwt`** (version maintenue, qui exige l’option
`algorithms`), la copie racine **`jsonwebtoken` ≥ 9.0.0** et **`jws` ≥ 3.2.3**,
puis vérifier la résolution effective de toutes les copies. Configurer
`algorithms: ['RS256']` dans chaque vérificateur (`isAuthorized()`,
`updateAuthenticatedUsers()`, `security.verify()`, `routes/verify.ts`).

Cette correction ne suffit pas tant que la clé privée de signature est
publique : voir [F-002](F-002-cle-privee-jwt-codee-en-dur.md).

Après correction, reconstruire l’image, refaire le scan avec une nouvelle
base et vérifier les routes d’authentification avec des tests fonctionnels.
Le rapport initial doit rester préservé comme référence.

## Incertitudes et limites

- Le constat décrit la configuration et le code observés dans l’image
  figée ; il ne prouve pas l’exploitation d’une route.
- Les appels utilisant d’autres vérificateurs JWT ou d’autres
  middlewares ne sont pas couverts par cette fiche.
- La compatibilité d’une mise à niveau de jsonwebtoken ou express-jwt
  n’a pas été évaluée.
- Aucun changement applicatif ni scan de validation n’a été effectué.
