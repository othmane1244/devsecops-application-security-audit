# F-002 — Clé privée de signature JWT codée en dur et publique

## Résumé

La clé privée RSA qui signe tous les jetons d’authentification de Juice Shop
v20.3.0 est une constante du code source (`lib/insecurity.ts:21`) et de sa
copie compilée livrée dans l’image (`build/lib/insecurity.js:55`). Cette clé
correspond à la clé publique `encryptionkeys/jwt.pub` utilisée pour vérifier
les jetons. Comme le code source est public et l’image téléchargeable, toute
personne peut signer un jeton RS256 que l’application considère comme valide,
avec les claims de son choix (identifiant, email, rôle).

**Statut : confirmé statiquement, sur le tag publié et sur l’image auditée
(correspondance cryptographique vérifiée). Aucune requête ni jeton forgé n’a
été envoyé à l’application.**

**Priorité proposée : P1.** Ce constat ne dépend d’aucune CVE de bibliothèque :
il resterait vrai après la mise à jour de `jsonwebtoken`, `jws` et
`express-jwt`. Il est plus direct que le scénario de confusion d’algorithmes
de [F-001](F-001-jwt-algorithm-confusion.md).

## Preuves

| ID | Preuve | Source |
|---|---|---|
| K-01 | Le scan de secrets Trivy signale `private-key` (HIGH) dans `lib/insecurity.ts:21` et `build/lib/insecurity.js:55`, même matériel. | [Rapport secrets, S-01/S-02](../secrets/rapport-partageable.md) |
| K-02 | `lib/insecurity.ts:20` charge `publicKey` depuis `encryptionkeys/jwt.pub`; `:21` définit `privateKey` comme chaîne PEM littérale. | Source publiée [v20.3.0](https://github.com/juice-shop/juice-shop/blob/v20.3.0/lib/insecurity.ts) |
| K-03 | `:54` `authorize()` signe avec `jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })`. | Idem |
| K-04 | Les vérifications utilisent la clé publique correspondante : `:52` `isAuthorized()` (express-jwt), `:55` `verify()` (jws), `:189` `jwt.verify(token, publicKey, …)` dans `updateAuthenticatedUsers()`. | Idem; détails dans [01](../analysis/01-authentification.md) |
| K-05 | **Correspondance de la paire vérifiée** le 4 novembre 2026 : la clé privée extraite de `lib/insecurity.ts` (tag v20.3.0) a été chargée localement en DER, et son module/exposant public est égal à celui de `encryptionkeys/jwt.pub` du même tag. Résultat : `MATCH`. Taille de clé : **1024 bits**. La clé n’a été ni affichée, ni copiée dans le dépôt; le fichier temporaire a été supprimé. | Script de comparaison local (Python `cryptography`), sources publiées |
| K-06 | La même clé privée sert aussi de secret HMAC pour `deluxeToken(email)` (`lib/insecurity.ts:149-152`). Sa divulgation permet donc aussi de calculer ces jetons. | Source publiée v20.3.0 |
| K-07 | **Même vérification sur l’image auditée** (4 novembre 2026) : `build/lib/insecurity.js` et `encryptionkeys/jwt.pub` copiés depuis un conteneur créé (jamais démarré, état `created`, supprimé ensuite) à partir de `sha256:cea5a4af…`. `scripts/keycheck.py` → `MATCH`, 1024 bits. Le `jwt.pub` de l’image a le même SHA-256 que celui du tag (`89fdb7cb…f338`). La ligne 72 du fichier compilé signe avec `{ expiresIn: '6h', algorithm: 'RS256' }`. | Image locale, lecture seule |

Commande de reproduction :
`python -I scripts/keycheck.py <arbre extrait>/build/lib/insecurity.js <arbre extrait>/encryptionkeys/jwt.pub`.

## Impact

- **Usurpation d’identité / élévation de privilèges :** un jeton signé avec
  cette clé passe toutes les vérifications de signature listées en K-04,
  y compris les routes protégées par `isAuthorized()` (`/rest/basket`,
  `/api/Users`, `/b2b/v2`, routes 2FA…, liste dans [01](../analysis/01-authentification.md)).
  Les contrôles métier qui lisent ensuite les claims (rôle, email, id) reçoivent
  des valeurs choisies par l’émetteur du jeton.
- **Aucune révocation possible sans changement de code :** la clé ne peut pas
  être changée par configuration.
- **Clé faible :** RSA 1024 bits est en dessous du minimum recommandé
  (2048 bits, ANSSI/NIST).

Juice Shop est volontairement vulnérable; ce défaut sert probablement un
challenge. Pour l’audit, cela ne change pas le constat : la configuration livrée
dans l’image accepte des jetons signés par n’importe qui.

## Correction proposée (pour la phase P6)

1. Supprimer la constante `privateKey`; charger la clé au démarrage depuis un
   secret d’exécution (variable d’environnement, fichier monté, gestionnaire de
   secrets) absent de l’image et du dépôt.
2. Générer une nouvelle paire **RSA ≥ 2048 bits** (ou ECDSA P-256) par
   déploiement; considérer l’ancienne comme compromise.
3. Utiliser un secret HMAC distinct pour `deluxeToken`.
4. Fixer `algorithms: ['RS256']` à chaque vérification (voir F-001).
5. Contre-audit : nouveau scan secrets Trivy sur l’image reconstruite
   (0 occurrence `private-key` attendue dans `lib/` et `build/`), test de
   connexion fonctionnel, et vérification qu’un jeton signé avec l’ancienne
   clé est refusé.

## Lien avec les autres constats

- [F-001](F-001-jwt-algorithm-confusion.md) : confusion d’algorithmes; F-002
  la rend secondaire tant que la clé privée est publique.
- [F-003](F-003-jetons-sans-expiration.md) : les jetons émis n’ont pas
  d’expiration, ce qui aggrave toute fuite ou falsification.
