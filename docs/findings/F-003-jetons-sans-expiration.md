# F-003 — Jetons d’authentification émis sans expiration

## Résumé

`authorize()` demande une durée de vie de 6 heures avec l’option
`expiresIn: '6h'`. Mais la bibliothèque réellement importée,
`jsonwebtoken@0.4.0`, ne connaît pas cette option : elle ne gère que
`expiresInMinutes`. Le champ `exp` n’est donc jamais ajouté, et les deux
versions de `jsonwebtoken` présentes n’imposent une expiration que si `exp`
existe. Un jeton émis reste valide indéfiniment, tant que la clé de signature
ne change pas.

**Statut : confirmé statiquement (code de l’application + archive npm exacte).
Aucun jeton n’a été émis ni testé.** **Priorité proposée : P2** (aggrave F-002
et tout vol de jeton; pas exploitable seul).

## Preuves

| ID | Preuve | Source |
|---|---|---|
| E-01 | `lib/insecurity.ts:54` : `jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })`. | Source publiée [v20.3.0](https://github.com/juice-shop/juice-shop/blob/v20.3.0/lib/insecurity.ts) |
| E-02 | L’import `jsonwebtoken` de `lib/insecurity.ts` se résout vers la copie racine `0.4.0` dans l’image. | [01, section 2](../analysis/01-authentification.md); rapport Trivy initial |
| E-03 | Archive npm exacte `jsonwebtoken-0.4.0.tgz`, `package/index.js` : `sign()` ajoute `exp` **seulement** si `options.expiresInMinutes` (lignes 14–16); aucune lecture de `expiresIn`. | [Archive npm](https://registry.npmjs.org/jsonwebtoken/-/jsonwebtoken-0.4.0.tgz), lue le 4 novembre 2026 |
| E-04 | Même fichier, `verify()` : l’expiration n’est contrôlée que `if (payload.exp)` (lignes 50–51). Sans `exp`, aucun refus pour expiration. | Idem |
| E-05 | `jsonwebtoken@0.1.0` (sous `express-jwt`) ne compare `exp` que s’il est présent ([11](../analysis/11-moment.md), `index.js:27-47`). | Archive npm exacte 0.1.0 |

Le support de `expiresIn` (chaîne de durée) n’existe que dans des versions
bien plus récentes de `jsonwebtoken`.

## Impact

- Un jeton volé (XSS, journal, poste partagé) reste utilisable sans limite de
  durée.
- Combiné à [F-002](F-002-cle-privee-jwt-codee-en-dur.md), un jeton forgé n’a
  pas non plus besoin de `exp`.
- La déconnexion côté client ne retire pas la validité du jeton côté serveur.

## Correction proposée

1. Mettre à jour `jsonwebtoken` vers une version maintenue (≥ 9.0.0, ce qui
   corrige aussi CVE-2022-23539/23540/23541) et `express-jwt` (qui fige
   aujourd’hui `jsonwebtoken ~0.1.0`).
2. Garder `expiresIn` et exiger `exp` à la vérification.
3. Contre-audit : décoder un jeton émis par l’image corrigée et vérifier la
   présence de `exp` ≈ `iat + 21600`; vérifier qu’un jeton expiré est refusé.

## Limites

La copie compilée de l’image (`build/lib/insecurity.js:72`, lue le
4 novembre 2026 depuis un conteneur créé et jamais démarré) contient la même
option `expiresIn: '6h'`. Aucun test dynamique n’a été réalisé : l’absence de
`exp` est déduite du code exact de `jsonwebtoken@0.4.0`, pas observée sur un
jeton émis.
