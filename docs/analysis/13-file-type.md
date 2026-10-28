# Analyse de `file-type`

## Périmètre et détections

Le rapport Trivy initial inventorie sept installations sous `juice-shop/node_modules` : `file-type@16.5.4` à la racine, `11.1.0` sous `download`, `3.9.0` sous `decompress-unzip`, `4.4.0` sous `archive-type`, deux copies `5.2.0` sous `decompress-tar` et `decompress-targz`, et `6.2.0` sous `decompress-tarbz2`. Le rapport signale une détection `CVE-2026-31808`, MEDIUM, sur la copie racine `16.5.4` (`juice-shop/node_modules/file-type/package.json`). Le champ `Status: fixed` et `FixedVersion: 21.3.1` indiquent qu’une version correctrice est publiée; ils ne signifient pas que l’installation est déjà corrigée : `InstalledVersion` reste `16.5.4`, dans la plage affectée. Le rapport HIGH/CRITICAL n’a aucune détection `file-type`.

| Version | Chemin de paquet dans le rapport initial | Relation de dépendance établie par le chemin |
| --- | --- | --- |
| 16.5.4 | `juice-shop/node_modules/file-type/package.json` | Dépendance directe déclarée par Juice Shop (`^16.5.4` dans le tag publié v20.3.0) |
| 11.1.0 | `juice-shop/node_modules/download/node_modules/file-type/package.json` | Copie imbriquée sous `download@8.0.0` |
| 3.9.0 | `juice-shop/node_modules/decompress-unzip/node_modules/file-type/package.json` | Copie imbriquée sous `decompress-unzip@4.0.1` |
| 4.4.0 | `juice-shop/node_modules/archive-type/node_modules/file-type/package.json` | Copie imbriquée sous `archive-type@4.0.0` |
| 5.2.0 | `juice-shop/node_modules/decompress-tar/node_modules/file-type/package.json` | Copie imbriquée sous `decompress-tar@4.1.1` |
| 5.2.0 | `juice-shop/node_modules/decompress-targz/node_modules/file-type/package.json` | Copie imbriquée sous `decompress-targz@4.1.1` |
| 6.2.0 | `juice-shop/node_modules/decompress-tarbz2/node_modules/file-type/package.json` | Copie imbriquée sous `decompress-tarbz2@4.1.1` |

Les chemins Trivy identifient l’installation et les parents immédiats; les rapports résolvent aussi les versions de ces parents ci-dessus. Ils ne prouvent pas à eux seuls que chaque parent est appelé au runtime. La source publiée de Juice Shop v20.3.0 déclare `download` et `file-type` comme dépendances directes. `server.ts` importe et monte le gestionnaire d’upload de profil sur `POST /profile/image/file` [2]. Le fichier source exact de ce gestionnaire n’a pas pu être chargé pendant cette vérification; l’appel précis à l’API `file-type` et ses contrôles ne sont donc pas présentés comme établis par le code de l’image. Les sources versionnées de `download` et des paquets `decompress-*` indiquent les consommateurs directs de leurs copies imbriquées, mais leur utilisation applicative n’est pas déduite du seul arbre de dépendances.

## Avis officiel et mécanisme

L’avis mainteneur GHSA-5v7r-6r5c-r473 indique comme versions affectées `>=13.0.0, <21.3.1` et comme version corrigée `21.3.1`. Un fichier ASF (conteneurs WMV/WMA) forgé avec une sous-en-tête de taille nulle fait calculer une charge utile `-24`; `tokenizer.ignore(payload)` recule alors la position et la boucle relit la même sous-en-tête sans fin. L’avis indique qu’un fichier de 55 octets suffit à bloquer la boucle événementielle lorsque l’application demande à `file-type` d’identifier une entrée non fiable ou contrôlée par un attaquant [1].

La source publiée exacte de `file-type@16.5.4` contient bien le chemin ASF concerné : détection de la signature ASF, calcul `header.size - 24`, boucle de lecture et appel à `tokenizer.ignore(payload)` [3, extrait 1]. Cette version est dans la plage affectée; les copies `11.1.0`, `3.9.0`, `4.4.0`, `5.2.0` et `6.2.0` sont en dessous du seuil minimal de l’avis et ne sont pas concernées par ce GHSA.

Le correctif publié ajoute un contrôle de progression : il mémorise la position avant lecture et quitte la boucle si la position n’a pas avancé après `ignore` [4]. La source v16.5.4 commente que l’en-tête doit être recherché dans le premier KiB, mais la condition de boucle affichée ne borne pas explicitement la position à 1 KiB; ce commentaire ne neutralise donc pas le cas de recul décrit par l’avis.

## Provenance des octets et contrôles applicatifs

Dans les sources publiées du tag v20.3.0, `server.ts` configure `multer.memoryStorage()` avec une limite `fileSize: 200000` octets [2]. Le même fichier monte séparément `/file-upload`, `/profile/image/file` et `/profile/image/url`. La route URL récupère son contenu avec `fetch(url)` et l’écrit directement dans les fichiers d’images; le code source publié consulté ne passe pas ces octets à `file-type` [5]. La validation du formulaire `/file-upload` inspecte l’extension du nom de fichier plutôt que sa signature [6].

Le flux pertinent pour `CVE-2026-31808` est donc l’upload multipart en mémoire associé à `/profile/image/file`, si le gestionnaire importé appelle effectivement `file-type` sur `file.buffer`. La limite Multer de 200 000 octets est supérieure aux 55 octets décrits dans l’avis et ne suffit pas à éliminer ce prérequis. La route est publiée parmi les endpoints de profil; les sources consultées ne démontrent pas ici ses exigences d’authentification, les vérifications du type détecté, la gestion d’erreur autour de l’analyse, ni la présence effective du chemin dans l’image auditée. Aucun appel sur fichier local, téléchargement d’URL ou données fixes n’a été établi pour la copie racine vulnérable.

| Élément | État des preuves |
| --- | --- |
| Version affectée installée | Confirmée par le rapport initial : `InstalledVersion: 16.5.4`, chemin racine; CVE MEDIUM. Le champ Trivy `Status: fixed` se rapporte à la disponibilité du correctif (21.3.1), pas à l’installation détectée. |
| Fonction vulnérable disponible | Confirmée dans `file-type@16.5.4/core.js` : parsing ASF et boucle vulnérable (extrait 1). |
| Octets contrôlables atteignant la fonction | Chemin d’upload multipart publié et limite 200 000 octets confirmés; appel précis du handler de profil au parseur non confirmé faute d’accès à son fichier source dans cette vérification. |
| Contrôle de type / traitement d’erreur du handler | Inconnu pour la copie de l’image; ne pas inférer depuis l’extension seule de `/file-upload`. |
| Exploitation / blocage en production | Non démontrés; aucune requête ou exploitation n’a été exécutée. |

## Conclusion

Le mécanisme vulnérable est présent dans les sources publiées de `file-type@16.5.4`, et le rapport initial confirme l’installation de cette version dans l’image analysée. Le statut Trivy `fixed` ne veut pas dire que l’image est corrigée : la version détectée reste affectée et la version fixée annoncée est `21.3.1`. L’application publiée expose un upload de fichier en mémoire limité à 200 000 octets, mais le raccord précis entre les octets reçus et le parseur ASF doit être confirmé dans le gestionnaire de profil et dans les fichiers de l’image. La détection du composant vulnérable est confirmée; l’exposition effective au chemin vulnérable et une exploitation ne sont pas démontrées. Les anciennes copies listées par Trivy sont hors de la plage de versions de cet avis.

## Limites de vérification

Le daemon Docker reste indisponible; les fichiers installés, le gestionnaire de profil compilé et la configuration de l’image n’ont pas pu être extraits ou comparés directement aux sources publiées. Le fetch du fichier source du gestionnaire de profil au tag v20.3.0 a également échoué dans l’outil de consultation. Les manifestes publiés et les rapports sont donc des preuves distinctes, et leur identité octet pour octet n’est pas établie. Aucun test, scan, requête ou test d’exploitation n’a été effectué.

## Extraits numérotés

1. `file-type@16.5.4/core.js` (tag immuable), lignes 1012–1051 : signature ASF, lecture du sous-en-tête, `payload = header.size - 24`, boucle et `tokenizer.ignore(payload)`. [Source versionnée](https://github.com/sindresorhus/file-type/blob/v16.5.4/core.js#L1012-L1051)
2. Juice Shop v20.3.0 `server.ts` (tag immuable), lignes 117, 2384–2391 et 674–710 : import et montage des routes, limite Multer de 200 000 octets et configuration de mémoire/disque. [Source versionnée](https://github.com/juice-shop/juice-shop/blob/v20.3.0/server.ts)
3. Juice Shop v20.3.0 `package.json`, ligne 117 : dépendance directe `file-type: ^16.5.4`. [Source versionnée](https://github.com/juice-shop/juice-shop/blob/v20.3.0/package.json#L117)
4. Correctif mainteneur, commit `319abf871b50ba2fa221b4a7050059f1ae096f4f`, contrôle que le tokenizer avance après l’ignorance du payload. [Commit exact](https://github.com/sindresorhus/file-type/commit/319abf871b50ba2fa221b4a7050059f1ae096f4f)
5. Juice Shop v20.3.0 `routes/profileImageUrlUpload.ts`, lignes 14–39 : téléchargement `fetch(url)`, écriture du flux reçu, aucun appel à `file-type` dans cette route. [Source versionnée](https://github.com/juice-shop/juice-shop/blob/v20.3.0/routes/profileImageUrlUpload.ts)
6. Juice Shop v20.3.0 `routes/fileUpload.ts`, lignes 56–63 : contrôle d’extension par `originalname`; ce n’est pas une détection de signature par `file-type`. [Source versionnée](https://github.com/juice-shop/juice-shop/blob/v20.3.0/routes/fileUpload.ts)

## Références

- [GHSA-5v7r-6r5c-r473 — avis officiel du mainteneur](https://github.com/sindresorhus/file-type/security/advisories/GHSA-5v7r-6r5c-r473)
- [file-type v16.5.4 — `core.js`](https://github.com/sindresorhus/file-type/blob/v16.5.4/core.js)
- [Correctif exact `319abf871b50ba2fa221b4a7050059f1ae096f4f`](https://github.com/sindresorhus/file-type/commit/319abf871b50ba2fa221b4a7050059f1ae096f4f)
- [Juice Shop v20.3.0 — package.json](https://github.com/juice-shop/juice-shop/blob/v20.3.0/package.json)
- [Juice Shop v20.3.0 — server.ts](https://github.com/juice-shop/juice-shop/blob/v20.3.0/server.ts)
- [Juice Shop v20.3.0 — profileImageUrlUpload.ts](https://github.com/juice-shop/juice-shop/blob/v20.3.0/routes/profileImageUrlUpload.ts)
- [Juice Shop v20.3.0 — fileUpload.ts](https://github.com/juice-shop/juice-shop/blob/v20.3.0/routes/fileUpload.ts)
- Rapport Trivy initial : `reports/trivy-image-initial.json`, inventaire lignes 8372–8485 et détection lignes 17567–17622.
- Rapport Trivy HIGH/CRITICAL : `reports/trivy-image-high-critical.json`, inventaire lignes 6612–6725; aucune détection `file-type`.
