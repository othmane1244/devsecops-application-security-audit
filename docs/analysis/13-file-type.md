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

Les chemins Trivy identifient l’installation et les parents immédiats; ils ne prouvent pas à eux seuls que chaque parent est appelé au runtime. La vérification Docker en lecture seule ci-dessous confirme maintenant, pour le chemin de profil, l’appel dans le JavaScript compilé présent dans le conteneur arrêté dont les couches correspondent au rapport. Les sources publiées des consommateurs `download` et `decompress-*` continuent d’indiquer les consommateurs directs des copies imbriquées; leur utilisation applicative n’est pas déduite du seul arbre de dépendances.

## Avis officiel et mécanisme

L’avis mainteneur GHSA-5v7r-6r5c-r473 indique comme versions affectées `>=13.0.0, <21.3.1` et comme version corrigée `21.3.1`. Un fichier ASF (conteneurs WMV/WMA) forgé avec une sous-en-tête de taille nulle fait calculer une charge utile `-24`; `tokenizer.ignore(payload)` recule alors la position et la boucle relit la même sous-en-tête sans fin. L’avis indique qu’un fichier de 55 octets suffit à bloquer la boucle événementielle lorsque l’application demande à `file-type` d’identifier une entrée non fiable ou contrôlée par un attaquant [1].

La source publiée exacte de `file-type@16.5.4` contient bien le chemin ASF concerné : détection de la signature ASF, calcul `header.size - 24`, boucle de lecture et appel à `tokenizer.ignore(payload)` [3, extrait 1]. Cette version est dans la plage affectée; les copies `11.1.0`, `3.9.0`, `4.4.0`, `5.2.0` et `6.2.0` sont en dessous du seuil minimal de l’avis et ne sont pas concernées par ce GHSA.

Le correctif publié ajoute un contrôle de progression : il mémorise la position avant lecture et quitte la boucle si la position n’a pas avancé après `ignore` [4]. La source v16.5.4 commente que l’en-tête doit être recherché dans le premier KiB, mais la condition de boucle affichée ne borne pas explicitement la position à 1 KiB; ce commentaire ne neutralise donc pas le cas de recul décrit par l’avis.

## Provenance des octets et contrôles applicatifs

Dans les sources publiées du tag v20.3.0, `server.ts` configure `multer.memoryStorage()` avec une limite `fileSize: 200000` octets [2]. Le même fichier monte séparément `/file-upload`, `/profile/image/file` et `/profile/image/url`. La route URL récupère son contenu avec `fetch(url)` et l’écrit directement dans les fichiers d’images; le code source publié consulté ne passe pas ces octets à `file-type` [5]. La validation du formulaire `/file-upload` inspecte l’extension du nom de fichier plutôt que sa signature [6].

Le flux pertinent est confirmé : le gestionnaire compilé de `POST /profile/image/file` appelle `fileType.fromBuffer(file.buffer)`. Multer conserve l’upload en mémoire avec une limite de 200 000 octets, supérieure aux 55 octets décrits par l’avis. La route n’utilise pas les middlewares de challenge `checkUploadSize` et `checkFileType` montés sur `/file-upload`; elle applique son propre contrôle MIME dans le gestionnaire. L’authentification de l’utilisateur est vérifiée après l’analyse du buffer, donc elle ne protège pas ce parsing. Cela confirme un chemin de code disponible, pas une requête reçue ni une exploitation.

| Élément | État des preuves |
| --- | --- |
| Version affectée installée | Confirmée par le rapport initial : `InstalledVersion: 16.5.4`, chemin racine; CVE MEDIUM. Le champ Trivy `Status: fixed` se rapporte à la disponibilité du correctif (21.3.1), pas à l’installation détectée. |
| Fonction vulnérable disponible | Confirmée dans `file-type@16.5.4/core.js` : parsing ASF et boucle vulnérable (extrait 1). |
| Octets contrôlables atteignant la fonction | Confirmé dans le gestionnaire compilé du chemin multipart : `file.buffer` est passé à `fileType.fromBuffer`; limite Multer de 200 000 octets. Aucun upload n’a été soumis. |
| Contrôle de type / authentification | Le parseur est appelé avant l’authentification. Après parsing, `undefined` donne une erreur 500 « Illegal file type »; `null` ou un MIME ne commençant pas par `image` donne 415. |
| Traitement d’erreur | Les erreurs d’écriture sont consignées par `logger.warn` puis le handler poursuit; les erreurs de mise à jour du modèle passent à `next(error)`. Le routeur enveloppe le handler dans `utils.asyncHandler`, mais l’implémentation compilée de ce helper est tronquée dans l’image avant son corps : le forwarding d’un rejet de `fromBuffer` n’est pas confirmé par ce fichier. |
| Exploitation / blocage en production | Non démontrés; aucune requête ou exploitation n’a été exécutée. |

## Conclusion

Le rapport initial et le manifeste de l’image confirment `file-type@16.5.4`; le code compilé du gestionnaire appelle son parseur sur le buffer multipart du profil. Les contrôles MIME viennent après ce parsing; l’authentification vérifiée dans le handler vient également après. La taille maximale Multer de 200 000 octets n’exclut pas le fichier de 55 octets décrit par l’avis. **Le chemin d’analyse est donc présent dans l’artefact inspecté**, mais aucune requête n’a été effectuée et le conteneur est arrêté : l’exposition en cours ou une exploitation ne sont pas démontrées. Le forwarding des rejets asynchrones reste incertain car le fichier compilé `build/lib/utils.js` s’arrête dans un commentaire avant l’implémentation annoncée d’`asyncHandler`. Les anciennes copies listées par Trivy sont hors de la plage de versions de cet avis. Le statut Trivy `fixed` indique toujours qu’un correctif existe (`21.3.1`), pas que l’installation `16.5.4` est corrigée.

## Limites de vérification

### Complément — vérification Docker en lecture seule (28 octobre 2026)

- **D-01 — moteur et image.** Le client Docker 29.1.2 et le moteur Linux sont accessibles dans le contexte `desktop-linux`. Le tag local `bkimminich/juice-shop:v20.3.0` existe. Ses 24 `RootFS.Layers` sont identiques aux 24 `Metadata.DiffIDs` du rapport Trivy initial. L’ID Docker local (`sha256:cea5a4…`) diffère toutefois de `Metadata.ImageID` dans le rapport (`sha256:40606c…`); la concordance des couches confirme le même contenu de couches, sans effacer cette divergence d’identifiant/configuration.
- **D-02 — conteneur existant, pas état runtime.** `juice-shop-audit` référence l’ID local, n’a aucun montage et est à l’état `exited` (code 255). Aucun conteneur Juice Shop n’est en cours d’exécution. Son environnement stocké ne contient que les noms `PATH` et `SSL_CERT_FILE`; aucun réglage Juice Shop de profil/challenge, port ou chemin de base n’est défini. Le conteneur a des changements de fichiers sous `data`, `frontend`, `ftp`, `i18n` et `logs`; `docker diff` n’en signale pas sous `build`, `config`, `routes` ou `server.ts`. Ces constats ne décrivent pas une exécution active.
- **D-03 — route et parser compilés.** Dans le système de fichiers inchangé à ces chemins, `build/server.js:345` monte `POST /profile/image/file` avec `uploadToMemory.single('file')`, `ensureFileIsPassed`, la métrique puis `utils.asyncHandler(profileImageFileUpload())`. `build/server.js:690` configure Multer en mémoire, avec `fileSize: 200000`. `build/routes/profileImageFileUpload.js:53-90` importe `file-type`, vérifie que le buffer existe, appelle `file_type_1.default.fromBuffer(buffer)`, rejette les types non `image`, vérifie ensuite le cookie utilisateur, écrit l’image et met à jour le modèle. Le manifeste `node_modules/file-type/package.json` indique `16.5.4`, concordant avec le finding.
- **D-04 — contrôles et erreurs.** Le middleware `ensureFileIsPassed` (`build/routes/fileUpload.js`) retourne 400 si aucun fichier n’est reçu. Dans le handler, un buffer absent ou un résultat `undefined` donne 500; un résultat `null` ou un MIME qui ne commence pas par `image` donne 415. Une absence d’utilisateur transmet une erreur à Express. L’échec d’écriture est seulement journalisé; l’échec de mise à jour utilisateur passe à `next(error)`. Le routeur appelle `utils.asyncHandler`, mais le fichier compilé `build/lib/utils.js` (9 457 octets) se termine au milieu d’un commentaire après les déclarations d’exports; son corps n’est pas vérifiable et le forwarding des rejets du parser reste donc incertain. La cause de l’état de sortie 255 n’a pas été recherchée.
- **D-05 — fichiers de configuration de l’image.** `config/default.yml:89` fixe le défaut image `challenges.safetyMode: auto`. Les profils présents `ctf.yml:12` et `defcon33.yml:48` contiennent `disabled`; `unsafe.yml:2` contient littéralement `disable` (forme différente des valeurs `enabled`, `disabled`, `auto` documentées dans le commentaire de `default.yml`). L’effet de cette valeur ne doit pas être supposé. Les chemins de configuration sont inchangés dans le conteneur arrêté et aucun environnement applicatif n’est défini; cela n’identifie pas le profil qui aurait été chargé lors d’une exécution passée.

Les contenus ci-dessus ont été lus via le système de fichiers du conteneur arrêté; l’identité des couches avec le rapport, l’absence de montage et l’absence de changements dans les chemins cités les relient à l’image analysée. Ils prouvent le contenu statique de l’artefact, **pas la configuration ou le comportement runtime**. Aucun conteneur n’a été démarré; aucun scan, appel applicatif ou test d’exploitation n’a été lancé.

## Extraits numérotés

1. `file-type@16.5.4/core.js` (tag immuable), lignes 1012–1051 : signature ASF, lecture du sous-en-tête, `payload = header.size - 24`, boucle et `tokenizer.ignore(payload)`. [Source versionnée](https://github.com/sindresorhus/file-type/blob/v16.5.4/core.js#L1012-L1051)
2. Juice Shop v20.3.0 `server.ts` (tag immuable), lignes 117, 338–339 et 722 : import/montage de la route et limite Multer de 200 000 octets. [Source versionnée](https://github.com/juice-shop/juice-shop/blob/v20.3.0/server.ts)
3. Juice Shop v20.3.0 `package.json`, ligne 117 : dépendance directe `file-type: ^16.5.4`. [Source versionnée](https://github.com/juice-shop/juice-shop/blob/v20.3.0/package.json#L117)
4. Correctif mainteneur, commit `319abf871b50ba2fa221b4a7050059f1ae096f4f`, contrôle que le tokenizer avance après l’ignorance du payload. [Commit exact](https://github.com/sindresorhus/file-type/commit/319abf871b50ba2fa221b4a7050059f1ae096f4f)
5. Juice Shop v20.3.0 `routes/profileImageUrlUpload.ts`, lignes 14–39 : téléchargement `fetch(url)`, écriture du flux reçu, aucun appel à `file-type` dans cette route. [Source versionnée](https://github.com/juice-shop/juice-shop/blob/v20.3.0/routes/profileImageUrlUpload.ts)
6. Juice Shop v20.3.0 `routes/fileUpload.ts`, lignes 56–63 : contrôle d’extension par `originalname`; ce n’est pas une détection de signature par `file-type`. [Source versionnée](https://github.com/juice-shop/juice-shop/blob/v20.3.0/routes/fileUpload.ts)
7. Fichiers compilés et configuration lus en lecture seule depuis le conteneur arrêté `juice-shop-audit` : `build/server.js`, `build/routes/profileImageFileUpload.js`, `build/lib/utils.js`, `node_modules/file-type/package.json` et `config/{default,ctf,defcon33,unsafe}.yml`. Pour les preuves Docker, voir D-01 à D-05 ci-dessus; elles ne sont pas des preuves runtime.

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
