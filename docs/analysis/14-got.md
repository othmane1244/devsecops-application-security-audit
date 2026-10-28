# Analyse de Got

## Périmètre et détection

Le rapport Trivy initial signale une seule installation de `got@8.3.2`, chemin `juice-shop/node_modules/got/package.json`, avec une détection MEDIUM `CVE-2022-33987` / `GHSA-pfrx-2q88-qq97`. Il donne `InstalledVersion: 8.3.2`, `FixedVersion: 12.1.0, 11.8.5` et `Status: fixed`. Ce statut signifie qu’un correctif existe dans les branches indiquées; il ne signifie pas que la copie installée est corrigée. La branche 8.3.2 reste antérieure aux versions correctives. L’inventaire du rapport HIGH/CRITICAL contient aussi la copie, mais le filtre ne conserve aucune alerte Got puisqu’il s’agit d’une détection MEDIUM.

Dans l’arbre relevé par les rapports et l’analyse 09, `download@8.0.0` consomme cette copie de Got; `download@8.0.0` déclare `got: ^8.3.1`, résolu en `8.3.2` dans l’image. Juice Shop déclare `download` et son code publié l’importe dans `lib/utils.ts`. Aucun import direct de Got par le code applicatif n’a été trouvé dans le chemin examiné. L’analyse 08 de `basic-ftp` porte sur une autre chaîne dépendance et n’ajoute pas de consommateur Got.

## Avis officiel et prérequis

L’avis officiel GitHub décrit une possibilité de rediriger une requête Got vers un socket UNIX. Il déclare affectées les versions `<11.8.5` et `>=12.0.0, <12.1.0`; les versions correctives indiquées sont `11.8.5` et `12.1.0` [1]. Le prérequis applicatif important est un appel Got qui suit une redirection dont la destination désigne un socket UNIX. Le chemin observé doit donc recevoir une URL initiale téléchargeable et une réponse HTTP avec redirection vers cette destination; les possibilités réelles dépendent aussi de l’existence et des permissions du socket sur l’hôte.

Got 8.3.2 suit par défaut les redirections (`followRedirect: true`), résout la valeur `Location`, reconstruit des options depuis cette cible et appelle à nouveau le chemin de requête. Il limite le nombre de redirections à dix, mais le code versionné ne montre pas de contrôle explicite rejetant une destination `unix` dans cette branche [4, extraits 2–3]. Le même fichier prend en charge une URL de socket en transformant `unix:` en URL HTTP dont l’hôte est `unix`, puis en extrayant `socketPath` [4, extrait 4]. Le correctif amont ajoute un contrôle qui refuse une redirection d’une URL non socket vers une URL socket [2]. Ces éléments concordent avec l’avis; ils confirment le mécanisme disponible dans le code publié 8.3.2 sans démontrer qu’un appel de l’application auditée a effectivement suivi une telle redirection.

## Consommateur et flux d’URL dans Juice Shop

La chaîne observée dans les sources publiées est :

```text
server.start()
└─ customizeApplication()
   └─ retrieveCustomFile(config property, destination)
      └─ utils.downloadToFile(url, destination)
         └─ download@8.0.0(url, { agent: proxyAgent })
            └─ got@8.3.2.stream(url, options)
               └─ suit les redirections HTTP par défaut
```

`customizeApplication` appelle `retrieveCustomFile` pour le logo, le favicon, la vidéo et les sous-titres promotionnels, l’avatar du chatbot et celui de l’instructeur. `retrieveCustomFile` obtient l’URL depuis `config`, puis appelle le téléchargement seulement si `utils.isUrl(file)` renvoie vrai; cette fonction teste uniquement le préfixe `http`. `downloadToFile` utilise `download(url, { agent: proxyAgent })`, écrit le buffer dans le fichier de destination et intercepte les erreurs pour journaliser un avertissement et retourner `false` [5–7]. `download@8.0.0` appelle `got.stream(uri, opts)` et transmet ses options, sans fournir `followRedirect: false` [8].

### Origine des valeurs

Dans `config/default.yml` du tag v20.3.0, les propriétés de personnalisation par défaut sont des noms de fichiers locaux (`JuiceShop_Logo.png`, `favicon_js.ico`, `owasp_promo.mp4`, `owasp_promo.vtt`, noms d’avatars locaux). Elles ne passent donc pas par le téléchargement HTTP avec la configuration par défaut [9]. Les mêmes propriétés peuvent être redéfinies dans la configuration de déploiement; lorsqu’une valeur commence par `http`, elle est transmise à `download` sans liste de domaines autorisés ni désactivation des redirections dans le code observé.

Aucune donnée de route ou entrée utilisateur directe n’a été trouvée dans cette chaîne. L’entrée est une configuration, par défaut fixe et locale; une surcharge runtime peut la rendre distante. Une deuxième possibilité conditionnelle est qu’un hôte de téléchargement distant fournisse le header `Location` pointant vers une URL de socket. Le réglage runtime exact et l’existence d’un tel serveur/socket ne sont pas établis par les rapports.

## Options, contrôles et erreurs

| Contrôle / option | Preuve dans les sources publiées | Portée |
|---|---|---|
| Agent | L’application passe `agent: proxyAgent`; le Got est appelé avec cette option propagée par `download`. | Change le transport/proxy; ne désactive pas le suivi des redirections. La configuration effective du proxy n’est pas connue. |
| `followRedirect` | Aucun override n’est passé dans l’appel observé; Got 8.3.2 fixe le défaut à `true`. | Une réponse avec `Location` peut déclencher un nouvel appel. |
| Nombre de redirections | Got lève `MaxRedirectsError` à partir de dix suivis. | Borne les redirections successives; ne filtre pas la cible selon son hôte ou son type de socket. |
| Validation de l’URL applicative | `utils.isUrl` vérifie seulement `startsWith('http')`. | Filtre les valeurs non HTTP de configuration, sans restreindre l’hôte ou les redirections. |
| Délai et reprises | Got définit deux retries par défaut; l’appel ne fournit pas d’option de timeout. | Les erreurs réessayables peuvent être reprises; aucun délai applicatif explicite n’est établi dans ce chemin. |
| Erreurs de téléchargement | `downloadToFile` capture l’erreur, la journalise et retourne `false`; `retrieveCustomFile` retourne alors `undefined`. | Le flux d’échec de personnalisation est traité; ce traitement ne bloque pas une destination socket avant la tentative. |

## État des preuves et conclusion

| Proposition | État |
|---|---|
| Got 8.3.2 installé dans l’image selon Trivy | Confirmé par le rapport initial; le statut Trivy `fixed` indique la disponibilité d’une correction, pas une mise à niveau de l’installation. |
| Fonctionnalité d’URL et redirection concernée disponible dans Got 8.3.2 publié | Confirmée par les sources versionnées, compatible avec l’avis officiel. |
| Consommateur applicatif indirect | Confirmé dans les sources publiées : `download@8.0.0` → `got.stream`, appelé par `downloadToFile` pour les personnalisations configurables. |
| URL directement fournie par une requête utilisateur | Non observée dans ce chemin. |
| URL distante de configuration dans les valeurs par défaut | Absente : les valeurs par défaut publiées sont locales. Une surcharge de configuration peut fournir une URL HTTP. |
| Redirection effective vers un socket UNIX | Non observée; aucun événement réseau ni runtime n’a été testé. |
| Exploitation / accès à un service local | Non démontrés. |

La détection du composant vulnérable est fondée : la copie signalée est `8.3.2`, comprise dans la plage décrite par l’avis, et le chemin Got vulnérable existe dans la source publiée exacte. Le consommateur applicatif est indirect et conditionnel : au démarrage, des personnalisations configurées comme URL HTTP peuvent atteindre Got via `download`; la configuration par défaut utilise des fichiers locaux. Une redirection vers un socket UNIX nécessiterait une réponse distante correspondante et un socket utilisable sur l’hôte. Ces prérequis ne sont pas établis pour l’instance de l’image; aucune exploitation n’est démontrée.

## Limites de vérification

Le rapport initial prouve la version et le chemin de paquet inventoriés. Lors de cette analyse, le daemon Docker était indisponible; les manifestes, le code et la configuration de l’image n’ont donc pas été extraits ou comparés directement. Le contrôle ultérieur du 28 octobre a rendu Docker accessible et confirmé l’égalité des 24 DiffIDs avec le rapport, mais n’a pas relu les fichiers Got ni vérifié la configuration runtime. Les preuves des appels applicatifs de cette fiche proviennent toujours des sources publiées au tag Juice Shop v20.3.0. L’analyse 09 confirme déjà la chaîne `download@8.0.0 → got@8.3.2 → cacheable-request@2.1.4`; sa conclusion sur le cache ne remplace pas l’examen des redirections mené ici. Aucun scan, test, requête de test ou test d’exploitation n’a été effectué.

## Extraits numérotés

1. Rapport Trivy initial : inventaire `got@8.3.2` et chemin `juice-shop/node_modules/got/package.json` (lignes 9161–9168); détection `CVE-2022-33987` (lignes 17625–17724). Rapport HIGH/CRITICAL : inventaire Got aux lignes 7401–7408, sans finding Got conservé.
2. Correctif Got, commit `861ccd9ac2237df762a9e2beed7edd88c60782dc` : refuse la redirection d’une URL non socket vers une URL socket (`isUnixSocketURL(url)` / `isUnixSocketURL(redirectUrl)`). [Diff exact](https://github.com/sindresorhus/got/commit/861ccd9ac2237df762a9e2beed7edd88c60782dc)
3. Got 8.3.2 `index.js`, lignes 73–83, 106–134 et 590–592 : protocoles HTTP(S), suivi des redirections, résolution de `Location`, réappel et défaut `followRedirect: true`. [Source taggée](https://github.com/sindresorhus/got/blob/v8.3.2/index.js#L73-L134) (défaut : [lignes 590–592](https://github.com/sindresorhus/got/blob/v8.3.2/index.js#L590-L592))
4. Got 8.3.2 `index.js`, lignes 469–500 et 567–575 : parse des URL, transformation de `unix:` et affectation de `socketPath`. [Source taggée](https://github.com/sindresorhus/got/blob/v8.3.2/index.js#L469-L575)
5. Juice Shop v20.3.0 `lib/utils.ts`, lignes 9–10, 21 et 101–113 : `download`, `ProxyAgent`, construction d’agent et `downloadToFile`. [Source taggée](https://github.com/juice-shop/juice-shop/blob/v20.3.0/lib/utils.ts#L9-L113)
6. Juice Shop v20.3.0 `lib/startup/customizeApplication.ts`, lignes 10–35, 37–87 : appels de personnalisation, valeurs issues de `config`, filtre `isUrl` et appel de téléchargement. [Source taggée](https://github.com/juice-shop/juice-shop/blob/v20.3.0/lib/startup/customizeApplication.ts#L10-L87)
7. Juice Shop v20.3.0 `server.ts`, lignes 711–738 : lancement de `customizeApplication` au démarrage. [Source taggée](https://github.com/juice-shop/juice-shop/blob/v20.3.0/server.ts#L711-L738)
8. `download@8.0.0` `index.js`, lignes 57–68 : appel `got.stream(uri, opts)`; `package.json`, lignes 27–38 : dépendance Got `^8.3.1`. [Source taggée](https://github.com/kevva/download/tree/v8.0.0)
9. Juice Shop v20.3.0 `config/default.yml`, lignes 7–9, 17–20, 58–60 et 96–99 : noms de fichiers locaux par défaut. [Configuration taggée](https://github.com/juice-shop/juice-shop/blob/v20.3.0/config/default.yml)

## Références

- [GHSA-pfrx-2q88-qq97 / CVE-2022-33987 — avis officiel GitHub](https://github.com/advisories/GHSA-pfrx-2q88-qq97)
- [Got 8.3.2 `index.js`](https://github.com/sindresorhus/got/blob/v8.3.2/index.js)
- [Correctif Got exact `861ccd9ac2237df762a9e2beed7edd88c60782dc`](https://github.com/sindresorhus/got/commit/861ccd9ac2237df762a9e2beed7edd88c60782dc)
- [`download@8.0.0` `index.js` et `package.json`](https://github.com/kevva/download/tree/v8.0.0)
- [Juice Shop v20.3.0 `lib/utils.ts`](https://github.com/juice-shop/juice-shop/blob/v20.3.0/lib/utils.ts)
- [Juice Shop v20.3.0 `lib/startup/customizeApplication.ts`](https://github.com/juice-shop/juice-shop/blob/v20.3.0/lib/startup/customizeApplication.ts)
- [Juice Shop v20.3.0 `server.ts`](https://github.com/juice-shop/juice-shop/blob/v20.3.0/server.ts)
- [Juice Shop v20.3.0 `config/default.yml`](https://github.com/juice-shop/juice-shop/blob/v20.3.0/config/default.yml)
- [Analyse connexe 09 — http-cache-semantics](09-http-cache-semantics.md), pour l’installation imbriquée et le chemin de cache (distinct des redirections).
- Rapport Trivy initial : `reports/trivy-image-initial.json`, lignes 9161–9168 et 17625–17724.
- Rapport HIGH/CRITICAL : `reports/trivy-image-high-critical.json`, lignes 7401–7408; aucun finding Got.
