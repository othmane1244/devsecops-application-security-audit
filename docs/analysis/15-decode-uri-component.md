# Analyse de decode-uri-component

## Détection et installation

Le rapport Trivy initial signale `decode-uri-component@0.2.2`, chemin `juice-shop/node_modules/decode-uri-component/package.json`, pour `CVE-2026-45822` / `GHSA-vcc3-ghjq-m6fr`, gravité MEDIUM. Il indique `FixedVersion: 0.5.0` et `Status: fixed` : un correctif existe, mais la copie installée reste `0.2.2`. Le rapport HIGH/CRITICAL inventorie cette même installation, sans conserver de finding pour elle puisque l’alerte est MEDIUM. Les rapports ne montrent qu’une copie.

Le rapport initial inventorie aussi `query-string@5.1.1`, `normalize-url@2.0.1`, `cacheable-request@2.1.4`, `got@8.3.2` et `download@8.0.0`, tous sous `juice-shop/node_modules/<paquet>/package.json`. Les sources exactes de `query-string@5.1.1` déclarent `decode-uri-component: ^0.2.0`; le résolveur a installé la copie racine `0.2.2`. `normalize-url@2.0.1` dépend de `query-string@^5.0.1`; `cacheable-request@2.1.4` dépend de cette copie de `normalize-url`. C’est la chaîne transitive résolue pertinente :

```text
Juice Shop
└─ download@8.0.0
   └─ got@8.3.2
      └─ cacheable-request@2.1.4
         └─ normalize-url@2.0.1
            └─ query-string@5.1.1
               └─ decode-uri-component@0.2.2
```

Les versions et chemins des paquets signalés viennent des rapports Trivy. Les relations de dépendance et les appels ci-dessous viennent des manifests et sources publiés aux versions précises; Docker était indisponible lors de cette analyse, donc les fichiers embarqués n’avaient pas été comparés directement. Le contrôle ultérieur du 28 octobre a confirmé les 24 couches de l’image, mais n’a pas extrait cette copie de `decode-uri-component`.

## Avis officiel et prérequis

L’avis officiel indique que les versions jusqu’à `0.4.2` sont concernées et que `0.5.0` corrige le défaut. Une entrée contrôlée par un attaquant doit parvenir à `decodeUriComponent()` directement ou par une dépendance qui parse une URL, une query ou un chemin. Les conséquences décrites sont une consommation CPU excessive et une indisponibilité; le contournement officiel est de borner la taille de l’entrée [1]. Le rapport initial décrit le chemin de repli superlinéaire du décodeur et cite des mesures, qui sont reprises ici comme description du rapport et non comme résultats de tests de cette analyse.

La source publiée `decode-uri-component@0.2.2` tente d’abord le `decodeURIComponent` natif. En cas d’exception, elle parcourt les séquences percent encodées, découpe récursivement les composants avec `decodeComponents()` et réessaie le décodage. Le point délicat est la boucle qui reforme et redécoupe les tokens lorsque l’entrée contient des encodages invalides. Le module rejette les arguments qui ne sont pas des chaînes par `TypeError`, mais n’impose aucune limite de longueur dans le code examiné [2].

## Consommateur et chaîne d’appels

Dans `query-string@5.1.1`, `parse(str)` enlève les préfixes `?`, `#` ou `&`, découpe la query sur `&`, sépare chaque paramètre sur `=`, puis appelle `decodeComponent()` sur la valeur et la clé (source exacte, lignes 117–146) [3]. `decodeComponent` est l’import de `decode-uri-component` (ligne 3). `normalize-url@2.0.1` normalise le composant query en le parsant puis en le reformant avec `query-string`; `cacheable-request@2.1.4` construit une clé de requête avec l’URL normalisée. Dans cette version, la normalisation de clé est effectuée avant la branche qui saute les lectures du cache lorsque `opts.cache` vaut `false` [4]. Ainsi, Got peut atteindre ce parseur même avec le cache désactivé; cela n’implique pas que la réponse soit conservée ou réutilisée.

Dans le code applicatif publié de Juice Shop v20.3.0, `downloadToFile(url, dest)` appelle `download(url, { agent: proxyAgent })`; `download@8.0.0` transmet l’URL à `got.stream`. L’appel Got n’ajoute pas d’option `cache`; Got 8.3.2 passe `opts.cache` à `cacheable-request` et sa valeur par défaut est `false` (analyse connexe 09). Le chemin documenté pour les valeurs personnalisées est invoqué au démarrage par `customizeApplication`, qui obtient ses URL de la configuration et appelle le helper de téléchargement si `isUrl(file)` les accepte. Ce contrôle teste seulement le préfixe `http` et n’impose pas de taille maximale [5–6].

Les valeurs de personnalisation de `config/default.yml` sont des noms de fichiers locaux. Elles ne passent donc pas par ce parseur de query dans la configuration publiée par défaut. Une surcharge de configuration peut fournir une URL HTTP et donc des clés et valeurs de query traitées par `query-string`. Aucun chemin repéré ne transmet directement un paramètre d’une requête entrante de l’utilisateur à ce téléchargement. Le fait qu’une URL arbitraire soit configurable en déploiement ne prouve ni que cette configuration a été changée dans l’image auditée, ni qu’un attaquant puisse la modifier.

## Limites, contrôles et erreurs

| Élément | Preuve et portée |
|---|---|
| Type d’argument | `decode-uri-component` exige une chaîne et lève `TypeError` pour les autres types. Dans `query-string.parse`, le paramètre entier est ignoré (résultat vide) si `str` n’est pas une chaîne. |
| Parsing de query | `query-string` parse les clés et valeurs après séparation sur `&` et `=`; les `+` sont remplacés par des espaces avant leur décodage. |
| Taille de l’URL ou de la query | Aucune limite applicative ni limite de longueur transmise à `query-string` ou au décodeur n’a été trouvée dans les appels inspectés. Le contournement documenté par l’avis — limiter la taille — n’est pas mis en œuvre dans ce chemin. |
| Validation applicative de l’URL | `isUrl` vérifie le préfixe `http`; ce n’est pas une limite de longueur ni une validation des composants percent encodés de la query. |
| Erreurs de décodage | Le décodeur natif qui échoue déclenche le chemin de repli; les encodages mal formés sont traités par le décodeur tolérant plutôt que rejetés. Seul un argument de type incorrect provoque ici une erreur explicite de type. |
| Erreurs de téléchargement | `downloadToFile` capture les erreurs du téléchargement, journalise un avertissement et retourne `false`; cette gestion intervient après le traitement de l’URL et ne borne pas le travail du parseur. |
| Cache | Le cache de Got est désactivé par défaut dans l’appel analysé, mais le calcul de l’URL normalisée et le parsing de sa query restent possibles. Aucun stockage ou réemploi de réponse n’est nécessaire au chemin de décodage. |

## Prérequis et conclusion

| Proposition | État |
|---|---|
| Version signalée dans l’image | **Confirmée par Trivy** : une copie `0.2.2`, dans la plage de l’avis; `Status: fixed` signifie qu’une version corrective existe. |
| Fonction vulnérable disponible dans le code exact publié | **Confirmée** : source `0.2.2` avec découpage et reprises récursives sur le chemin de repli. |
| Consommateur indirect réellement résolu selon les rapports et manifests publiés | **Confirmé** : `cacheable-request@2.1.4 → normalize-url@2.0.1 → query-string@5.1.1 → decode-uri-component@0.2.2`. |
| Appel du parseur dans le chemin de normalisation | **Confirmé dans les sources publiées** : `query-string.parse()` décode chaque clé et valeur; `cacheable-request` normalise l’URL avant le branchement de cache désactivé. |
| URL avec query mal formée contrôlée par un attaquant | **Inconnue / conditionnelle** : l’appel de téléchargement observé prend une URL de configuration; les valeurs par défaut sont locales. Le contrôle d’une surcharge runtime et son origine ne sont pas établis. |
| Entrée de route utilisateur transmise à cet appel | **Non observée** dans les sources applicatives examinées. |
| Limite de taille ou validation dédiée des séquences encodées | **Absente** dans les fonctions applicatives et bibliothèques citées. |
| Déni de service effectif ou exploitation | **Non démontrés**; aucune requête de test ni test d’exploitation n’a été effectué. |

La présence d’une version signalée vulnérable et du mécanisme de décodage exact est établie par les rapports et les sources publiées. Le chemin code peut analyser une query d’URL sortante même avec `cache: false`, mais l’appel applicatif retrouvé est alimenté par configuration et les valeurs par défaut sont des chemins locaux. L’exposition à une chaîne spécialement construite dépend donc d’une URL HTTP configurée et d’une possibilité non établie de contrôler cette configuration ou sa valeur. L’applicabilité à l’instance reste conditionnelle; aucune exploitation n’est démontrée.

## Extraits et références

1. Rapport initial : inventaire `decode-uri-component@0.2.2` et chemin aux lignes 7052–7066; finding `CVE-2026-45822`, alias GHSA, description, version corrigée et statut aux lignes 17197–17258. Rapport HIGH/CRITICAL : inventaire aux lignes 5292–5306, sans finding correspondant. JSON inchangés.
2. [`decode-uri-component@0.2.2/index.js`](https://github.com/SamVerschueren/decode-uri-component/blob/v0.2.2/index.js), lignes 1–38 (tokenisation, récursion et boucle de repli), 40–73 (décodage des blocs percent encodés), 75–88 (validation de type, substitution de `+`, tentative native et fallback). [Avis officiel GHSA-vcc3-ghjq-m6fr / CVE-2026-45822](https://github.com/advisories/GHSA-vcc3-ghjq-m6fr), plage affectée, correctif et workaround.
3. [`query-string@5.1.1/index.js`](https://github.com/sindresorhus/query-string/blob/v5.1.1/index.js), ligne 3 (import du décodeur), lignes 117–146 (parse et décodage des clés et valeurs); [`package.json`](https://github.com/sindresorhus/query-string/blob/v5.1.1/package.json), dépendance `decode-uri-component: ^0.2.0`.
4. [`normalize-url@2.0.1/package.json`](https://github.com/sindresorhus/normalize-url/blob/v2.0.1/package.json) déclare `query-string`; [`index.js`](https://github.com/sindresorhus/normalize-url/blob/v2.0.1/index.js) normalise le composant query. [`cacheable-request@2.1.4`, manifest](https://github.com/lukechilds/cacheable-request/blob/3f2d8e2f64af835a82721c51898bd6f08883c4de/package.json) et [`src/index.js`](https://github.com/lukechilds/cacheable-request/blob/3f2d8e2f64af835a82721c51898bd6f08883c4de/src/index.js), dépendance normaliseur et calcul de clé/branche `cache:false`. Le commit `3f2d8e2f64af835a82721c51898bd6f08883c4de` correspond à `2.1.4`.
5. Juice Shop v20.3.0 [`lib/utils.ts`](https://github.com/juice-shop/juice-shop/blob/v20.3.0/lib/utils.ts#L9-L113), téléchargement; [`lib/startup/customizeApplication.ts`](https://github.com/juice-shop/juice-shop/blob/v20.3.0/lib/startup/customizeApplication.ts#L10-L87), valeurs de configuration, contrôle `isUrl` et appels; [`server.ts`](https://github.com/juice-shop/juice-shop/blob/v20.3.0/server.ts#L711-L738), appel au démarrage; [`config/default.yml`](https://github.com/juice-shop/juice-shop/blob/v20.3.0/config/default.yml), valeurs locales par défaut.
6. [`download@8.0.0`](https://github.com/kevva/download/tree/v8.0.0), appel `got.stream(uri, opts)` et dépendance Got. [`got@8.3.2/index.js`](https://github.com/sindresorhus/got/blob/v8.3.2/index.js), wrapper cacheable et option de cache par défaut. Voir aussi [analyse 09](09-http-cache-semantics.md), qui établit que cache désactivé ne supprime pas tout le traitement en amont.

Les preuves d’installation et de chemin proviennent des rapports; les éléments de code applicatif proviennent de sources publiées taggées, et ceux des bibliothèques de leurs tags/commit exacts. Le Docker Engine est maintenant accessible et les couches de l’image correspondent au rapport, mais cette vérification ciblée n’a pas contrôlé les octets du paquet ni la configuration runtime. Le conteneur existant est arrêté; aucun comportement d’exécution n’est établi. Aucun scan, test ou test d’exploitation n’a été exécuté.
