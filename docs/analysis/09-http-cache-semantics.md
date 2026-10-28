# Analyse statique de http-cache-semantics

## Périmètre et détections Trivy

Les deux rapports contiennent la même installation : `http-cache-semantics@3.8.1`, chemin `juice-shop/node_modules/http-cache-semantics/package.json`. Le rapport initial et le rapport HIGH/CRITICAL signalent chacun deux détections HIGH :

| CVE | GHSA associé dans le rapport | Sujet | Statut/version corrigée selon le rapport |
|---|---|---|---|
| `CVE-2022-25881` | `GHSA-rc47-6667-2j5j` | Complexité inefficace d’une expression régulière, risque ReDoS | Affecté; version corrigée `4.1.1` |
| `CVE-2026-93748` | `GHSA-ch52-4w7c-c8xp` | Traitement de `max-stale` et réutilisation d’entrées de cache partagées selon l’avis | Affecté; le rapport ne renseigne pas de version corrigée |

Chaque identifiant CVE et GHSA désigne le même avis correspondant; les quatre chaînes ne représentent donc que deux détections par rapport. Les fichiers JSON sont restés inchangés. Le rapport initial a `CreatedAt` `2026-10-20T11:28:17.521956103Z`; le rapport filtré a `CreatedAt` `2026-10-21T14:42:43.231675625Z`.

## Avis et prérequis décrits

### CVE-2022-25881 / GHSA-rc47-6667-2j5j

L’avis GitHub officiel classe les versions npm antérieures à `4.1.1` comme affectées et `4.1.1` comme corrigée. Il décrit une complexité inefficace menant à un déni de service via des valeurs de champs d’en-tête de requête malveillantes **lorsqu’un serveur lit la politique de cache de cette requête avec la bibliothèque**. Le prérequis central est donc qu’une valeur de header contrôlée par l’attaquant atteigne le parsing concerné. Une dépendance présente dans un client HTTP sortant ne prouve pas que l’application traite directement les headers d’une requête HTTP entrante avec `CachePolicy`.

### CVE-2026-93748 / GHSA-ch52-4w7c-c8xp

L’avis GitHub associe l’attaque au traitement d’un `Cache-Control: max-stale` client par une entrée de cache partagée qu’il considère comme neutralisée pour des raisons de sécurité, potentiellement avec `Set-Cookie`. Son scénario suppose au minimum un cache partagé qui stocke et relit des réponses entre utilisateurs, une réponse sensible conservée dans ce cache et un `max-stale` contrôlable par le demandeur. L’avis GitHub ne publie pas de version corrigée.

**Version signalée par Trivy :** `3.8.1`, incluse dans la plage de versions affectées annoncée par GHSA. **Mécanisme vulnérable confirmé : non.** L’avis est contesté par le mainteneur amont : dans l’issue liée, celui-ci indique que `Set-Cookie` n’interdit pas seul la mise en cache selon RFC 9111 et que l’isolation de réponses privées doit être exprimée par des directives telles que `Cache-Control: private`; l’issue est fermée « not planned ». Cette contestation ne retire pas l’avis GitHub, mais les sources consultées ne suffisent pas à confirmer que le comportement décrit constitue un mécanisme de vulnérabilité. Le rapport Trivy n’indique aucune version corrigée pour cet avis.

## Installation, consommateur et chaîne d’appels

Dans les rapports, la copie résolue est unique et installée à la racine de `juice-shop/node_modules`. La chaîne de dépendances observée dans les métadonnées et l’image est :

```text
Juice Shop
└─ download@8.0.0
   └─ got@8.3.2
      └─ cacheable-request@2.1.4
         └─ http-cache-semantics@3.8.1
```

La source de Juice Shop v20.3.0 importe `download` et `ProxyAgent` dans `lib/utils.ts`; `downloadToFile(url, dest)` transmet le proxy à `download(url, { agent: proxyAgent })`. Les appels applicatifs repérés pour ce téléchargeur portent sur des ressources décrites par la configuration ou les données de démarrage (images, blueprint et overlay). Cette chaîne établit un consommateur et un chemin d’appel disponibles dans le code. Elle ne démontre pas, à elle seule, que les deux avis sont atteignables par une requête entrante arbitraire.

## Activation effective du cache et traitement des headers

Les sources de version exacte affinent la conclusion précédente : `cache` est bien `false` par défaut dans Got 8.3.2, mais le wrapper `cacheable-request` est quand même construit et **`CachePolicy` est quand même instanciée après la réponse**. Le cache désactivé empêche la lecture/écriture des entrées et le chemin de réutilisation/revalidation; il ne supprime pas le parsing de politique effectué dans le handler de réponse.

### Extraits numérotés

Les numéros ci-dessous sont les lignes des fichiers publiés par les versions indiquées; pour `cacheable-request`, le commit de publication `3f2d8e2f64af835a82721c51898bd6f08883c4de` est celui de `2.1.4`.

**Got 8.3.2 — `index.js`** ([source versionnée](https://github.com/sindresorhus/got/blob/v8.3.2/index.js)) :

```js
// L92-L93 — instancie le wrapper à chaque requête et lui passe opts.cache.
const cacheableRequest = new CacheableRequest(fn.request, opts.cache);
const cacheReq = cacheableRequest(opts, res => { ... });

// L487-L501 — valeur par défaut, puis fusion des options reçues.
opts = Object.assign({
    path: '',
    retries: 2,
    cache: false,
    ...
}, url, ..., opts);
```

**cacheable-request 2.1.4 — `src/index.js`** ([source au commit publié](https://github.com/lukechilds/cacheable-request/blob/3f2d8e2f64af835a82721c51898bd6f08883c4de/src/index.js)) :

```js
// L7 — importe la classe même si l’option cache vaut false.
const CachePolicy = require('http-cache-semantics');

// L34-L40 — valeurs par défaut et normalisation des headers.
opts = Object.assign({ headers: {}, method: 'GET', cache: true, ... }, opts);
opts.headers = lowercaseKeys(opts.headers);

// L61-L68 — après une réponse non issue du cache, construit toujours
// CachePolicy; opts.cache ne protège que l’appel storable/stockage.
response.cachePolicy = new CachePolicy(opts, response);
...
if (opts.cache && response.cachePolicy.storable()) { ... }

// L100-L105 — cache=false évite la lecture; l’absence d’entrée appelle
// makeRequest(opts), dont le handler ci-dessus instancie CachePolicy.
.then(() => opts.cache ? this.cache.get(key) : undefined)
.then(cacheEntry => {
    if (typeof cacheEntry === 'undefined') return makeRequest(opts);
});
```

**http-cache-semantics 3.8.1 — `node4/index.js`** ([archive npm exacte](https://registry.npmjs.org/http-cache-semantics/-/http-cache-semantics-3.8.1.tgz)) confirme ce que fait ce constructeur : L18-L25 découpe les directives `Cache-Control`; L62-L95 initialise `CachePolicy` et parse les `Cache-Control` de la réponse et de la requête (`res.headers['cache-control']` et `req.headers['cache-control']`). Par conséquent, la désactivation du cache ne signifie pas « aucune analyse de header ». Got normalise les noms de headers en minuscules et ajoute ses headers usuels; dans l’appel Juice Shop décrit ci-dessous, aucun `req.headers` Express n’est transmis.

Pour **CVE-2022-25881**, la regex effectivement atteinte est `/\s*,\s*/` dans `parseCacheControl()`. Elle est appliquée aux valeurs de `Cache-Control` de la requête **et** de la réponse par `CachePolicy` 3.8.1 (`node4/index.js`, lignes 18–25, 89–95). Dans le scénario de l’avis côté serveur, l’appelant distant contrôle le header `Cache-Control` de sa requête entrante. Dans le chemin client observé ici, Got contrôle/construit les headers de requête sortants; aucun header Express entrant ne leur est transmis. En revanche, l’origine HTTP distante contrôle les headers de réponse — dont `Cache-Control` — pour l’URL téléchargée. Cette source peut donc fournir une valeur analysée par la regex si elle sert une réponse forgée ou contrôlée. Le parsing de header est exécuté même lorsque le cache est désactivé; cela ne prouve pas qu’une valeur malveillante atteigne l’appel, ni qu’une exploitation ait eu lieu.

Pour **CVE-2026-93748**, le parsing syntaxique du header `Cache-Control` persiste également avec `cache:false`, mais le chemin distinct qui charge une politique stockée (`CachePolicy.fromObject`) puis appelle `satisfiesWithoutRevalidation()` n’est pas atteint faute d’entrée lue du cache. Cet avis concerne la réutilisation d’une réponse stockée avec des directives `max-stale` dans un cache partagé, et non le seul parsing du header. L’avis demeure contesté et son mécanisme n’est pas confirmé.

Cette conclusion est limitée aux appels retrouvés dans le dépôt v20.3.0 et aux options visibles dans leur code. Aucune lecture/écriture de cache ni aucun adaptateur n’est observé. Une utilisation supplémentaire injectée par configuration ou environnement de déploiement n’est pas établie par les rapports Trivy. L’activation d’un cache externe partagé n’a pas été vérifiée sur l’instance auditée.

## Provenance des en-têtes et contrôles

Pour le chemin observé, `downloadToFile` reçoit une URL depuis les appelants applicatifs/configurations et l’envoie au client `download`/Got. Aucun transfert d’un objet `req.headers` Express vers cet appel n’a été trouvé dans ce chemin. Les headers de requête sortants relèvent donc des options et valeurs par défaut du client ainsi que des options transmises; la source de la réponse HTTP est le serveur distant ciblé par l’URL. Le code analysé ne fournit pas de valeur entrante arbitraire `Cache-Control: max-stale` au client.

Le code de Juice Shop inspecté ne contient pas de cache applicatif pour ces téléchargements ni de contrôle custom sur `Cache-Control`, `Set-Cookie` ou `max-stale` dans cette chaîne. Avec le cache désactivé, aucune entrée n’est lue ou écrite, et aucune politique d’entrée n’est consultée pour décider de servir une réponse réutilisée. En revanche, le handler de réponse instancie `CachePolicy` et analyse les directives `Cache-Control` de la requête sortante et de la réponse amont avant de transmettre la réponse. Aucune preuve n’établit un cache partagé multi-utilisateur dans l’instance auditée.

## Qualification des éléments

| Élément | Conclusion statique |
|---|---|
| Version signalée par Trivy | **Oui** : `3.8.1`, une installation et deux alertes HIGH dans chaque rapport. |
| Regex CVE-2022-25881 appelée dans le chemin | **Oui** : `parseCacheControl()` applique `/\s*,\s*/` aux `Cache-Control` de requête et de réponse. |
| Source contrôlant les valeurs analysées | **Requête sortante :** options Got de Juice Shop; aucune transmission d’un header Express observée. **Réponse :** origine HTTP distante de l’URL téléchargée. |
| Mécanisme CVE-2022-25881 confirmé dans l’application | **Non** : l’appel de parsing est confirmé, mais aucun header malveillant ni ralentissement/exploitation n’est démontré. Une origine distante contrôlée pourrait fournir le header de réponse analysé. |
| Mécanisme CVE-2026-93748 confirmé | **Non** : l’avis est contesté par l’amont; le cache est désactivé dans Got et le code de réutilisation d’entrée n’est donc pas atteint dans l’appel observé. |
| Consommateur dans l’arbre | **Oui** : chaîne via `download` → `got` → `cacheable-request`. |
| Appel de téléchargement observé | **Oui** : helper `downloadToFile` utilise `download` avec un agent proxy. |
| Cache Got activé dans cet appel | **Non** : défaut `false` de Got 8.3.2 confirmé par `index.js` L487-L501; aucun override/adaptateur dans l’appel observé. |
| `CachePolicy`/headers analysés quand le cache est désactivé | **Oui** : `cacheable-request` 2.1.4 construit `CachePolicy` dans le handler (L61-L68); `http-cache-semantics` parse les Cache-Control de requête et réponse. |
| Header Express entrant transmis à ce client | **Non observé** dans le chemin identifié; les headers de réponse restent contrôlés par le serveur distant ciblé. |
| Cache partagé et réponse sensible réutilisée entre utilisateurs | **Non établi**. |
| Exposition CVE-2022-25881 | **Conditionnelle et non démontrée** : la regex est atteinte sur `Cache-Control`; l’origine distante de l’URL peut fournir la valeur de réponse, mais aucune origine/header malveillant ni exploitation n’est établi. |
| Exposition CVE-2026-93748 | **Non démontrée** : Trivy signale la version; le mécanisme reste contesté/non confirmé, et le chemin cache requis est désactivé dans l’appel observé. |

## Conclusion provisoire

L’image contient bien la version `3.8.1` signalée par Trivy. Got désactive le cache par défaut, mais le handler construit `CachePolicy`; `parseCacheControl()` exécute `/\s*,\s*/` sur les valeurs `Cache-Control` des headers request/response. Got construit les headers de requête dans cet appel; le serveur distant de l’URL téléchargée contrôle les headers de réponse. Une valeur de réponse malveillante pourrait donc atteindre le parsing, mais aucun tel header, impact ReDoS ou exploitation n’a été démontré. Ce parsing est distinct de la réutilisation d’une entrée : celle-ci n’a pas lieu quand le cache est désactivé. CVE-2026-93748 porte sur cette réutilisation, et son mécanisme demeure contesté/non confirmé. Aucun scan, requête de test ou test d’exploitation n’a été effectué.

## Références

- [Avis GitHub GHSA-rc47-6667-2j5j / CVE-2022-25881](https://github.com/advisories/GHSA-rc47-6667-2j5j) — plage affectée, correction et prérequis ReDoS.
- [Avis GitHub GHSA-ch52-4w7c-c8xp / CVE-2026-93748](https://github.com/advisories/GHSA-ch52-4w7c-c8xp) — scénario `max-stale`, plage affectée et absence de version corrigée publiée dans l’avis.
- [Discussion amont #56](https://github.com/kornelski/http-cache-semantics/issues/56) — avis initial et contestation du mainteneur.
- [Code Juice Shop v20.3.0 `lib/utils.ts`](https://github.com/juice-shop/juice-shop/blob/v20.3.0/lib/utils.ts) — import de `download` et `ProxyAgent`, helper `downloadToFile`.
- [Source exacte Got 8.3.2 `index.js`](https://github.com/sindresorhus/got/blob/v8.3.2/index.js) — L92-L93 passe `opts.cache` au wrapper; L487-L501 fixe `cache: false` par défaut.
- [Source exacte cacheable-request 2.1.4 `src/index.js`](https://github.com/lukechilds/cacheable-request/blob/3f2d8e2f64af835a82721c51898bd6f08883c4de/src/index.js) — L61-L68 construit toujours `CachePolicy` au retour réseau; L100-L105 saute seulement la lecture du cache avec `cache:false`.
- [Archive npm exacte http-cache-semantics 3.8.1](https://registry.npmjs.org/http-cache-semantics/-/http-cache-semantics-3.8.1.tgz) — `node4/index.js` L18-L25 et L62-L95 parse les directives de cache HTTP.
- [Documentation amont http-cache-semantics](https://github.com/kornelski/http-cache-semantics) — usage de `CachePolicy`, `storable()` et `satisfiesWithoutRevalidation()`.
