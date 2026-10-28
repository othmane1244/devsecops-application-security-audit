# 18 — @tootallnate/once

## Résumé

Le rapport Trivy initial contient une détection LOW `CVE-2026-3449` pour `@tootallnate/once@1.1.2`, au chemin `juice-shop/node_modules/@tootallnate/once/package.json`; Trivy la marque `fixed` et donne `2.0.1, 3.0.1` comme versions correctives. L’avis officiel couvre bien les versions `<2.0.1`, donc inclut la version signalée, mais son mécanisme exige l’option `AbortSignal`.

Le consommateur résolu identifié est `http-proxy-agent@4.0.1`, lui-même dans l’arbre de dépendances de `sqlite3@5.1.7` via `node-gyp@8.4.1` et `make-fetch-happen@9.1.0`. Son appel publié attend l’événement `connect` sans fournir d’option de signal. Le code publié de la copie npm `1.1.2` examiné dans un bundle Corepack exact expose une annulation manuelle `.cancel()`, mais pas d’argument `AbortSignal`; son mécanisme d’annulation n’est pas celui décrit par l’avis. L’exploitation du scénario CVE n’est donc pas confirmée dans l’usage résolu.

## Détection et résolution

| Preuve | Constat |
|---|---|
| O-01 | Le rapport initial (`reports/trivy-image-initial.json`, lignes 16874–16924) signale une occurrence `CVE-2026-3449`, `@tootallnate/once@1.1.2`, chemin `juice-shop/node_modules/@tootallnate/once/package.json`, sévérité LOW, état `fixed`, `FixedVersion: 3.0.1, 2.0.1`. Le texte Trivy décrit une promesse qui reste pendante si la promesse est annulée par `AbortSignal`. |
| O-02 | L’inventaire initial situe aussi `sqlite3@5.1.7`, `node-gyp@8.4.1`, `make-fetch-happen@9.1.0`, `http-proxy-agent@4.0.1` et `agent-base@6.0.2` sous `juice-shop/node_modules/sqlite3/node_modules`. Les autres copies de `http-proxy-agent` (9.1.0), `agent-base` (9.1.0) et des agents proxy associées sont dans les arbres `proxy-agent`/`pac-proxy-agent` et ne résolvent pas cette copie `once@1.1.2`. |
| O-03 | Le rapport HIGH/CRITICAL ne contient pas de finding pour `@tootallnate/once`; il ne fait apparaître que l’inventaire du paquet. La détection est LOW dans le rapport initial. |
| O-04 | La source publiée de [`node-gyp@8.4.1`](https://github.com/nodejs/node-gyp/blob/v8.4.1/package.json#L23-L33) dépend de `make-fetch-happen ^9.1.0`; celle de [`make-fetch-happen@9.1.0`](https://github.com/npm/make-fetch-happen/blob/v9.1.0/package.json#L34-L50) dépend de `http-proxy-agent ^4.0.1` et `https-proxy-agent ^5.0.0`. Le manifeste [`http-proxy-agent@4.0.1`](https://github.com/TooTallNate/node-http-proxy-agent/blob/4.0.1/package.json#L31-L35) déclare directement `@tootallnate/once: "1"`, ce qui correspond à la version 1.1.2 inventoriée. Aucun appel `once` depuis l’application métier elle-même n’est établi par ces éléments. |
| O-05 | Le manifeste publié de [`sqlite3@5.1.7`](https://github.com/TryGhost/node-sqlite3/blob/v5.1.7/package.json#L56-L70) classe `node-gyp` comme dépendance optionnelle et exécute `prebuild-install -r napi || node-gyp rebuild` à l’installation. La chaîne jusqu’à l’agent proxy sert donc au téléchargement pendant une installation/reconstruction native; le fait que ce chemin soit appelé en production par le serveur n’est pas établi. |

## Avis officiel et code de la version

| Preuve | Constat |
|---|---|
| O-06 | L’avis officiel [GHSA-vpq2-c234-7xj6 / CVE-2026-3449](https://github.com/advisories/GHSA-vpq2-c234-7xj6) énumère `<2.0.1` et `>=3.0.0, <3.0.1` comme plages affectées; correctifs `2.0.1` et `3.0.1`. Il requiert l’option `AbortSignal`: à l’abort, la promesse reste non résolue/non rejetée, ce qui peut bloquer un `await` ou `.then()`. La version `1.1.2` est dans la plage publiée, mais l’applicabilité dépend encore de la présence de cette option dans le code et l’appel effectivement résolus. |
| O-07 | Le manifeste du tag publié [`@tootallnate/once@1.1.2`](https://github.com/TooTallNate/once/blob/1.1.2/package.json#L1-L8) indique cette version et `main: ./dist/index.js`. Le code distribué `dist/index.js` est également reproduit avec son chemin de cache et son nom de paquet explicites dans le [bundle publié de Corepack 0.15.2](https://app.unpkg.com/corepack@0.15.2/files/dist/vendors-_yarn_berry_cache_proxy-agent-npm-5_0_0-41772f4b01-9_zip_node_modules_proxy-agent_index_js.js#L16-L61), lignes 16–61 : `once(emitter, name)` ne prend que l’émetteur et le nom d’événement; `spread()` crée la promesse, attache `name` et `error`, et expose `.cancel()`. Ce `cancel()` retire ces deux écouteurs et remplace `p.cancel` par une fonction vide; il n’appelle ni `resolve` ni `reject`. Aucun paramètre `signal`, listener `abort` ou `AbortSignal` n’apparaît dans cette copie de la version 1.1.2. C’est une source publiée tierce contenant le code du paquet, pas un fichier extrait de l’image auditée. |
| O-08 | Le [correctif amont `b9f43cc`](https://github.com/TooTallNate/once/commit/b9f43cc5259bee2952d91ad3cdbd201a82df448a) décrit le cas signal déjà aborté et ajoute une fonction `onAbort()` qui nettoie les listeners puis rejette une `AbortError`; il retire également `onAbort` au nettoyage. Cette différence confirme le mécanisme attendu par l’avis, mais ce commit de correction ne prouve pas à lui seul la composition exacte du fichier 1.1.2 dans l’image. |

## Appels, événements et options

| Preuve | Constat |
|---|---|
| O-09 | Dans le code versionné de [`http-proxy-agent@4.0.1/src/agent.ts`](https://github.com/TooTallNate/node-http-proxy-agent/blob/4.0.1/src/agent.ts#L4-L5), le paquet importe `once`; les lignes 112–120 ouvrent un socket TCP ou TLS vers le proxy, puis les lignes 151–156 font `await once(socket, 'connect')`. Aucun troisième argument ni `signal` n’est transmis. L’événement attendu est `connect`; un événement `error` est aussi surveillé par `once@1.1.2` et rejette la promesse. |
| O-10 | Pour `once@1.1.2`, `connect` déclenche le retrait des écouteurs `connect`/`error` et la résolution; `error` retire ces écouteurs et rejette. L’annulation explicite par `.cancel()` retire également les écouteurs mais laisse la promesse en attente; aucune utilisation de `.cancel()` dans `http-proxy-agent@4.0.1` n’est observée. Une connexion qui n’émet ni `connect` ni `error` peut rester en attente, mais ce cas général d’attente n’établit pas le scénario d’avis lié à un `AbortSignal`. |
| O-11 | Les versions actuelles de `proxy-agent@8.0.2`/`http-proxy-agent@9.1.0` visibles dans le rapport utilisent une autre chaîne `agent-base@9.0.0`; elles ne consomment pas la copie signalée. La copie concernée se résout sous l’arbre de `sqlite3`, via les composants d’installation cités en O-04/O-05. |

### Prérequis et limites

- **Version dans la plage de l’avis : présent.** `1.1.2` est `<2.0.1` d’après GHSA et Trivy.
- **Option `AbortSignal` dans l’API exacte publiée examinée : absente.** Le paquet `1.1.2` exposé dans le bundle Corepack attend seulement `(emitter, name)` et fournit à la place `.cancel()`.
- **Option `AbortSignal` à l’appel consommateur : absente.** `http-proxy-agent@4.0.1` appelle `once(socket, 'connect')` sans option supplémentaire.
- **Événement et erreur : identifiés.** `connect` résout; `error` rejette; tous deux nettoient leurs écouteurs. Le délai / l’émission effective des événements dans l’image n’a pas été observé en exécution.
- **Exécution de la chaîne d’installation dans cette image : inconnue.** `sqlite3` prévoit un téléchargement précompilé puis une reconstruction native de repli; les rapports d’inventaire ne prouvent pas quelle branche a été exécutée ni que `node-gyp` ou `make-fetch-happen` soit utilisé par le serveur en production.
- **Fichiers image exacts : non vérifiés.** Le JSON Trivy établit chemin, version et finding, mais ne contient pas les sources installées. Le code 1.1.2 cité provient d’un bundle publié externe, et les appels `http-proxy-agent` des sources publiées versionnées; ils ne sont pas des extraits des fichiers extraits de l’image.

## Conclusion

**La détection est présente; le mécanisme décrit par CVE-2026-3449 n’est pas confirmé dans le consommateur résolu.** Bien que `1.1.2` soit inclus dans la plage GHSA, le code publié de cette version ne présente pas l’option `AbortSignal`; l’appel publié de `http-proxy-agent@4.0.1` attend `connect` sans cette option. Son `error` rejette la promesse et son événement attendu résout normalement. La méthode `.cancel()` propre à cette version peut retirer les écouteurs sans régler la promesse, mais aucun appel à cette méthode n’est identifié dans le consommateur résolu et elle ne correspond pas au prérequis `AbortSignal` de l’avis. Aucune exploitation n’est démontrée. Les sources image elles-mêmes et le chemin d’installation réellement pris par sqlite3 restent inconnus.

## Références

1. Rapport initial : `reports/trivy-image-initial.json`, finding lignes 16874–16924; inventaire Node.js des paquets concernés. Rapport HIGH/CRITICAL : inventaire seul, sans finding once.
2. Avis officiel [GHSA-vpq2-c234-7xj6 / CVE-2026-3449](https://github.com/advisories/GHSA-vpq2-c234-7xj6), issue amont [#8](https://github.com/TooTallNate/once/issues/8) et correctif [`b9f43cc`](https://github.com/TooTallNate/once/commit/b9f43cc5259bee2952d91ad3cdbd201a82df448a).
3. Code publié de la version exacte : [`@tootallnate/once@1.1.2/package.json`](https://github.com/TooTallNate/once/blob/1.1.2/package.json) et copie distribuée référencée dans le bundle [Corepack 0.15.2](https://app.unpkg.com/corepack@0.15.2/files/dist/vendors-_yarn_berry_cache_proxy-agent-npm-5_0_0-41772f4b01-9_zip_node_modules_proxy-agent_index_js.js#L16-L61).
4. Consommateur exact [`http-proxy-agent@4.0.1`](https://github.com/TooTallNate/node-http-proxy-agent/tree/4.0.1), et chaîne publiée : [`node-gyp@8.4.1`](https://github.com/nodejs/node-gyp/blob/v8.4.1/package.json), [`make-fetch-happen@9.1.0`](https://github.com/npm/make-fetch-happen/blob/v9.1.0/package.json), [`sqlite3@5.1.7`](https://github.com/TryGhost/node-sqlite3/blob/v5.1.7/package.json).
