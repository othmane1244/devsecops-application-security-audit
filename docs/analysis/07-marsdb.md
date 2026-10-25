# Analyse statique — MarsDB

## Périmètre

Analyse des deux rapports Trivy et des sources de l’image Juice Shop associée. Aucun scan, changement applicatif ou test d’exploitation n’a été effectué. L’inspection du code n’exécute aucune requête MarsDB.

Le rapport initial conservé sur la branche `docs/project-readme` porte `CreatedAt: 2026-10-20T11:28:17.521956103Z`. Le rapport filtré `reports/trivy-image-high-critical.json` porte `CreatedAt: 2026-10-21T14:42:43.231675625Z`.

## Détection et installation

Les deux rapports contiennent la même détection : **une alerte CRITICAL** pour `marsdb@0.6.11`, cible `Node.js`, classe `lang-pkgs`, chemin `juice-shop/node_modules/marsdb/package.json`. Elle est donc présente dans le rapport initial et dans le filtre HIGH/CRITICAL. Aucun identifiant CVE séparé n’est indiqué par Trivy.

`package.json:131` déclare `marsdb: ^0.6.11`; `package-lock.json:10192-10206` résout le module racine à `0.6.11` depuis le tarball npm correspondant. `data/mongodb.ts:6-10` est l’import applicatif et instancie les collections `posts` et `orders`. L’installation unique confirmée par le rapport correspond à cette résolution. Le rapport classe l’avis `GHSA-5mrr-rgp6-x4gr` comme affecté.

L’avis [GHSA-5mrr-rgp6-x4gr](https://github.com/advisories/GHSA-5mrr-rgp6-x4gr) couvre toutes les versions (`>=0.0.0`), n’indique aucune version corrigée et ne donne pas de CVE connu. Il décrit la classe `DocumentMatcher` : les sélecteurs `$where` sont passés sans assainissement au constructeur `Function`; si la fonction générée est exécutée, du code arbitraire peut s’exécuter dans le processus. La page d’avis référence aussi l’[avis npm 1122](https://www.npmjs.com/advisories/1122) et une issue Juice Shop; ces références ne sont pas des CVE alias. Le dépôt MarsDB est [archivé en lecture seule](https://github.com/c58/marsdb).

## Preuve dans l’implémentation vulnérable

**Preuve M-01 — compilation et invocation du sélecteur (`node_modules/marsdb/lib/DocumentMatcher.js:368-380`).** Le gestionnaire `$where` passe une valeur qui n’est pas déjà une fonction à `Function('obj', 'return ' + selectorValue)` sans neutralisation, puis retourne un prédicat qui invoque cette fonction avec le document comme `this` et comme argument. `node_modules/marsdb/lib/Cursor.js:152-177,195-198` relie le matcher au filtrage des documents; `Cursor.js:104-115` déclenche l’exécution lorsque le curseur est consommé par `.then()`.

**Preuve M-02 — API et collections (`data/mongodb.ts:6-10`; `node_modules/marsdb/lib/Collection.js:181-205`).** L’application expose deux collections MarsDB : `reviewsCollection` et `ordersCollection`. Elles fournissent `find()` et `findOne()`; leur usage réel et les données qui alimentent les sélecteurs sont examinés par consommateur ci-dessous.

## Consommateurs et chemins de données

### Avis de produit — `GET /rest/products/:id/reviews`

**Preuve M-03 — route et paramètre (`server.ts:659-663`; `routes/showProductReviews.ts:15-48`).** La route transmet `req.params.id` au handler sans middleware d’authentification affiché dans son enregistrement (`server.ts:660`). Le handler produit `id` ainsi : si `noSqlCommandChallenge` est désactivé, `Number(req.params.id)`; si le challenge est actif, `utils.trunc(req.params.id, 40)` (`showProductReviews.ts:30-31`). `utils.trunc` retire les retours à la ligne et limite la longueur, mais ne neutralise pas la syntaxe JavaScript (`lib/utils.ts:55-58`). Le helper global `sleep` limite à deux secondes sa durée (`showProductReviews.ts:15-25`); cette borne ne neutralise pas la valeur du sélecteur et ne constitue pas une validation de `$where`.

Le sélecteur passé à MarsDB est construit par le code, sous la forme `$where: 'this.product == ' + id` (`showProductReviews.ts:36`). Il n’accepte pas un objet de requête fourni directement par l’utilisateur. Toutefois, lorsque le challenge est actif, le texte du paramètre est concaténé comme code source à la chaîne `$where`; la seule troncature à 40 caractères ne constitue pas une validation syntaxique.

`noSqlCommandChallenge` est marqué `disabledEnv: Docker, Heroku` (`data/static/challenges.yml:762-777`). Avec `challenges.safetyMode: auto` (défaut de `config/default.yml:80-90`), la logique `getChallengeEnablementStatus` désactive ce challenge dans ces environnements (`lib/utils.ts:153-185`). Dans cette branche désactivée, la conversion `Number()` restreint la valeur à sa représentation numérique (ou `NaN`/`Infinity`), plutôt que de transmettre le texte original comme source d’expression. Si la configuration runtime active le challenge ou si l’environnement n’est pas désactivé, la branche `trunc` laisse passer davantage de syntaxe. La configuration effective au runtime n’a pas été collectée.

### Suivi de commande — `GET /rest/track-order/:id`

**Preuve M-04 — paramètre et expression (`server.ts:645`; `routes/trackOrder.ts:12-27`).** La route fournit le paramètre URL `id` au handler sans middleware d’authentification affiché dans son enregistrement. Si `reflectedXssChallenge` est désactivé, le code retire toute valeur hors `\w` et `-` (`trackOrder.ts:14-15`). Si le challenge est actif, il applique seulement `utils.trunc(..., 60)`. Le sélecteur devient ensuite `$where: \`this.orderId === '${id}'\`` (`:18`), donc le paramètre est concaténé dans le corps d’une expression JavaScript et dans une chaîne entre apostrophes.

Le défi `reflectedXssChallenge` est également marqué `disabledEnv: Docker, Heroku` (`data/static/challenges.yml:904-921`). En Docker/Heroku avec le mode par défaut `auto`, la branche de filtrage par allowlist est sélectionnée. En environnement où le challenge est actif (ou avec une surcharge de configuration qui l’active), `trunc` ne neutralise pas la syntaxe de l’expression. Cette condition applicative de challenge est distincte de la vulnérabilité MarsDB elle-même.

### Chatbot — outil `getProductReviews`

**Preuve M-05 — conversion numérique avant MarsDB (`server.ts:665-666`; `routes/chat.ts:114-150,190-209`).** L’endpoint `/rest/chat` lit l’historique de chat depuis `req.body.messages`; l’outil `getProductReviews` accepte un champ chaîne `id` selon son schéma Zod (`chat.ts:142-146`), puis le convertit immédiatement avec `Number(id)` (`:147-149`) avant de le concaténer à l’expression fixe `this.product == ...`. La valeur n’est pas utilisée telle quelle comme code source. L’outil est proposé à `streamText` parmi ses outils (`:202-209`); son appel dépend du traitement du modèle et n’est pas déterminé par la seule réception du message.

Dans le même handler, `getOrderById` appelle `db.ordersCollection.findOne({ orderId })` (`chat.ts:153-171`). La forme du sélecteur est un objet littéral fixe avec égalité sur une propriété; l’utilisateur ou le modèle ne transmet pas d’objet selector arbitraire et cette opération n’utilise pas `$where`. Elle constitue bien un consommateur MarsDB, mais le chemin de `Function` de l’avis n’y est pas observé.

## Rapprochement des prérequis et conclusion provisoire

| Chemin | Sélecteur/entrée | Contrôle et validation constatés | Applicabilité provisoire au GHSA |
|---|---|---|---|
| `/rest/products/:id/reviews` | Expression `$where` dont le suffixe est issu de `id`. | Challenge désactivé : coercition `Number`; challenge actif : troncature seule (40 caractères), sans échappement d’expression. Le challenge est désactivé en Docker/Heroku avec le défaut `auto`. | Le sink vulnérable est atteint. La source d’expression brute est conditionnelle à l’activation du challenge ou à l’environnement/configuration effective. Applicabilité conditionnelle; aucun code n’a été exécuté. |
| `/rest/track-order/:id` | Expression `$where` avec `id` injecté dans le littéral chaîne de l’expression. | Challenge désactivé : allowlist `\w` et `-`; actif : troncature seule (60 caractères). Challenge désactivé en Docker/Heroku avec `auto`. | Le sink vulnérable est atteint. Le texte contrôlé atteint la construction d’expression lorsque le challenge est actif; autrement l’allowlist retire les caractères de syntaxe pertinents. Applicabilité conditionnelle au mode d’exécution. |
| Chat `getProductReviews` | Expression `$where` fixe plus conversion `Number(id)`. | Schéma Zod vérifie que `id` est une chaîne, puis `Number()` fait la coercition avant concaténation. | Usage `$where` effectivement présent, mais les caractères de l’entrée ne sont pas transmis comme expression libre. Prérequis d’expression contrôlée non observé dans ce chemin. |
| Chat `getOrderById` | `findOne({ orderId })`, objet de forme fixe. | Valeur utilisateur utilisée comme valeur du champ `orderId`; pas de `$where`, pas d’objet de sélecteur fourni par l’appelant. | Le mécanisme décrit par l’avis n’est pas observé dans cette opération. |

**Synthèse.** MarsDB 0.6.11 est présent et réellement utilisé. Le code vulnérable est confirmé : `$where` compile une fonction sans neutraliser le texte puis l’exécute pendant l’évaluation du curseur. Deux routes REST construisent des expressions à partir d’identifiants URL; les branches qui transmettent le texte plus librement sont liées à des challenges et sont conditionnées par l’environnement/configuration. Le chatbot utilise également `$where`, mais convertit d’abord l’entrée en nombre; une autre opération chatbot utilise une forme de requête fixe sans `$where`. Il s’agit d’une preuve statique de chemins et de prérequis, pas d’une démonstration d’exploitation.

## Limites de l’inspection

- Les rapports attestent la version et l’avis, pas la configuration d’exécution de l’application.
- Le mode de sécurité effectif et la plateforme d’exécution active n’ont pas été lus dans le conteneur du service; les conclusions Docker/Heroku ci-dessus sont conditionnelles aux valeurs par défaut et à `isDocker()`/`isHeroku()` au runtime.
- Aucune donnée n’a été envoyée aux routes et aucune expression MarsDB n’a été exécutée manuellement.
- La présence d’un sink vulnérable et d’un paramètre contrôlable ne suffit pas à conclure qu’une exploitation a eu lieu ou qu’elle est faisable dans la configuration actuelle.
