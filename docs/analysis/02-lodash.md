# Analyse statique — lodash

## Périmètre et méthode

Analyse en lecture seule des champs CreatedAt des rapports Trivy 0.76.0 et des sources de l’image associée à l’ImageID sha256:40606cfb…. Le rapport initial, conservé dans Git sur la branche docs/project-readme sous reports/trivy-image-initial.json, porte CreatedAt 2026-10-20T11:28:17.521956103Z. Le rapport filtré reports/trivy-image-high-critical.json porte CreatedAt 2026-10-21T14:42:43.231675625Z. Ce sont deux horodatages distincts; le second n’est pas la date du rapport initial. Aucun scan, test d’exploitation ou changement applicatif n’a été réalisé.

Les sources inspectées sont celles de l’image associée à l’ImageID du rapport. Les numéros de ligne ci-dessous sont ceux relevés dans cette image, pas ceux d’une autre révision locale.

## Rôle et installations

Lodash est une bibliothèque JavaScript d’utilitaires de manipulation de collections et d’objets. Deux installations distinctes sont inventoriées :

| Version | Chemin dans l’image | Consommateur observé | Résolution |
|---|---|---|---|
| 2.4.2 | juice-shop/node_modules/sanitize-html/node_modules/lodash | sanitize-html | Le require('lodash') de sanitize-html/index.js résout vers cette copie imbriquée. sanitize-html/package.json déclare lodash: 2.4.x. |
| 4.18.1 | juice-shop/node_modules/lodash | Dépendances runtime, notamment Sequelize et finale-rest | Les imports directs de lodash observés dans ces dépendances résolvent vers la copie racine 4.18.1. Aucune alerte n’est rapportée pour cette version. |

lodash.isfinite@3.3.2 est un paquet distinct et n’est pas compté comme une installation du paquet lodash.

## Détections du rapport

| Avis Trivy | Sévérité Trivy | Version et chemin | Présence dans HIGH/CRITICAL |
|---|---:|---|---|
| CVE-2019-10744 | CRITICAL | lodash@2.4.2, chemin imbriqué sous sanitize-html | Oui |
| CVE-2018-16487 | HIGH | même installation | Oui |
| CVE-2021-23337 | HIGH | même installation | Oui |
| CVE-2026-2950 | MEDIUM | même installation | Non — le filtre ne conserve que HIGH/CRITICAL |
| CVE-2018-3721 | LOW | même installation | Non — le filtre ne conserve que HIGH/CRITICAL |

Le rapport initial comporte cinq détections lodash pour la copie 2.4.2; le rapport filtré en affiche trois. Ces lignes représentent des avis, pas la preuve de cinq chemins d’exploitation indépendants. Les avis de pollution de prototype ont des surfaces qui se recoupent (defaultsDeep, merge, mergeWith), mais leurs identifiants et conditions ne sont pas fusionnés. Aucun alias CVE/GHSA n’a été établi pour ces cinq avis.

## Preuves statiques

**P-01 — inventaire et versions.** Le rapport initial associe les cinq avis ci-dessus à lodash@2.4.2 et au chemin imbriqué sous sanitize-html. Il inventorie séparément lodash@4.18.1 au chemin racine, sans vulnérabilité listée pour cette version.

**P-02 — dépendance et résolution de la copie signalée.** Dans juice-shop/node_modules/sanitize-html/package.json, la ligne 26 déclare la dépendance lodash: 2.4.x. Dans juice-shop/node_modules/sanitize-html/index.js, ligne 2, var _ = require('lodash') charge la copie imbriquée. Les appels observés dans ce fichier utilisent notamment _.defaults (ligne 28), _.each (lignes 40, 45, 51, 59 et 75) et _.contains (ligne 231). Aucun appel à merge, template ou omit n’a été trouvé dans ce fichier; aucune fonction intégrée defaultsDeep, mergeWith ou unset n’y est appelée.

**P-03 — entrée applicative vers sanitize-html.** Dans juice-shop/lib/insecurity.ts, ligne 13, l’application importe sanitize-html; lignes 58 et 62, le wrapper appelle sanitizeHtmlLib(html) et sanitizeSecure lui transmet html. Cette bibliothèque reçoit donc du contenu HTML fourni par son appelant, mais les appels internes examinés n’invoquent pas les fonctions visées par les avis étudiés.

**P-04 — autre appel applicatif.** Dans juice-shop/lib/challengeUtils.ts, ligne 5, sanitize-html est importé directement; ligne 65, il traite challenge.description avec allowedTags: [] et allowedAttributes: {} avant l’inclusion dans la notification. La provenance initiale de challenge.description dépend des données de défi; aucune validation propre à lodash n’est visible ici. Cet appel reste un usage du sanitizer et ne correspond pas à un appel explicite aux fonctions vulnérables.

**P-05 — autres consommateurs et séparation lodash-es.** Des imports directs de lodash dans les dépendances runtime, notamment Sequelize et finale-rest, résolvent vers juice-shop/node_modules/lodash/lodash.js (version 4.18.1). Le frontend importe lodash-es/sortBy dans frontend/src/app/score-board/components/filter-settings/pipes/difficulty-selection-summary.pipe.ts (ligne 3, appel sortBy ligne 21) et frontend/src/app/score-board/helpers/challenge-sorting.ts (ligne 3, appel sortBy ligne 8); lodash-es est un paquet distinct et ces imports ne constituent pas des consommateurs de l’installation npm lodash recensée ici. Les usages frontend observés trient des collections.

La recherche couvre les sources applicatives présentes dans l’image et le code du consommateur sanitize-html chargé par l’application. Elle ne constitue pas une preuve formelle sur toute exécution dynamique, tout code généré ou toute dépendance tierce non inspectée.

## Fonctions présentes dans lodash 2.4.2

Les extraits ci-dessous proviennent de juice-shop/node_modules/sanitize-html/node_modules/lodash/dist/lodash.js, déclaré main dans le package.json de lodash 2.4.2. La présence a été vérifiée à la fois dans les définitions et dans les exports de l’objet lodash.

**P-06 — merge est présente et récursive.** La fonction _.merge est définie aux lignes 2679–2706 et exportée à la ligne 6558. Elle parcourt les sources via baseMerge (ligne 2702). L’implémentation interne lignes 1226–1277 parcourt les propriétés et réaffecte object[key] (ligne 1276); elle n’a pas de garde générale qui rejette la clé __proto__. La fusion récursive des valeurs objet est visible aux lignes 1250–1262. Le paramètre callback/customizer est aussi accepté par merge (lignes 2691–2695). Cette copie a donc une implémentation réelle de merge, mais aucun appel n’est observé dans sanitize-html ou les sources applicatives examinées.

**Extrait E-01 — baseMerge, lignes 1226–1277 (passages pertinents).**

```js
function baseMerge(object, source, callback, stackA, stackB) {
  (isArray(source) ? forEach : forOwn)(source, function(source, key) {
    var result = source,
        value = object[key];
    // parcours/fusion récursive des objets imbriqués omis
    if (source && (isArray(source) || isPlainObject(source))) {
      // ...
      if (!isShallow) baseMerge(value, source, callback, stackA, stackB);
    }
    // ...
    object[key] = value;
  });
}
```

**P-07 — omit est présente, mais superficielle.** _.omit est définie aux lignes 2735–2760 et exportée ligne 6560. Sa documentation dit qu’elle crée une copie superficielle (lignes 2710–2724); l’implémentation énumère les propriétés, calcule les clés à omettre puis copie les autres dans un nouvel objet (lignes 2738–2759). La liste de sélecteurs est aplatie sur un niveau (ligne 2742); ce code ne résout pas un chemin imbriqué et ne supprime pas directement une propriété d’un prototype intégré. Aucun appel à omit n’a été trouvé dans le consommateur ou l’application.

**Extrait E-02 — omit, lignes 2735–2759.**

```js
function omit(object, callback, thisArg) {
  var result = {};
  if (typeof callback != 'function') {
    // ...
    props = baseDifference(props, baseFlatten(arguments, true, false, 1));
    // ...
    result[key] = object[key];
  }
  // ...
  return result;
}
```

**P-08 — template est présente et compile du code.** _.template est définie lignes 6221–6319 et exportée ligne 6654. La signature est template(text, data, options) (ligne 6221); options.variable alimente le nom de paramètre inséré dans la source générée (lignes 6275–6283 et 6290–6292), puis le code est compilé via Function(...) (ligne 6306). Aucune validation du contenu de variable n’apparaît dans ces lignes de cette version. Pour le scénario CVE-2021-23337, l’entrée pertinente est donc le troisième argument options, en particulier options.variable, contrôlé par un attaquant et transmis à _.template. Le deuxième argument data seul n’entre pas dans la construction de Function; il ne suffit pas à ce scénario. Contrôler text avec des délimiteurs d’évaluation configurés peut aussi produire du code de template, mais c’est un autre chemin de génération de code. Aucun appel à _.template n’a été observé dans le consommateur ou l’application, et aucune donnée utilisateur n’a été reliée à options.variable.

**Extrait E-03 — template, lignes 6275–6306.**

```js
var variable = options.variable,
    hasVariable = variable;
if (!hasVariable) {
  variable = 'obj';
  source = 'with (' + variable + ') {\n' + source + '\n}\n';
}
source = 'function(' + variable + ') {\n' + /* corps généré */;
var result = Function(importsKeys, 'return ' + source + sourceURL)
  .apply(undefined, importsValues);
```

**P-09 — fonctions intégrées absentes.** Aucune définition ni export de defaultsDeep, mergeWith ou unset n’a été trouvé dans dist/lodash.js. Le mot defaultsDeep apparaît uniquement dans un exemple de documentation des lignes 5647–5654, où l’exemple construit lui-même ce nom avec _.partialRight(_.merge, _.defaults); il ne s’agit pas d’une méthode exportée par lodash 2.4.2. mergeWith n’est pas exportée comme méthode distincte, même si merge accepte un callback. unset n’est pas disponible dans cette version.

**Extrait E-04 — exports, lignes 6558–6560 et 6654.** La table d’exports associe merge, omit et template à leurs implémentations; elle ne contient pas defaultsDeep, mergeWith ou unset. Pour defaultsDeep, la seule occurrence textuelle relevée est l’exemple documentaire précité, et non une définition ou un export.

## Avis, prérequis et conclusions provisoires

### CVE-2019-10744 — pollution de prototype dans defaultsDeep

L’avis officiel GitHub décrit les versions lodash < 4.17.12 et une pollution de prototype via defaultsDeep et un objet contenant constructor.prototype ([GHSA-jf85-cpcp-j695](https://github.com/advisories/GHSA-jf85-cpcp-j695)). lodash 2.4.2 n’exporte pas defaultsDeep; une mention dans un exemple documentaire montre comment l’utilisateur pourrait le composer à partir de merge et defaults, mais aucun tel appel/composite n’est observé dans le consommateur ou l’application. sanitize-html utilise _.defaults, fonction distincte. **Conclusion provisoire :** le point d’entrée exact de l’avis est absent par défaut de cette copie; aucun équivalent composé n’est observé dans le périmètre. Applicabilité via un autre code non inspecté non établie.

### CVE-2018-16487 — pollution de prototype dans defaultsDeep, merge et mergeWith

L’avis officiel décrit lodash < 4.17.11 et l’altération de prototype par constructor.prototype, au travers de defaultsDeep, merge ou mergeWith ([GHSA-4xc9-xhrj-v574](https://github.com/advisories/GHSA-4xc9-xhrj-v574)). Dans cette copie, merge existe, mais defaultsDeep et mergeWith ne sont pas des méthodes intégrées. Pour un objet destination ordinaire, baseMerge traite la propriété constructor en lisant la fonction constructeur héritée; celle-ci n’est pas un objet simple, donc la branche récursive remplace la valeur par un nouvel objet avant de l’affecter à object.constructor (P-06). Le trajet exact constructor.prototype décrit par l’avis n’est donc pas confirmé par cette implémentation pour ce cas standard. Aucun appel à merge n’a été trouvé dans le consommateur ou l’application. **Conclusion provisoire :** une fonction connexe existe, mais aucun usage applicatif observé; le vecteur précis de l’avis ne se transpose pas de façon démontrée à l’algorithme et au cas standard examinés. Ce constat statique ne couvre pas toutes les formes d’objet destination.

### CVE-2021-23337 — injection de commande via template

L’avis officiel vise lodash < 4.17.21 et la fonction template ([GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm)); ses références détaillent l’injection par options.variable. La fonction existe dans 2.4.2 sans validation visible de cette valeur avant son insertion dans le code passé à Function (P-08). Pour correspondre au scénario, il faudrait qu’un chemin appelle _.template et qu’une donnée contrôlée atteigne options.variable, le troisième argument. Le contrôle de data seul ne satisfait pas ce prérequis. Aucun appel à template ou flux vers options.variable n’a été trouvé. **Conclusion provisoire :** construction de code compatible avec le mécanisme décrit; aucun appel exposé observé.

### CVE-2026-2950 — pollution par suppression dans unset et omit

L’avis officiel vise lodash jusqu’à 4.17.23 et décrit le contournement par segment de chemin sous forme de tableau pour supprimer des propriétés de prototypes via unset ou omit ([GHSA-f23m-r3pf-42rh](https://github.com/advisories/GHSA-f23m-r3pf-42rh)). Dans la version 2.4.2, unset est absent. omit existe, mais construit une copie superficielle et ne résout pas de chemin imbriqué; la condition de suppression de propriété de prototype décrite ne correspond pas à cette implémentation (P-07). Aucun appel à omit n’a été trouvé dans le consommateur ou l’application. **Conclusion provisoire :** malgré la plage de versions générique remontée par Trivy, le vecteur précis de CVE-2026-2950 n’est pas applicable aux fonctions présentes dans cette copie, selon l’implémentation examinée. La détection est conservée pour traçabilité.

### CVE-2018-3721 — pollution de prototype dans les utilitaires

L’avis GitHub décrit les versions < 4.17.5 et les fonctions defaultsDeep, merge et mergeWith, avec une pollution par __proto__ ([GHSA-fvqr-27wr-82fm](https://github.com/advisories/GHSA-fvqr-27wr-82fm)). De ces fonctions, seule merge est directement exportée dans 2.4.2; son implémentation récursive lit object[key] et réaffecte object[key] sans garde générale sur __proto__ (P-06). Sur une cible ordinaire, un source contenant cette clé peut donc atteindre la branche de fusion de l’objet prototype hérité. Aucun appel à merge n’a cependant été observé dans le consommateur ou l’application, et aucune donnée utilisateur ne lui est transmise dans les usages inspectés. **Conclusion provisoire :** implémentation compatible avec le mécanisme décrit si elle était appelée avec une source contrôlée; prérequis d’usage et de flux utilisateur absents des preuves recueillies. Ce constat n’établit pas une exploitation effective.

## Incertitudes restantes

- L’inspection statique n’établit pas l’absence absolue d’appels construits dynamiquement, indirectement ou dans du code tiers non couvert.
- Les données passant par sanitize-html sont contrôlées par leurs appelants, mais aucun passage de ces données aux fonctions lodash citées dans les avis n’a été observé. Un autre consommateur de la copie imbriquée peut exister hors du périmètre inspecté.
- Pour CVE-2026-2950, la conclusion se limite à l’implémentation exacte de cette copie 2.4.2; d’autres versions de lodash et d’autres fonctions ne sont pas couvertes par cette comparaison.
- Aucune conclusion d’exploitation n’est tirée de la seule présence du paquet ou du classement Trivy.

## Références officielles

- [CVE-2019-10744 — GHSA-jf85-cpcp-j695](https://github.com/advisories/GHSA-jf85-cpcp-j695)
- [CVE-2018-16487 — GHSA-4xc9-xhrj-v574](https://github.com/advisories/GHSA-4xc9-xhrj-v574)
- [CVE-2021-23337 — GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm)
- [Correctif amont CVE-2021-23337 — validation de l’option variable](https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c)
- [CVE-2026-2950 — GHSA-f23m-r3pf-42rh](https://github.com/advisories/GHSA-f23m-r3pf-42rh)
- [CVE-2018-3721 — GHSA-fvqr-27wr-82fm](https://github.com/advisories/GHSA-fvqr-27wr-82fm)
