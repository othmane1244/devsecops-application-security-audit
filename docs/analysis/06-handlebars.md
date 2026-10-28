# Analyse statique — Handlebars

## Périmètre et méthode

Analyse documentaire et statique de l’image Juice Shop associée au rapport Trivy. Aucun scan n’a été relancé, aucun modèle n’a été compilé ou rendu à titre de test, aucune modification applicative et aucun test d’exploitation n’ont été effectués. Les références `fichier:ligne` ci-dessous sont celles relevées lors de l’inspection des sources de l’image. Elles ne décrivent pas une exécution dynamique.

Le rapport initial conservé dans l’historique Git (`reports/trivy-image-initial.json`, branche `docs/project-readme`) porte `CreatedAt: 2026-10-20T11:28:17.521956103Z`. Le rapport filtré présent dans le dépôt (`reports/trivy-image-high-critical.json`) porte `CreatedAt: 2026-10-21T14:42:43.231675625Z`. Le filtre HIGH/CRITICAL ne constitue pas le rapport complet.

## Détections

Trivy signale une seule installation, `handlebars@4.7.9`, à `juice-shop/node_modules/handlebars/package.json`.

| Avis | Sévérité | Description dans Trivy | Rapport initial | HIGH/CRITICAL | Correctif indiqué |
|---|---|---|---|---|---|
| CVE-2026-106445 | CRITICAL | JS injection via contournement du contrôle de propriété propre | Oui | Oui | 4.7.10 |
| CVE-2026-106446 | CRITICAL | JS injection par confusion de type AST (`Program.blockParams`) | Oui | Oui | 4.7.10 |
| CVE-2026-106444 | MEDIUM | XSS via balise de fermeture `script` dans des modèles précompilés | Oui | Non | 4.7.10 |

Il y a donc **3 détections** dans le rapport initial et **2** dans le rapport HIGH/CRITICAL. Ces trois identifiants sont des avis distincts; aucun alias de CVE n’a été constaté entre ces trois lignes du rapport. Le filtre omet l’alerte MEDIUM, il ne l’annule pas.

## Installation, résolution et consommateurs

**Preuve H-01 — dépendance et résolution.** Le `package.json` applicatif déclare `hbs@^4.2.0`; l’image contient `hbs@4.3.1`, qui dépend de `handlebars@4.7.9`. L’installation de Handlebars est hoistée à `juice-shop/node_modules/handlebars`. Le module `juice-shop/node_modules/hbs/lib/hbs.js` importe cette installation. Aucune seconde installation de Handlebars n’a été trouvée dans l’arborescence inspectée.

**Preuve H-02 — moteur de vues.** `server.ts:164-165` configure Express avec `hbs` comme moteur de vues. Le consommateur observé est donc principalement le moteur de vues `hbs`, qui appelle Handlebars en interne; ce n’est pas un appel applicatif direct à `Handlebars.compile`.

**Preuve H-03 — source des modèles.** Dans `node_modules/hbs/lib/hbs.js:73-76`, les options par défaut de rendu positionnent `allowProtoMethodsByDefault: true` et `allowProtoPropertiesByDefault: true`. Dans `node_modules/hbs/lib/hbs.js:91,107`, le moteur récupère le modèle de vue et appelle `handlebars.compile(str)` lors de son chargement, puis exécute le modèle mis en cache avec les locals. Le texte compilé provient du fichier de vue sélectionné par le moteur. Cela établit une compilation des modèles de vues, mais ne prouve pas que leur texte est contrôlé par un utilisateur.

**Preuve H-04 — vues et données.** Les deux vues Handlebars applicatives observées sont `views/dataErasureForm.hbs` et `views/dataErasureResult.hbs`. Leurs interpolations utilisent les accolades doubles (échappement HTML par défaut); aucune interpolation triple accolade n’a été trouvée. La vue du formulaire reçoit notamment `userEmail` et `securityQuestion`. Dans `routes/dataErasure.ts:26-43,50-52`, les valeurs sont dérivées de l’utilisateur authentifié et d’une question récupérée en base. Sur le chemin ordinaire, ces valeurs sont des **données** passées à un modèle de vue, et non le texte du modèle lui-même.

**Parcours de challenge complété ci-dessous.** La requête ne choisit pas le nom principal de la vue (`dataErasureResult`); `req.body.layout` est néanmoins copié dans les locals des deux branches. HBS interprète ensuite cette propriété comme le chemin du fichier de layout et peut lire puis compiler son contenu. Cela établit un contrôle du chemin et de la sélection de fichier, mais pas des octets du fichier. Voir H-05 à H-10.

Les appels `pug.compile` relevés dans `routes/userProfile.ts:90` et `routes/videoHandler.ts:69` sont des appels au moteur **Pug**, pas à Handlebars. Ils ne constituent pas des consommateurs Handlebars. Aucune utilisation applicative directe de `Handlebars.precompile` ou `Handlebars.template` n’a été observée dans le périmètre inspecté. Aucun helper personnalisé Handlebars applicatif n’a été identifié.

## Modèle contrôlé et données contrôlées

La distinction est déterminante pour ces avis :

- **Contrôle du modèle** : l’attaquant peut choisir le texte du modèle ou l’AST remis à une API de compilation/précompilation. Les avis CVE-2026-106445, CVE-2026-106446 et CVE-2026-106444 nécessitent chacun un chemin de ce type, avec des conditions propres à l’avis.
- **Contrôle des données** : l’attaquant fournit des valeurs utilisées comme contexte d’un modèle fixe. Les valeurs interpolées n’altèrent pas à elles seules la grammaire du modèle. L’option `allowProtoMethodsByDefault: true` rend toutefois nécessaire l’examen des objets de contexte et des expressions capables d’accéder à leurs propriétés ou méthodes; la seule présence de cette option ne prouve ni un chemin exploitable ni l’absence de risque.

Les modèles observés utilisent des expressions simples et échappées. Cela réduit les usages qui ressortent de l’inspection, mais ne démontre pas à lui seul la sûreté de tous les objets de contexte, helpers ou branches de challenge.

## Conditions des avis et rapprochement

| Détection et avis officiel | Prérequis décrits par l’avis | Preuves observées | Éléments absents ou inconnus | Conclusion provisoire |
|---|---|---|---|---|
| CVE-2026-106445 — [GHSA-p8wg-vrv2-v86f](https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-p8wg-vrv2-v86f) | Version affectée jusqu’à 4.7.9; modèle contrôlé, `allowProtoMethodsByDefault: true` et fonction accessible dans le contexte. | Version 4.7.9 et option activée par HBS (`hbs.js:73-76`). Le chemin du layout vient de `req.body.layout`, puis le fichier est lu et compilé (H-05 à H-09). | Aucun contrôle de l’utilisateur sur les octets du fichier ni fonction de contexte pertinente n’est établi. | Option requise et contrôle du chemin observés; prérequis de modèle contrôlé non établi. Applicabilité à approfondir, exploitation non démontrée. |
| CVE-2026-106446 — [GHSA-8r5x-fm3f-whwj](https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-8r5x-fm3f-whwj) | Version affectée >=4.0.0 et <=4.7.9; objet/AST non fiable remis à `compile()` ou `precompile()`. Une chaîne ordinaire n’est pas concernée; certains champs AST requièrent `stringParams: true`. | HBS lit le fichier sélectionné comme chaîne UTF-8 et appelle `compile(str)` (`hbs.js:102-107,201-215`). | Aucun AST issu de la requête n’est transmis. | Prérequis AST absent dans le chemin inspecté; le choix de chemin ne transforme pas la chaîne en AST. |
| CVE-2026-106444 — [GHSA-xw65-4hp5-5hc7](https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-xw65-4hp5-5hc7) | Modèle contrôlé passé à `precompile()`, puis résultat généré inséré directement dans un élément HTML `<script>`. | HBS compile et rend un layout; la branche challenge tronque le HTML rendu. | Aucun `precompile()` ni insertion de sa sortie JavaScript dans `<script>` observé. | Prérequis spécifiques absents de ce chemin; la balise `<script>` statique de la vue ne correspond pas à l’avis. |

## Synthèse et limites

> **Mise à jour du 25 octobre 2026 :** le complément ci-dessous remplace, pour `dataErasure`, les incertitudes antérieures sur le choix de vue et l’argument de rendu. La vue principale est constante; `req.body.layout` devient une option consommée par HBS.

### Complément — traçage détaillé de `dataErasure`

Les extraits ci-dessous renvoient aux lignes inspectées dans l’image. Aucun appel de rendu n’a été exécuté.

**Preuve H-05 — route, authentification et séquence POST (`routes/dataErasure.ts:74-101`).** La route POST est montée sous `/dataerasure` (`server.ts:683-684`). Elle exige un utilisateur présent dans `authenticatedUsers` à partir du cookie (`dataErasure.ts:76-80`), crée ensuite la demande d’effacement et efface le cookie (`:82-89`) avant le rendu. Le type du corps déclare `layout?: string` (`:68-72`); ce typage ne valide pas à lui seul la valeur reçue.

**Preuve H-06 — branche spéciale (`routes/dataErasure.ts:103-121`).** La condition est `req.body.layout` truthy ET `utils.isChallengeEnabled(challenges.lfrChallenge)` (`:103`). `path.resolve(req.body.layout).toLowerCase()` est utilisé uniquement pour vérifier les sous-chaînes `ftp`, `ctf.key` et `encryptionkeys` (`:104-106`). Ce chemin résolu n’est pas passé comme premier argument de `res.render`. Si la liste de sous-chaînes ne correspond pas, le code rend la vue constante `dataErasureResult` (`:107`), avec `...req.body`, puis `...themeVars` (`:108-109`), plus une callback (`:110`). Cette callback envoie les 100 premiers caractères du HTML suivi d’un marqueur (`:114-115`) puis marque le challenge comme résolu (`:116`). Si une sous-chaîne est interdite, la branche renvoie une erreur (`:119-121`).

**Preuve H-07 — branche normale ou challenge désactivé (`routes/dataErasure.ts:122-126`).** Le `else` rend également la vue constante `dataErasureResult` (`:123`) et transmet les mêmes spreads `...req.body`, puis `...themeVars` (`:124-125`). Si le corps contient `layout` mais que le challenge est désactivé, ce champ demeure donc dans l’objet passé à Express; le code ne l’efface pas.

**Preuve H-08 — distinction vue / locals / options (Express et HBS).** Dans les deux appels POST, le premier argument de `res.render` est constant. Le second argument contient les locals construits avec le corps, puis les variables de thème qui remplacent d’éventuelles valeurs de même nom. Express fusionne ces options dans `renderOptions` (`node_modules/express/lib/application.js:562-571`), puis construit l’objet `View` à partir du nom de vue (`:583-609`). `node_modules/express/lib/view.js:52-95,104-120` ajoute l’extension du moteur si nécessaire et résout le nom de vue depuis la racine de vues. HBS lit ensuite `options.layout` (`node_modules/hbs/lib/hbs.js:143-149`) : ce champ est interprété comme option de layout, il ne remplace pas le nom de vue donné à `res.render`.

**Preuve H-09 — sélection, lecture, compilation et rendu du layout (`node_modules/hbs/lib/hbs.js:143-219`).** Si `layout` vaut `false`, HBS rend uniquement le fichier principal (`:151-155`). Sinon, HBS construit un chemin depuis `options.settings.views` et la valeur de layout avec `path.join`, ou utilise le layout conventionnel; il ajoute l’extension de la vue principale si le chemin n’a pas d’extension (`:158-168`). Il peut réutiliser un modèle en cache (`:170-175`); autrement `fs.readFile(..., 'utf8')` lit le fichier (`:198-215`), puis `handlebars.compile(str)` compile son texte (`:189-195`). HBS rend le fichier principal et place son résultat dans `body` du layout (`:123-140`). La valeur contrôlée par la requête sélectionne ainsi le chemin/fichier à lire et compiler. La garde de la route vérifie des sous-chaînes dans un appel `path.resolve` distinct; ce n’est pas une contrainte de résolution sous la racine de vues appliquée par HBS.

**Portée du contrôle démontré.** L’utilisateur contrôle la valeur du chemin de layout et donc le choix du fichier local que le moteur tente de lire. Le contenu lu par `compile()` provient de ce fichier; il n’est pas le texte transmis directement dans la requête. La route ne démontre ni que l’utilisateur peut écrire ou modifier un fichier sélectionnable, ni que le contenu de chaque fichier est un modèle valide ou contrôlé par lui, ni l’accès réussi à un chemin arbitraire. La sortie est du HTML rendu, pas les octets bruts du fichier; la branche spéciale en tronque une partie. Aucun chemin n’a été soumis pour vérifier le comportement.

**Preuve H-10 — configuration et activation du challenge.** Les métadonnées de `lfrChallenge` le décrivent comme challenge de lecture de fichier local et portent `disabledEnv: Docker, Heroku` (`data/static/challenges.yml:1456-1472`). Le défaut de l’image `config/default.yml:89` a été lu directement : `challenges.safetyMode: auto`. La logique `getChallengeEnablementStatus` active les challenges si le mode vaut `disabled`; sinon elle désactive le challenge dans une plateforme figurant dans `disabledEnv`, puis désactive les défis dangereux lorsque le mode vaut `enabled` (`lib/utils.ts:153-185`). Pour une exécution Docker avec ce défaut effectivement chargé, `isChallengeEnabled(lfrChallenge)` est donc faux. Le conteneur existant est arrêté; aucun réglage applicatif ne figure dans ses deux noms d’environnement (`PATH`, `SSL_CERT_FILE`), il n’a aucun montage, et ses fichiers `config` ne sont pas modifiés, mais cela ne prouve pas la configuration chargée lors d’une exécution passée. Dans ce cas, la branche `else` conserve tout de même `req.body.layout` (H-07); le contrôle du layout ne dépend donc pas uniquement de l’activation du challenge. La branche de challenge ajoute toutefois le filtre de sous-chaînes, la troncature et la résolution du challenge. Voir aussi les preuves Docker D-01/D-02/D-05 de [13-file-type.md](13-file-type.md).

### Rapprochement révisé des trois avis pour ce chemin

| Avis officiel | Ce que `dataErasure` établit | Ce qui manque / conclusion pour ce chemin |
|---|---|---|
| CVE-2026-106445 — [GHSA-p8wg-vrv2-v86f](https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-p8wg-vrv2-v86f) | Handlebars 4.7.9; `allowProtoMethodsByDefault: true` par défaut dans HBS (`hbs.js:73-76`); chemin de layout choisi par l’utilisateur, fichier lu puis compilé. | Le chemin choisi n’établit pas le contrôle des octets du modèle. Aucun moyen d’écriture de fichier sélectionnable ni fonction requise dans le contexte du layout n’a été établi. **Option requise présente, contrôle du chemin présent, prérequis du contenu contrôlé encore inconnu** : applicabilité non tranchée, exploitation non démontrée. |
| CVE-2026-106446 — [GHSA-8r5x-fm3f-whwj](https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-8r5x-fm3f-whwj) | La route ne transmet pas `req.body` à `compile`; HBS lit un fichier en chaîne UTF-8 et appelle `compile(str)` (`hbs.js:102-107,201-215`). | Aucun AST/objet non fiable n’est passé à `compile` ou `precompile` dans ce parcours. **Prérequis AST absent dans le chemin inspecté**; le choix d’un chemin n’est pas un objet AST. |
| CVE-2026-106444 — [GHSA-xw65-4hp5-5hc7](https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-xw65-4hp5-5hc7) | HBS emploie `compile`, rend une vue/layout, puis Express retourne du HTML; la branche challenge retourne une tranche de ce HTML. | Aucun `precompile()` ni insertion de sa sortie JavaScript dans un `<script>` n’est observé. Le `<script>` déjà présent dans la vue fixe ne constitue pas cette chaîne de traitement. **Prérequis spécifique absent pour ce chemin.** |

**Limites précises.** Le contenu du défaut image est confirmé, mais l’état runtime effectif de `challenges.safetyMode` pendant une exécution passée reste inconnu : le conteneur présent est arrêté. Les sources inspectées ne permettent pas d’affirmer qu’aucun autre composant ne peut écrire un fichier atteignable par le layout. Aucun rendu, compilation manuelle ou essai de sélection de chemin n’a été réalisé.

L’image contient Handlebars 4.7.9 derrière le moteur hbs. L’option allowProtoMethodsByDefault est activée par défaut. Pour dataErasure, la vue principale est constante, mais req.body.layout est transmis dans les locals puis interprété par HBS comme chemin du layout. L’avis CVE-2026-106445 reste à approfondir, car le contrôle du contenu du fichier et le contexte nécessaire ne sont pas établis. Les prérequis AST de CVE-2026-106446 et le pipeline precompile puis insertion dans script de CVE-2026-106444 ne sont pas observés dans ce parcours.

Constat applicatif distinct HBS-APP-01 : contrôle de chemin observé statiquement ; lecture arbitraire et exploitation non démontrées. La configuration runtime effective et les autres possibilités d’écriture de fichiers restent inconnues; les conclusions restent limitées aux sources inspectées. La présence d’une version vulnérable ne démontre pas à elle seule l’exploitation.
