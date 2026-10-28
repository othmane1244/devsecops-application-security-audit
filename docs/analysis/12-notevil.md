# Analyse statique — notevil

## Détection et installation

Le rapport Trivy initial contient une détection **MEDIUM**, CVE-2021-23771, pour notevil@1.3.3, cible Node.js, chemin juice-shop/node_modules/notevil/package.json. La détection n’apparaît pas dans le rapport filtré HIGH/CRITICAL.

L’avis officiel [GHSA-8g4m-cjm2-96wq / CVE-2021-23771](https://github.com/advisories/GHSA-8g4m-cjm2-96wq) couvre notevil jusqu’à 1.3.3 inclus; aucune version corrigée n’est publiée dans l’avis et le paquet est déprécié. Il décrit une sortie du sandbox permettant la pollution de prototypes : la bibliothèque ne restreint pas suffisamment l’accès au contexte principal, et une entrée interprétée peut ajouter ou modifier des propriétés de prototype. Le prérequis applicatif à examiner est qu’une expression contrôlée atteigne l’évaluateur dans un contexte où cet effet peut être observé. La plage Trivy confirme la version signalée, pas ce chemin ni son impact.

## Sources et preuves

| Preuve | Observation |
|---|---|
| N-01 — inventaire image | reports/trivy-image-initial.json:12428–12443 rapporte notevil@1.3.3 au chemin juice-shop/node_modules/notevil/package.json. |
| N-02 — détection image | reports/trivy-image-initial.json:19688–19715 identifie CVE-2021-23771, sévérité MEDIUM, statut affected, ce paquet et chemin. L’avis GHSA est la source de sévérité. |
| N-03 — dépendance applicative publiée | Le manifeste Juice Shop [v20.3.0](https://github.com/juice-shop/juice-shop/blob/v20.3.0/package.json) déclare notevil: ^1.3.3. Le rapport image résout l’installation inventoriée en version 1.3.3. |
| N-04 — implémentation publiée | Le dépôt mainteneur [notevil package.json](https://github.com/mmckegg/notevil/blob/master/package.json) déclare la version 1.3.3; son dépôt est archivé en lecture seule. L’analyse ci-dessous s’appuie sur son [index.js](https://github.com/mmckegg/notevil/blob/master/index.js) et [lib/primitives.js](https://github.com/mmckegg/notevil/blob/master/lib/primitives.js), pas sur des fichiers extraits du conteneur. |
| N-05 — source applicative publiée | Les références Juice Shop pointent vers le tag v20.3.0, correspondant à la version et à l’image consignées dans [README.md](../../README.md). Cela établit le contenu du tag publié, pas une comparaison octet pour octet avec l’image. |

Une recherche statique du code publié v20.3.0 identifie un consommateur direct : routes/b2bOrder.ts. Aucune autre importation directe n’a été relevée dans les sources applicatives consultées; des usages générés ou indirects dans les fichiers du conteneur ne peuvent être exclus sans inspection de celui-ci.

## Chemin d’appel et provenance

**N-06 — route et contrôle d’accès.** Dans server.ts:421–422, security.isAuthorized() est monté sur le préfixe /b2b/v2; server.ts:631–632 enregistre POST /b2b/v2/orders avec b2bOrder(). Dans le code publié, l’appel à cette route passe donc par le contrôle d’autorisation B2B. Une fois autorisé, le corps de requête reste contrôlé par le client.

**N-07 — expression passée à l’évaluateur.** Dans routes/b2bOrder.ts:13–20, le handler :

1. ne lance l’évaluation que si rceChallenge ou rceOccupyChallenge est activé (:15);
2. lit body.orderLinesData || '' sans schéma, allowlist ou validation syntaxique dédiée (:16);
3. place safeEval et orderLinesData dans un nouvel objet sandbox, puis appelle vm.createContext(sandbox) et vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 }) (:18–20).

Une chaîne non vide du champ orderLinesData atteint donc l’argument source de notevil.eval() dans le code publié si la condition de challenge est satisfaite. Une propriété absente ou falsy est remplacée par la chaîne vide. La route ne vérifie pas que la valeur est une chaîne; dans la source notevil, prepareAst parse les chaînes mais transmet les valeurs non-string à hoist comme AST (index.js:34–37). La forme et l’effet d’une telle valeur JSON n’ont pas été vérifiés. Le handler ignore la valeur de retour de l’évaluation; il ne l’utilise pas pour former la commande ou sa réponse. L’accès au chemin nécessite aussi l’autorisation B2B.

## Objets accessibles et mécanisme vulnérable

La source mainteneur de notevil@1.3.3 expose safeEval et crée le contexte à partir de Object.create(parentContext || {}) (index.js:6–16). L’application appelle safeEval avec un seul argument; aucun parentContext applicatif n’est fourni. L’évaluateur ajoute ensuite ses wrappers de types intégrés (lib/primitives.js:0–20), dont Object, String, Boolean, Number, RegExp, Date, Array et Function.

L’évaluateur interprète les accès aux membres et les appels (index.js:326–355), puis permet certaines écritures après contrôle (:389–416,455–473). Une protection explicite refuse une écriture directe de propriété nommée __proto__ (:455–458); les wrappers de primitives visent également à isoler certains prototypes (lib/primitives.js:36–65). Ces contrôles ne suffisent pas à écarter l’avis : celui-ci décrit précisément une restriction incomplète permettant d’atteindre ou de modifier un prototype. Une protection partielle ne prouve pas que les voies d’accès sont fermées.

Dans le contexte construit par la route, les noms expressément fournis sont safeEval et orderLinesData; les types intégrés sont ajoutés par la bibliothèque. La route ne fournit pas explicitement process, require, global ou un objet applicatif comme contexte. Cela borne les valeurs visibles dans le code d’appel, mais ne prouve pas que notevil ne peut pas accéder au contexte principal. L’effet d’une pollution sur le processus Juice Shop n’a pas été exécuté ou établi.

## Conditions de challenge et garde-fous

Les wrappers des types intégrés sont construits à partir des constructeurs globaux du processus (notevil/lib/primitives.js:78–103), puis les accès de propriétés utilisent les helpers de prototypes de la bibliothèque. La route ne fournit pas explicitement process, require, global ou un objet applicatif au contexte de safeEval, mais la fonction safeEval importée du processus hôte est appelée par la chaîne exécutée via vm.runInContext. Cette frontière supplémentaire ne prouve donc pas, à elle seule, que l’interpréteur notevil ou ses objets internes sont isolés du contexte principal. L’avis signale précisément une restriction de contexte incomplète; l’effet d’une pollution sur le processus Juice Shop n’a pas été exécuté ou établi.

Dans les fichiers Juice Shop v20.3.0 présents dans l’image, les défis `rceChallenge` et `rceOccupyChallenge` portent `disabledEnv: Docker, Heroku` (`data/static/challenges.yml:162–178, 1095–1108`). Le défaut image `config/default.yml:89` a été vérifié directement : `challenges.safetyMode: auto`. Le helper `lib/utils.ts:141–170` désactive un défi Docker dans ce mode (`:154–156`), mais réactive les défis `disabledEnv` si le mode configuré vaut `disabled` (`:151–152`). Les sources prévoient donc que le chemin d’évaluation est inactif sous Docker si le défaut est chargé; une surcharge peut changer ce résultat. Le conteneur existant est arrêté, sans montage ni variable d’environnement applicative; ses fichiers `config` sont inchangés, mais l’état de configuration d’une exécution passée reste inconnu. Voir les preuves D-01/D-02/D-05 de [13-file-type.md](13-file-type.md).

Si la branche d’évaluation est active, notevil borne certaines boucles à 1 000 000 itérations (index.js:11,165–184,222–228; lib/infinite-checker.js:2–15). vm.runInContext a aussi un délai de 2 000 ms (routes/b2bOrder.ts:20). Les erreurs de timeout sont traitées séparément du dépassement de compteur (:22–29). Ces limites réduisent certains scénarios de déni de service; elles ne valident pas l’expression et ne démontrent pas l’absence de pollution de prototype.

| Prérequis / contrôle | État établi statiquement |
|---|---|
| Version et mécanisme de sandbox signalés | Version présente dans l’image; évaluateur et accès/écritures de propriétés présents dans la source publiée. |
| Consommateur applicatif | Présent dans routes/b2bOrder.ts du tag v20.3.0. |
| Expression / valeur contrôlée par requête | Présente conditionnellement : orderLinesData va à l’évaluateur sans validation de type ou de syntaxe si un challenge RCE est actif; les valeurs non-string sont transmises au chemin AST de notevil. |
| Autorisation | Requise dans le code publié par le middleware sur /b2b/v2. |
| Challenge actif dans Docker avec défaut image | Le profil par défaut de l’image dit `auto`; les challenges Docker sont prévus désactivés si ce fichier est chargé. Le conteneur arrêté ne permet pas d’établir quel profil a été chargé lors de son exécution antérieure. |
| Impact sur un prototype partagé / le processus | Le mécanisme est décrit par l’avis; effet dans ce chemin applicatif non vérifié. |
| Exploitation réelle | Non démontrée; aucune requête ni aucun test d’exploitation effectué. |

## Conclusion

`notevil@1.3.3` est une détection MEDIUM valide du rapport initial et `routes/b2bOrder.ts` est un consommateur observé dans les fichiers non modifiés de l’image. Le mécanisme vulnérable est présent dans la bibliothèque; une expression du corps de requête peut atteindre `safeEval` lorsque le challenge RCE est actif. Le chemin requiert une autorisation B2B et le défaut image prévoit de désactiver les challenges Docker. Le conteneur est arrêté; ni le profil effectivement chargé lors d’une exécution passée ni l’exécution de la route ne sont établis. L’exploitation n’est pas démontrée.

## Limites de vérification

Docker Engine 29.1.2 et le contexte `desktop-linux` sont accessibles. Le tag local Juice Shop a les mêmes 24 empreintes de couches que le rapport initial; l’ID Docker diffère toutefois du `ImageID` Trivy. Le conteneur `juice-shop-audit` est arrêté, sans montage; aucun état runtime actif n’a donc été vérifié. Les valeurs par défaut et profils image sont consignés dans [13-file-type.md](13-file-type.md). Aucun conteneur n’a été démarré, aucun scan, aucune requête applicative ni test d’exploitation n’a été effectué.

## Références

- [Avis officiel GHSA-8g4m-cjm2-96wq / CVE-2021-23771](https://github.com/advisories/GHSA-8g4m-cjm2-96wq).
- Juice Shop v20.3.0 : [routes/b2bOrder.ts](https://github.com/juice-shop/juice-shop/blob/v20.3.0/routes/b2bOrder.ts), [server.ts](https://github.com/juice-shop/juice-shop/blob/v20.3.0/server.ts), [data/static/challenges.yml](https://github.com/juice-shop/juice-shop/blob/v20.3.0/data/static/challenges.yml), [lib/utils.ts](https://github.com/juice-shop/juice-shop/blob/v20.3.0/lib/utils.ts), [config/default.yml](https://github.com/juice-shop/juice-shop/blob/v20.3.0/config/default.yml), [package.json](https://github.com/juice-shop/juice-shop/blob/v20.3.0/package.json).
- Sources mainteneur publiées : [notevil index.js](https://github.com/mmckegg/notevil/blob/master/index.js), [primitives.js](https://github.com/mmckegg/notevil/blob/master/lib/primitives.js), [infinite-checker.js](https://github.com/mmckegg/notevil/blob/master/lib/infinite-checker.js), [package.json](https://github.com/mmckegg/notevil/blob/master/package.json).
- Rapports conservés : [Trivy initial](../../reports/trivy-image-initial.json) et [filtre HIGH/CRITICAL](../../reports/trivy-image-high-critical.json).
