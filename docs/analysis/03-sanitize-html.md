# Analyse statique — sanitize-html

## Périmètre et rapports

Analyse en lecture seule des rapports Trivy 0.76.0 et des sources de l’image associée à l’ImageID du rapport. Le rapport initial, conservé dans Git sur la branche docs/project-readme sous reports/trivy-image-initial.json, porte CreatedAt 2026-10-20T11:28:17.521956103Z. Le rapport filtré reports/trivy-image-high-critical.json porte CreatedAt 2026-10-21T14:42:43.231675625Z. Ce sont deux rapports distincts.

Le rapport initial compte neuf lignes d’alerte sanitize-html, toutes pour la même installation. Le filtre HIGH/CRITICAL conserve une seule ligne. Aucun scan, test d’exploitation ou changement applicatif n’a été effectué.

## Installation et consommateurs observés

| Paquet | Version | Chemin dans l’image | Déclarant / consommateurs |
|---|---:|---|---|
| sanitize-html | 1.4.2 | juice-shop/node_modules/sanitize-html/package.json | Dépendance directe de Juice Shop (package.json racine: 1.4.2). Appels dans lib/insecurity.ts et lib/challengeUtils.ts. |

sanitize-html 1.4.2 charge htmlparser2 (~3.3.0), he (~0.4.1) et lodash (2.4.x). Le lodash imbriqué est celui analysé dans 02-lodash.md. Les numéros de ligne cités ci-dessous proviennent des fichiers de l’image auditée.

## Détections du rapport initial

| Identifiant | Sévérité Trivy | Résumé | HIGH/CRITICAL |
|---|---:|---|---|
| CVE-2022-25887 | HIGH | ReDoS dans le retrait de commentaires HTML par regex globale | Oui |
| CVE-2016-1000237 | MEDIUM | XSS — nettoyage non récursif | Non |
| CVE-2017-16016 | MEDIUM | XSS lorsque allowedTags comprend un nonTextTag | Non |
| CVE-2019-25225 | MEDIUM | XSS avec l’option personnalisée transformTags | Non |
| CVE-2021-26539 | MEDIUM | Contournement de liste blanche d’hôtes d’iframe avec IDN | Non |
| CVE-2021-26540 | MEDIUM | Contournement de liste blanche d’iframe si allowIframeRelativeUrls est activé | Non |
| CVE-2024-21501 | MEDIUM | Information exposure côté backend si style est autorisé | Non |
| CVE-2026-63670 | MEDIUM | Bypass XSS si textarea/xmp est autorisé et fermeture littérale avec slash | Non |
| NSWG-ECO-154 | MEDIUM | XSS avec un nonTextTag autorisé | Non |

NSWG-ECO-154 renvoie au même avis Node.js Security Working Group 154 et au même scénario que CVE-2017-16016 (GHSA-xc6g-ggrc-qq4r). Les deux lignes restent visibles pour la traçabilité, mais ne sont pas deux problèmes distincts. Le rapport contient neuf détections et huit CVE distincts.

## Comportement de sanitize-html 1.4.2

Dans node_modules/sanitize-html/index.js, sanitizeHtml(html, options) applique les défauts si options manque (lignes 25–29). Les valeurs par défaut (lignes 249–261) autorisent notamment a, mais pas script, style, textarea, xmp ou iframe. Les attributs par défaut sont href/name/target sur a et src sur img; style n’est pas permis. Les schémas URL admis par défaut sont http, https, ftp et mailto.

L’appel security.sanitizeHtml(html) n’ajoute aucune option. security.sanitizeSecure(html) rappelle le sanitizer jusqu’à ce que sa sortie soit identique à l’entrée (lib/insecurity.ts, lignes 58–67). L’appel de notification passe explicitement allowedTags: [] et allowedAttributes: {}, ce qui n’autorise aucun tag ni attribut (lib/challengeUtils.ts, ligne 65). Aucun réglage applicatif de allowedIframeHostnames, allowIframeRelativeUrls ou transformTags, ni mutation de sanitizeHtml.defaults, n’a été trouvé.

Dans le paquet, naughtyHref est appelé pour href et src (index.js, lignes 117–124); il retire ensuite les commentaires de l’URL avec href.replace(/<!--.*?-->/g, '') (ligne 223). Le correctif amont de CVE-2022-25887 remplace cette regex globale par une boucle de recherche des bornes de commentaires.

## Conditions exactes des branches de challenge

Les setters ne se basent pas sur le champ solved pour choisir la fonction de nettoyage. Ils appellent utils.isChallengeEnabled(challenge); cette fonction retourne le champ enabled de getChallengeEnablementStatus (lib/utils.ts, lignes 153–185). Le statut dépend de disabledEnv et de challenges.safetyMode, pas du fait que le défi ait déjà été résolu.

Le YAML de défis data/static/challenges.yml déclare disabledEnv: Docker, Heroku pour restfulXssChallenge, persistedXssUserChallenge, persistedXssFeedbackChallenge et httpHeaderXssChallenge (respectivement lignes 25–28, 248–251, 1077–1080 et 542–545). Au démarrage, data/datacreator.ts, lignes 80–87 et 117–130, évalue ces listes avec getChallengeEnablementStatus et persiste la cause de désactivation (par exemple Docker), ou null si le défi est disponible.

Dans l’image, config/default.yml, ligne 89, règle safetyMode à auto. La fonction isDocker (lib/is-docker.ts, lignes 8–35) détecte les marqueurs du conteneur à l’exécution : /.dockerenv, cgroup ou mountinfo. Avec le profil par défaut auto et une exécution où cette détection est vraie, les défis portant disabledEnv Docker sont indisponibles. safetyMode: disabled court-circuite ces restrictions et les laisse disponibles même dans Docker; safetyMode: enabled désactive tout défi qui déclare disabledEnv, même hors des environnements listés. Les profils unsafe.yml, ctf.yml et defcon33.yml présents dans l’image déclarent safetyMode: disabled. Le rapport d’image ne prouve pas quel profil ou surcharge de configuration a effectivement été chargé par le processus lors de l’exécution; l’état runtime des défis reste donc à confirmer.

La distinction opérationnelle est la suivante : « disponible/actif » signifie que getChallengeEnablementStatus autorise le défi et que le setter prend sa branche correspondante. « Résolu » est l’état ChallengeModel.solved. challengeUtils.solveIf vérifie notSolved(challenge) avant d’évaluer son critère; cela évite de résoudre de nouveau le défi, mais ne modifie ni safetyMode ni la branche du setter. Un défi résolu mais toujours disponible continue donc à sélectionner la même branche.

Effet précis sur les appels examinés :

- Feedback : si persistedXssFeedbackChallenge est disponible, une passe security.sanitizeHtml(comment); sinon security.sanitizeSecure(comment), qui répète le nettoyage jusqu’à stabilité.
- Produit : si restfulXssChallenge est disponible, le setter conserve description telle quelle; sinon il appelle sanitizeSecure.
- Username et email : si persistedXssUserChallenge est disponible, username passe dans sanitizeLegacy et email reste tel quel; sinon les deux passent dans sanitizeSecure.
- IP de connexion : si httpHeaderXssChallenge est disponible, sanitizeSecure est omis; sinon il est appliqué.

Ces choix existent parce que les défis sont activables par configuration et environnement; ils ne sont pas conditionnés par leur résolution antérieure. Pour la cible Docker et le profil default auto, le code indique que les défis marqués Docker devraient être désactivés au démarrage, mais cela ne confirme pas l’environnement ni le profil de configuration du runtime analysé.

## Appels applicatifs : provenance, options et destination

| Appel | Provenance et options | Traitement après nettoyage | Destination |
|---|---|---|---|
| Feedback — models/feedback.ts, lignes 41–51 | Commentaire saisi dans Contact (frontend/src/app/contact/contact.component.ts, ligne 82), puis POST /api/Feedbacks. L’endpoint permet les retours sans connexion, avec vérification CAPTCHA (server.ts, lignes 388–390 et 430–434). Le commentaire et le nom éventuel sont assemblés avant FeedbackModel.create (data/datacreator.ts, lignes 578–580). En fonctionnement ordinaire, sanitizeSecure applique les options par défaut. Si persistedXssFeedbackChallenge est actif, un seul appel à sanitizeHtml est fait. | Le setter ne transforme pas davantage le commentaire. | Stocké dans Feedbacks. GET /api/Feedbacks alimente About et Administration. Ces composants appellent bypassSecurityTrustHtml sur le commentaire (about.component.ts, lignes 117–127; administration.component.ts, lignes 87–96), puis le template l’affiche par innerHTML. |
| Description produit — models/product.ts, lignes 51–62 | Principalement catalogue chargé par data/datacreator.ts (lignes 423–433); POST /api/Products existe mais exige isAuthorized (server.ts, lignes 396–399). Options par défaut via sanitizeSecure, sauf si restfulXssChallenge est actif : la description est alors conservée sans cet appel. | Aucun nettoyage serveur ultérieur établi. | Stockée dans Products et exposée par l’API. product-details.component.html, ligne 18, l’affiche par innerHTML; search-result.component.ts, lignes 111–114, la marque aussi comme HTML de confiance. |
| Username et email — models/user.ts, lignes 44–68 | Valeurs fournies à l’inscription POST /api/Users, ou username modifié par updateUserProfile (routes/updateUserProfile.ts, ligne 38). Options par défaut via sanitizeSecure, sauf persistedXssUserChallenge : username passe par sanitizeLegacy et email n’est pas nettoyé dans ce setter. | Pas d’autre transformation après le setter identifiée. | Stockés dans Users et retournés par les API. Administration enveloppe email dans un span puis appelle bypassSecurityTrustHtml (administration.component.ts, lignes 68–76); le template l’affiche comme HTML. |
| IP du dernier login — routes/saveLoginIp.ts, lignes 14–33 | Pour un utilisateur connecté, vient de l’en-tête true-client-ip, ou de l’adresse socket si l’en-tête est absent. sanitizeSecure avec défauts, sauf si httpHeaderXssChallenge est actif. | Affectée à lastLoginIp par UserModel.update; l’endpoint renvoie l’utilisateur en JSON. Le frontend enveloppe ensuite la valeur dans small et appelle bypassSecurityTrustHtml (last-login-ip.component.ts, lignes 33–41). | Persistée en base et incluse dans les données du compte; rendue comme HTML via innerHTML. |
| Notification de défi — lib/challengeUtils.ts, ligne 65 | challenge.description vient du modèle Challenge et des données de défis de l’application; aucun flux du formulaire utilisateur n’a été identifié pour cet appel. Options explicites allowedTags: [] et allowedAttributes: {}. | entities.decode est exécuté après le sanitizer et peut réintroduire des caractères HTML. La chaîne est jointe à la notification, gardée en mémoire et émise par Socket.IO (lignes 62–75). | Le client construit le message reçu; le template l’affiche par interpolation Angular (challenge-solved-notification.component.ts, lignes 122–138 et HTML ligne 10), pas avec innerHTML dans ce composant. |

Les branches de challenge qui affaiblissent ou omettent le nettoyage sont des comportements applicatifs conditionnels. Elles ne prouvent pas l’applicabilité d’un avis précis; elles modifient toutefois les appels réellement effectués lorsque la condition est active.

## Ordre du POST feedback et limite de taille

L’ordre statique dans server.ts est :

1. bodyParser.urlencoded({ extended: true }) est installé à la ligne 335.
2. bodyParser.text({ type: '*/*' }) est installé ligne 342; le middleware jsonParser qui suit enregistre req.rawBody puis applique JSON.parse aux corps dont le Content-Type contient application/json (lignes 343–354).
3. Les middlewares des routes sont enregistrés ensuite. Pour POST /api/Feedbacks, forgedFeedbackChallenge s’exécute en premier (ligne 430), verifyCaptcha ensuite (ligne 432), puis captchaBypassChallenge (ligne 434).
4. verifyCaptcha cherche le captchaId en base et compare req.body.captcha à la réponse stockée; en cas d’échec ou d’absence, il renvoie HTTP 401 sans appeler next (routes/captcha.ts, lignes 35–46). forgedFeedbackChallenge et captchaBypassChallenge sont des évaluateurs de défis; ils appellent next et ne remplacent pas la validation CAPTCHA. captchaBypassChallenge n’est placé qu’après verifyCaptcha.
5. Après validation, la route REST générée par finale-rest traite le POST /api/Feedbacks (server.ts, lignes 507–535). La création Sequelize appelle le setter comment de FeedbackModel, qui choisit sanitizeHtml ou sanitizeSecure, appelle solveIf si besoin, puis affecte la valeur nettoyée à setDataValue avant persistance (models/feedback.ts, lignes 41–51).

Aucune option limit n’est fournie aux appels bodyParser.urlencoded ou bodyParser.text. Dans la version de body-parser incluse dans l’image, leurs valeurs par défaut sont 102400 octets (100 kb), visibles dans node_modules/body-parser/lib/types/urlencoded.js, lignes 53–55, et lib/types/text.js, lignes 38–40. Pour un corps JSON reçu avec application/json, c’est le parseur text configuré sur */* qui lit d’abord le corps et applique cette limite avant JSON.parse. Cela borne la taille de ce corps au niveau de l’application; des limites de proxy ou d’infrastructure éventuelles ne sont pas connues ici. Aucune requête n’a été soumise.

## Avis officiels et conclusions provisoires

### Synthèse des neuf détections

| Détection | Prérequis rapprochés des usages | Preuve statique | Conclusion et limite |
|---|---|---|---|
| CVE-2022-25887 | Entrée contrôlée dans un href autorisé : présent pour les commentaires de feedback; validation CAPTCHA requise. Taille du corps applicatif bornée par défaut à 100 kb. | Défauts autorisent a/href; naughtyHref appelle la regex globale; commentaire de POST feedback atteint le setter. | Chemin jusqu’à la regex établi. Aucune latence ou indisponibilité démontrée; le payload exact et les limites d’infrastructure n’ont pas été évalués. |
| CVE-2016-1000237 | Version antérieure à 1.4.3 présente. Une passe unique nécessite persistedXssFeedbackChallenge disponible; le profil default auto désactive ce défi si isDocker() est vrai. | Branche challenge appelle sanitizeHtml une fois; branche normale appelle sanitizeSecure en boucle. Le résultat du feedback est stocké et affiché comme HTML de confiance. | Applicabilité à une passe unique dépend du profil et de l’environnement réellement chargés, inconnus pour l’exécution auditée. Le wrapper ordinaire apporte des passes supplémentaires, sans preuve de mitigation universelle. |
| CVE-2017-16016 | Version affectée présente; allowedTags doit comprendre un nonTextTag. | Défauts n’autorisent ni script/style ni textarea; seul appel avec tags explicites passe une liste vide. | Prérequis d’options absent dans les appels inspectés. |
| CVE-2019-25225 | Version affectée présente; option transformTags nécessaire. | Aucun appel ni réglage global transformTags trouvé. | Prérequis absent dans le périmètre statique inspecté. |
| CVE-2021-26539 | Version affectée présente; liste allowedIframeHostnames et entrée IDN requises. | Aucune option de liste blanche d’iframe; iframe non autorisé par défaut. | Prérequis de configuration absent dans les appels observés. |
| CVE-2021-26540 | Version affectée présente; allowedIframeHostnames et allowIframeRelativeUrls: true requis. | Aucune des deux options n’est passée; iframe n’est pas dans les tags par défaut. | Prérequis de configuration absent dans les appels observés. |
| CVE-2024-21501 | Exécution backend présente; style doit être autorisé. | Défauts n’autorisent pas style; appel explicite utilise allowedAttributes: {}. | Condition style absente des options inspectées; configuration externe inconnue. |
| CVE-2026-63670 | Version antérieure au correctif présente; textarea ou xmp doit figurer dans allowedTags. | Tags par défaut les excluent; appel explicite de notification n’autorise aucun tag. | Prérequis d’allowlist absent dans les appels inspectés. Le sink HTML ne suffit pas à établir ce vecteur précis. |
| NSWG-ECO-154 | Même prérequis que CVE-2017-16016. | Même avis Node.js Security WG 154 / GHSA-xc6g-ggrc-qq4r et mêmes options applicatives. | Alias/détection redondante de CVE-2017-16016; pas un dixième scénario indépendant. |

### CVE-2022-25887 — ReDoS

L’avis vise sanitize-html avant 2.7.1 et relie le ReDoS au retrait des commentaires d’URL par regex globale. En 1.4.2, cette expression est dans naughtyHref (index.js, ligne 223), appelé pour href/src. Le formulaire de feedback fournit une entrée sans connexion au sanitizer; les défauts autorisent a et href. **Conclusion provisoire :** le chemin vers le mécanisme vulnérable est présent pour du contenu de feedback contrôlé, si la requête franchit la vérification CAPTCHA. Une interruption effective du service n’a pas été testée. [Correctif amont](https://github.com/apostrophecms/sanitize-html/commit/b4682c12fd30e12e82fa2d9b766de91d7d2cd23c), [suivi Red Hat](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2022-25887).

### CVE-2016-1000237 — nettoyage non récursif

L’avis concerne les versions antérieures à 1.4.3 et décrit une XSS possible si l’entrée n’est pas nettoyée récursivement ([GHSA-3j7m-hmh3-9jmp](https://github.com/advisories/GHSA-3j7m-hmh3-9jmp)). La version 1.4.2 est antérieure au correctif. Le chemin ordinaire des feedbacks, produits, comptes et IP passe par sanitizeSecure, qui réapplique le résultat jusqu’à stabilité. Le feedback en mode persistedXssFeedbackChallenge fait une seule passe; le champ est ensuite stocké et affiché comme HTML de confiance. **Conclusion provisoire :** un chemin utilisateur à une seule passe existe lorsque cette branche de challenge est active. Le wrapper itératif ordinaire est une barrière supplémentaire, mais son efficacité contre tous les cas visés n’est pas démontrée. [Correctif amont](https://github.com/apostrophecms/sanitize-html/commit/762fbc7bba389f3f789cc291c1eb2b64f60f2caf).

### CVE-2017-16016 et NSWG-ECO-154 — XSS avec nonTextTag autorisé

L’avis GitHub vise sanitize-html jusqu’à 1.11.1 lorsque allowedTags comprend au moins un nonTextTag; l’exemple utilise textarea ([GHSA-xc6g-ggrc-qq4r](https://github.com/advisories/GHSA-xc6g-ggrc-qq4r)). La version 1.4.2 est dans la plage. Les appels ordinaires utilisent les tags par défaut, qui ne contiennent ni textarea ni script/style; la notification passe une liste vide. Aucun appel ne permet un nonTextTag dans le périmètre inspecté. **Conclusion provisoire :** le prérequis de configuration est absent. NSWG-ECO-154 est une seconde référence de cette même détection/scénario.

### CVE-2019-25225 — XSS avec transformTags

L’avis vise les versions antérieures à 2.0.0-beta lorsque l’option transformTags transforme des attributs en texte sans renettoyer le résultat ([GHSA-qhxp-v273-g94h](https://github.com/advisories/GHSA-qhxp-v273-g94h)). La version 1.4.2 est dans la plage, mais aucun appel ne fournit transformTags; la notification ne passe que allowedTags et allowedAttributes. **Conclusion provisoire :** le prérequis transformTags n’est pas observé.

### CVE-2021-26539 — IDN et liste blanche d’hôtes d’iframe

L’avis vise les versions antérieures à 2.3.1 et l’usage d’allowedIframeHostnames avec un nom de domaine internationalisé mal traité ([GHSA-rjqq-98f6-6j3r](https://github.com/advisories/GHSA-rjqq-98f6-6j3r)). La version 1.4.2 est dans la plage, mais aucun appel ne définit allowedIframeHostnames et les défauts n’autorisent pas iframe. **Conclusion provisoire :** le scénario de liste blanche décrit n’est pas configuré.

### CVE-2021-26540 — validation d’iframe relative

L’avis vise les versions antérieures à 2.3.2 lorsque allowedIframeHostnames est défini et allowIframeRelativeUrls vaut true; une URL d’iframe relative mal formée peut contourner la liste blanche ([GHSA-mjxr-4v3x-q3m4](https://github.com/advisories/GHSA-mjxr-4v3x-q3m4)). La version 1.4.2 est dans la plage, mais les options ne sont pas passées par l’application et iframe est exclu des défauts. **Conclusion provisoire :** prérequis de configuration absent des appels inspectés.

### CVE-2024-21501 — exposition d’information via CSS

L’avis vise les versions antérieures à 2.12.1 utilisées côté backend avec style autorisé ([GHSA-rm97-x556-q36h](https://github.com/advisories/GHSA-rm97-x556-q36h)). L’usage est côté serveur et la version est dans la plage; cependant les défauts n’autorisent pas style et l’appel explicite de notification passe allowedAttributes: {}. **Conclusion provisoire :** prérequis style absent dans les configurations visibles. Un réglage externe à l’application inspectée n’a pas été examiné.

### CVE-2026-63670 — mutation XSS via textarea/xmp

L’avis décrit une fermeture littérale </textarea/> traitée différemment par le parseur et le navigateur, qui peut laisser passer du balisage actif. Il exige textarea ou xmp dans allowedTags et précise que la configuration par défaut n’est pas affectée ([GHSA-jxwj-j7wr-gfrw](https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-jxwj-j7wr-gfrw)). La version 1.4.2 précède le correctif, mais aucune option applicative n’autorise textarea/xmp; les défauts les excluent et la notification passe une liste vide. **Conclusion provisoire :** prérequis d’allowlist absent dans les appels inspectés; un sink HTML à lui seul ne démontre pas ce scénario.

## Limites

- Le chemin ReDoS par href est le plus directement relié à une entrée utilisateur sans connexion identifiée; taille effective des requêtes, limites réseau et effet temporel n’ont pas été évalués.
- Plusieurs valeurs nettoyées sont stockées puis rendues comme HTML de confiance. Cela rend les prérequis du sanitizer importants, sans prouver qu’un avis particulier est exploitable.
- La configuration statique par défaut et les profils alternatifs inclus dans l’image sont identifiés; le profil chargé, la détection effective de l’environnement et l’état solved des défis au runtime ne sont pas établis par le rapport. Le choix des setters dépend de la disponibilité/configuration, pas de solved.
- La notification décode des entités après le nettoyage, mais le rendu inspecté utilise l’interpolation Angular. Les autres consommateurs ou évolutions du rendu ne sont pas couverts.
- Les conclusions proviennent des sources statiques de l’image identifiée. Aucune charge utile n’a été soumise.

## Références officielles

- [CVE-2016-1000237 — GHSA-3j7m-hmh3-9jmp](https://github.com/advisories/GHSA-3j7m-hmh3-9jmp)
- [CVE-2017-16016 / NSWG-ECO-154 — GHSA-xc6g-ggrc-qq4r](https://github.com/advisories/GHSA-xc6g-ggrc-qq4r)
- [CVE-2019-25225 — GHSA-qhxp-v273-g94h](https://github.com/advisories/GHSA-qhxp-v273-g94h)
- [CVE-2021-26539 — GHSA-rjqq-98f6-6j3r](https://github.com/advisories/GHSA-rjqq-98f6-6j3r)
- [CVE-2021-26540 — GHSA-mjxr-4v3x-q3m4](https://github.com/advisories/GHSA-mjxr-4v3x-q3m4)
- [CVE-2022-25887 — correctif amont](https://github.com/apostrophecms/sanitize-html/commit/b4682c12fd30e12e82fa2d9b766de91d7d2cd23c)
- [CVE-2024-21501 — GHSA-rm97-x556-q36h](https://github.com/advisories/GHSA-rm97-x556-q36h)
- [CVE-2026-63670 — GHSA-jxwj-j7wr-gfrw](https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-jxwj-j7wr-gfrw)
