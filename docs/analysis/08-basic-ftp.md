# Analyse statique de basic-ftp

## Périmètre et détection

Le rapport initial et le rapport filtré HIGH/CRITICAL signalent la même installation : `basic-ftp@5.3.1`, chemin `juice-shop/node_modules/basic-ftp/package.json`, une détection HIGH. L’avis est `CVE-2026-102990`, déni de service par temps quadratique dans l’analyse des listes de répertoires Unix de `Client.list()`. Il concerne les versions jusqu’à 6.2.0 et indique 6.2.1 comme version corrigée. L’avis GitHub associe explicitement le CVE à `GHSA-c475-qrg2-pj4r` : il s’agit de deux identifiants du même avis, pas de deux détections.

Le rapport initial date du `2026-10-20T11:28:17.521956103Z`; le rapport HIGH/CRITICAL du `2026-10-21T14:42:43.231675625Z`. Les rapports JSON n’ont pas été modifiés.

## Conditions décrites par l’avis

L’avis officiel décrit un scénario où un serveur FTP malveillant ou compromis fournit une longue ligne de listing Unix construite pour faire rétrograder la regex `RE_LINE`. Il faut que `Client.list()` traite le listing; dans le scénario décrit, une ligne Unix normale placée en dernier sélectionne le parseur Unix pour toutes les lignes, et la ligne préparée provoque le coût CPU quadratique. L’effet décrit est le blocage de la boucle d’événements Node.js.

L’avis indique les versions affectées `<= 6.2.0`, la correction `6.2.1`, et classe le problème HIGH. Le rapport contient `5.3.1`, donc la version installée est dans la plage affectée. La seule présence de cette version ne prouve pas que le chemin de parsing soit atteint.

## Installation et chaîne de dépendances observée

L’application n’importe pas directement `basic-ftp` et aucun appel applicatif direct à `Client.list()` n’a été trouvé dans les fichiers de l’image inspectés. La dépendance est apportée par `get-uri@8.0.1`, lui-même utilisé par `pac-proxy-agent@9.1.0`. `proxy-agent@8.0.2` sélectionne dynamiquement ce dernier pour les URI de proxy PAC. L’application importe `ProxyAgent` dans `lib/utils.ts` et l’utilise pour les téléchargements de configuration.

### Preuves numérotées

**P1 — versions et dépendance inverse.** Dans `juice-shop/node_modules/basic-ftp/package.json`, l’installation est `5.3.1`. Dans `juice-shop/node_modules/get-uri/package.json`, ligne 45, `basic-ftp` est une dépendance (`^5.3.1`); le paquet résolu dans l’image est bien `5.3.1`. `juice-shop/node_modules/pac-proxy-agent/package.json` déclare `get-uri@8.0.1`; `juice-shop/node_modules/proxy-agent/package.json` déclare `pac-proxy-agent@9.1.0`.

**P2 — l’appel vulnérable est indirect et conditionnel.** Dans `juice-shop/node_modules/get-uri/dist/ftp.js`, lignes 18 et 28, le module crée un `Client` puis se connecte. Ligne 38, il tente `client.lastMod(filepath)`; si cette opération échoue sans erreur « fichier introuvable », lignes 46–50 exécutent `client.list(dirname(filepath))` et recherchent le fichier demandé. C’est ce dernier appel qui atteint le parseur concerné par l’avis. Le chemin FTP de `get-uri` est la seule consommation trouvée de `basic-ftp` dans les dépendances inspectées.

**P3 — accès au gestionnaire FTP depuis PAC.** Dans `juice-shop/node_modules/proxy-agent/dist/index.js`, lignes 14–18 et 31–35, le schéma `pac+ftp` est associé à `PacProxyAgent`; lignes 62 et 76, l’agent obtient le proxy depuis `proxy-from-env`. Dans `juice-shop/node_modules/pac-proxy-agent/dist/index.js`, lignes 42–46, le module documente explicitement le PAC fourni par FTP; ligne 123, il appelle `getUri(this.uri, ...)` pour charger le fichier PAC. `get-uri` choisit alors son gestionnaire FTP et peut suivre le chemin P2.

**P4 — appels du téléchargeur applicatif.** Dans `lib/utils.ts`, lignes 11 et 23, l’application importe et instancie `ProxyAgent`; lignes 110–117, `downloadToFile(url, dest, ...)` transmet cet agent à `downloadData(url, ...)`. Les appels trouvés sont dans `data/datacreator.ts` lignes 341–347 (images de souvenirs), 379–390 (images de produits) et 413–420 (fichier de blueprint), ainsi que dans `lib/startup/customizeEasterEgg.ts` lignes 11–19 (overlay configuré). Ces valeurs proviennent des configurations chargées au démarrage; aucun appel depuis une route HTTP ni aucune URL FTP fournie directement par un utilisateur n’a été observé.

## Prérequis et exposition

| Élément du scénario | État dans les preuves inspectées |
|---|---|
| Version de `basic-ftp` dans la plage affectée | **Présent** : `5.3.1`, rapport initial et image. |
| Un chemin appelle `Client.list()` | **Présent indirectement** dans `get-uri/dist/ftp.js`, uniquement après l’échec de `lastMod` dans le chemin FTP. |
| Un proxy PAC utilise une URI `pac+ftp:` | **Inconnu** : le code prend en charge ce schéma, mais la configuration runtime du conteneur audité n’est pas établie par le rapport Trivy ni par le code applicatif. |
| Un serveur FTP contrôlé par un tiers fournit le listing malformé | **Inconnu / non observé**. Il faudrait que la configuration PAC emprunte le FTP et que ce serveur réponde au chemin `LIST` concerné. |
| L’utilisateur de Juice Shop contrôle directement l’URL ou le listing FTP | **Non observé**. Les URL passées au téléchargeur proviennent de configuration; la sélection effective du proxy dépend de l’environnement/configuration de déploiement. |
| Blocage de la boucle d’événements en situation réelle | **Non testé**; aucun test d’exploitation n’a été réalisé. |

La chaîne d’accès nécessite donc une configuration de déploiement spécifique : un proxy PAC fourni par FTP et un listing malveillant atteint dans le cas où `lastMod` ne fournit pas de date. Les appels applicatifs au téléchargeur sont associés à des données de configuration, principalement pendant l’initialisation, et ne suffisent pas à établir que cette chaîne est active dans l’image déployée.

## Conclusion provisoire

**Applicabilité conditionnelle, non démontrée pour l’instance.** Le paquet vulnérable est présent et l’image inclut un chemin indirect jusqu’à `Client.list()`. Ce chemin passe par le téléchargement d’un fichier PAC utilisant `pac+ftp`, puis par le repli `get-uri` de `lastMod` vers `list()`. L’utilisation effective d’une URL PAC FTP, les paramètres de proxy du conteneur au moment de l’audit et la maîtrise du serveur FTP ne sont pas établis. La détection Trivy est conservée; elle ne constitue pas à elle seule une preuve d’exposition ni d’exploitation.

## Références

- [Avis officiel GitHub GHSA-c475-qrg2-pj4r](https://github.com/patrickjuchli/basic-ftp/security/advisories/GHSA-c475-qrg2-pj4r) — CVE-2026-102990, versions affectées, conditions et version corrigée.
- [Correctif amont](https://github.com/patrickjuchli/basic-ftp/commit/d0d9e07c56e519587bb50532ac6eadbb0cb0cfe9) — modification du parseur Unix et des limites de répétition.
- [Release basic-ftp 6.2.1](https://github.com/patrickjuchli/basic-ftp/releases/tag/v6.2.1).

## Limites de l’inspection

L’examen a porté sur les métadonnées Trivy et les sources présentes dans l’image identifiée, sans exécuter les chemins applicatifs. Le rapport ne contient pas les variables d’environnement effectives du conteneur ni la configuration externe de proxy au moment de l’analyse. Les valeurs configurées par l’exploitant peuvent donc modifier l’accessibilité du chemin PAC. Aucun scan, changement applicatif ou test d’exploitation n’a été effectué.
