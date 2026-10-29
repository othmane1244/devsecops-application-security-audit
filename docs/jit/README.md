# Préparer une intégration Jit

**État au 29 octobre 2026 : étude documentaire seulement.** Aucun compte Jit ou GitHub n’a été connecté, aucune application GitHub installée, aucun paramètre changé, aucune analyse lancée et aucune correction proposée ou appliquée. Aucun secret ni résultat brut n’a été transmis à Jit.

## Rôle de Jit et complémentarité avec Trivy

Jit orchestre plusieurs contrôles de sécurité dans des plans, centralise leurs résultats et les relie au flux GitHub (scans de dépôts/PR, checks et recommandations). Il peut ainsi fournir une surveillance continue et un backlog unifié. La documentation actuelle cite notamment Semgrep pour SAST, OSV-Scanner pour SCA, Gitleaks et TruffleHog pour les secrets, Trivy pour les Dockerfiles et KICS pour l’IaC; d’autres plans ajoutent des contrôles GitHub, Kubernetes, cloud et DAST.

Trivy a déjà servi dans cet audit pour analyser l’image Juice Shop, les dépendances, les configurations, les secrets, et produire un SBOM. Jit ne remplacerait pas ces éléments de preuve : il les compléterait surtout par des analyses de code et de dépendances dans les PR, une vue centralisée, et certains contrôles de configuration du dépôt GitHub lui-même. Les scanners, leurs versions, règles, périmètres et formats diffèrent; un résultat Jit ne doit pas être fusionné mécaniquement avec les rapports Trivy. Le scanner Jit documenté pour les conteneurs couvre les Dockerfiles; cela ne démontre pas qu’un plan donné réanalyse une image Docker locale ou ses couches.

## Cibles de cet audit

Le dépôt `audit-devsecops-work` est principalement composé de documentation d’audit et de rapports JSON/SBOM. L’inventaire du worktree n’a trouvé ni code source Juice Shop, ni manifestes `package*.json`/lockfiles, Dockerfile, fichiers Terraform ou workflows GitHub Actions. Il contient des données d’audit et des rapports bruts qui ne doivent pas être transmis.

| Cible | Contrôles qui auraient du sens | Adéquation et limites |
| --- | --- | --- |
| Dépôt d’audit actuel | Contrôle de la posture GitHub (ex. protection des branches), si l’objectif inclut les paramètres du dépôt et si les permissions sont acceptées. | SAST et SCA applicatifs auraient peu de matière; les rapports et documents ne remplacent pas les sources ou manifestes du produit. Ne pas sélectionner la détection de secrets ou l’ingestion des rapports tant que l’exclusion et le traitement des fichiers ne sont pas confirmés. Jit peut aussi écrire ses workflows/configurations dans un dépôt choisi pendant l’intégration. |
| Code Juice Shop correspondant à l’image `v20.3.0` | SAST, SCA, Dockerfile, IaC/Kubernetes si présents, et éventuellement contrôles GitHub sur son dépôt autorisé. | Cible adaptée aux contrôles du code. Le code extrait sous `/juice-shop` n’est pas un dépôt GitHub connecté; Jit ne peut pas scanner ce chemin local via l’intégration documentée. |
| Image locale et état runtime | Scan d’image / DAST seulement si le plan et les intégrations le prennent effectivement en charge, avec une cible autorisée. | Aucun scan d’image locale ni état runtime par Jit n’est confirmé par les pages publiques consultées. DAST suppose une application déployée et une URL accessible; cette étape n’est pas proposée ici. |

**Cible proposée pour une phase ultérieure :** un dépôt Juice Shop autorisé et contrôlé par notre organisation, épinglé au tag/version `v20.3.0` de l’application auditée. Il pourrait s’agir d’un miroir ou d’un fork déjà autorisé si un tel dépôt existe. La seule URL amont `juice-shop/juice-shop` ne suffit pas : l’application Jit doit être installée sur l’organisation et le dépôt doit être accessible avec son autorisation. Aucun dépôt ne sera créé ni aucun code importé dans cette préparation.

## Capacités et conditions d’accès relevées

| Capacité Jit documentée | Contrôle / outil mentionné | Conditions et limites |
| --- | --- | --- |
| Analyse applicative et retours continus dans les PR | SAST (Semgrep, Gosec pour Go), SCA (OSV-Scanner), détection de secrets (Gitleaks, TruffleHog) | L’intégration GitHub demande d’installer l’application Jit et de choisir les dépôts. Le guide d’intégration indique que SCA, SAST et secrets sont activés et que le premier scan démarre après l’installation. Ne pas connecter avant d’avoir résolu l’exclusion de données sensibles et la désactivation préalable des contrôles non souhaités. |
| Dockerfile et IaC | Trivy pour Dockerfile; KICS pour Terraform, Serverless, Pulumi, CloudFormation et AWS CDK | Portée fichier/configuration; ne pas assimiler à l’analyse Trivy de l’image locale et de ses paquets Debian/Node. |
| Contrôles du dépôt/organisation GitHub | GitHub Security Plan : Legitify, Chain Bench et vérifications Jit pour MFA/protection des branches | Les contrôles CI/CD GitHub sont annoncés comme quotidiens et dépendants du plan. La documentation du GitHub Security Plan indique qu’un PAT est nécessaire pour plusieurs contrôles; sans PAT, seul l’élément de configuration souhaitée de protection des branches est indiqué comme disponible. Vérifier l’offre réelle du tenant avant toute installation. |
| Scans d’infrastructure cloud | CSPM/Prowler et autres contrôles cloud | Exigent une intégration et des droits sur le compte AWS/GCP/Azure; hors périmètre de cette préparation. |
| DAST Web/API | ZAP dans les plans qui l’incluent | Nécessite une cible déployée/accessible. Le scan déclenché par déploiement est indiqué pour les déploiements via GitHub Actions et nécessite également l’intégration Slack, selon la documentation consultée. Aucun service ne sera démarré pour cette intégration. |

La documentation décrit l’exécution des scans au moyen de GitHub Actions dans l’environnement GitHub du client, afin que le code n’ait pas à être récupéré dans l’environnement Jit. Cela ne signifie pas qu’aucune donnée ne sort de GitHub : l’intégration présente les constats dans la plateforme Jit et ses conditions juridiques autorisent le traitement de contenu pour fournir le service. Les données et sous-traitants doivent donc être évalués avant connexion.

## Permissions GitHub à examiner avant toute autorisation

La table ci-dessous reproduit les permissions réclamées par la documentation d’intégration Jit au moment de la consultation. La demande affichée par GitHub lors d’une installation future doit être comparée à cette liste; les permissions réelles peuvent évoluer.

| Permission de l’application GitHub Jit | Accès documenté | Usage décrit par Jit |
| --- | --- | --- |
| Administration, issues, métadonnées | Lecture | Événements de création/suppression et métadonnées de dépôt. |
| Actions, checks, pull requests, workflows | Lecture/écriture | Lancer des workflows, créer/mettre à jour les checks et PR, modifier les workflows. |
| Contenu des dépôts | Lecture/écriture | Lire le code pour l’analyse et ouvrir des PR de remédiation. |
| Membres | Lecture | Lister et associer équipes et membres. |
| Déploiements | Lecture/écriture (présenté comme fonctionnalité future dans ce guide) | Contrôles de sécurité sur de nouveaux déploiements et blocage éventuel. Confirmer si cette permission est encore demandée. |

> Le plan GitHub Security documente en plus un **Personal Access Token** avec les scopes `repo`, `read:repo_hook`, `read:org`, `read:enterprise` et `read:packages` pour plusieurs vérifications d’organisation. Ces droits sont distincts des permissions de l’application GitHub. Nous n’en avons créé ni fourni aucun.

Les permissions en écriture sont importantes même si le premier objectif est l’observation : les workflows, checks et PR peuvent être modifiés. La configuration Jit est également stockée dans un dépôt choisi lors de l’onboarding. Une installation ne doit pas être approuvée sans revue des permissions actuelles, des changements proposés, du dépôt de configuration et de la portée exacte des dépôts sélectionnés. Ne pas sélectionner « tous les dépôts » par défaut.

## Données, secrets et résultats

Les pages officielles consultées indiquent ou impliquent les catégories suivantes :

- Le GitHub App peut lire le contenu des dépôts autorisés, les workflows/actions, les métadonnées, issues/PR/checks et, selon les permissions, des informations sur les membres et déploiements.
- Les constats, identifiants de dépôt/branche/commit, checks/PR et données de compte sont nécessaires à l’expérience de backlog et aux retours dans GitHub. Les pages publiques ne précisent pas complètement si les extraits de code, journaux détaillés ou rapports bruts des scanners sont conservés, ni leurs durées de rétention.
- La politique de confidentialité indique la collecte de données de compte et d’utilisation, dont nom, email, adresse IP, identifiants/appareil et journaux d’utilisation. La liste officielle de sous-traitants consultée comprend notamment des prestataires d’hébergement, base de données, analytics et authentification, avec des traitements indiqués aux États-Unis et en Israël.
- Les conditions d’utilisation définissent le contenu client comme incluant les fichiers, données et code source transmis ou accessibles dans le cadre du service. Elles donnent à Jit une licence pour traiter/héberger ce contenu et indiquent qu’il peut être partagé avec des modèles IA tiers hébergés notamment sur AWS Bedrock, sans entraînement sur ce contenu sans consentement écrit préalable. Ce périmètre juridique est plus large que la seule affirmation technique selon laquelle le code n’est pas rapatrié dans l’environnement Jit.

**Règle pour ce projet :** ne pas téléverser les JSON Trivy, SBOM bruts, rapports de secrets, journaux, secrets de configuration ou valeurs de secrets à Jit. Ne pas activer la détection de secrets sur les dépôts tant que son comportement d’exclusion, l’affichage des valeurs, la rétention et le flux vers la plateforme n’ont pas été confirmés. Le guide d’intégration annonce l’activation initiale de la détection de secrets; si elle ne peut pas être désactivée avant le premier scan, ne pas procéder avec un dépôt pouvant contenir des secrets. Les pages publiques ne permettent pas de garantir que le service ne transmettrait jamais d’extraits ou de résultats sensibles : demander les détails de traitement, rétention, région et DPA avant toute autorisation.

## Procédure proposée pour une intégration ultérieure

Cette procédure est un plan, pas une action réalisée.

1. Confirmer le dépôt cible autorisé et son contenu. Pour du code applicatif, préférer un dépôt Juice Shop contrôlé par l’organisation, à la version `v20.3.0`; ne pas utiliser le dépôt d’audit pour remplacer le code source manquant.
2. Avant d’ouvrir l’accès, examiner les conditions, DPA, politique de rétention, régions de traitement, sous-traitants, éventuel traitement IA et procédure de suppression. Demander au fournisseur ce qui est envoyé au plan de contrôle, y compris extraits de code, valeurs détectées, logs et JSON de rapports.
3. Examiner les permissions exactes de l’application GitHub et des éventuels PAT; vérifier l’accès uniquement au dépôt ciblé. Refuser une installation si elle exige un scope plus large que celui approuvé.
4. Vérifier si le premier scan automatique peut être empêché pendant la configuration et si la détection de secrets peut être désactivée avant ce scan. Si ce n’est pas possible, ne pas relier un dépôt contenant secrets, rapports bruts ou données sensibles.
5. Choisir un dépôt de configuration Jit existant et approuvé; ne pas choisir tous les dépôts de l’organisation. Examiner toute écriture de workflow ou configuration avant de la fusionner.
6. Si les conditions sont acceptées et l’autorisation accordée séparément, commencer par SAST, SCA, Dockerfile/IaC et les contrôles GitHub adaptés à la cible. Laisser désactivés DAST, accès cloud, remédiation automatique et détection de secrets tant que leurs prérequis et flux de données ne sont pas validés.
7. Comparer un résumé Jit à nos conclusions documentées sans importer de JSON Trivy ni assimiler des alertes de scanners différents. Consigner versions, règles, commits analysés, exclusions et limites.

## Contrôles envisagés et résultats attendus

| Cible future | Contrôles envisagés | Résultat attendu |
| --- | --- | --- |
| Dépôt Juice Shop autorisé, tag `v20.3.0` | SAST Semgrep; SCA OSV-Scanner; scan Dockerfile; scan IaC si les fichiers sont présents et le plan le permet. | Nouveaux constats de code/dépendances/infrastructure reliés au dépôt et aux PR. Ils seront triés puis comparés qualitativement aux conclusions Trivy; aucune égalité de règles ou de compte n’est attendue. |
| Même dépôt, seulement après validation des données | Détection de secrets en mode contrôlé, si exclusions et masque des valeurs sont vérifiés. | Indicateurs expurgés uniquement; aucune valeur de secret ni résultat JSON brut dans notre documentation ou un ticket partagé. Si ce comportement ne peut être garanti, ce contrôle reste désactivé. |
| Dépôt d’audit, si les réglages GitHub sont explicitement dans le périmètre | Vérification de protection de branches et, uniquement après accord sur les scopes, les contrôles d’organisation/MFA. | État des paramètres GitHub, distinct des résultats Trivy sur le code Juice Shop. La présence des rapports dans le dépôt rend SAST/SCA/secrets peu adaptés à cette cible. |
| Application déployée (hors cette étape) | DAST seulement avec approbation, fenêtre et URL autorisée. | Constat dynamique lié à une version et à un environnement identifiés; aucun lancement de l’application n’est prévu dans cette intégration documentaire. |

## Limites et coûts

- Les capacités dépendent du Security Plan, du type de compte et des intégrations activées; les pages publiques et le tenant peuvent diverger. Le plan GitHub Security peut exiger un PAT avec des scopes d’organisation larges.
- Le scan de PR et les vérifications périodiques utilisent les minutes GitHub Actions. La documentation Jit liste des quotas GitHub mensuels différents selon le type de compte et avertit que les jobs Jit et les autres pipelines partagent ce quota; un plan peut arrêter ses scans lorsque la limite est atteinte.
- Les informations publiques de prix ne sont pas cohérentes : la fiche GitHub Marketplace affiche un niveau Starter à 0 $ pour un développeur, tandis que la page Jit SAST affiche les trois premiers développeurs gratuits. Le coût au-delà, l’accès aux plans nécessaires et les éventuels frais/limites de scans doivent être confirmés dans une offre actuelle avant l’intégration. Aucun prix n’est engagé par ce document.
- Les pages publiques consultées ne suffisent pas à confirmer la résidence des résultats, les durées de rétention ou le transfert de valeurs détectées. La documentation détaillée de sécurité/DPA est annoncée dans le Trust Portal et peut nécessiter un accès fournisseur.
- L’analyse des sources d’un dépôt n’est pas un scan de l’image locale ni une preuve de déploiement. Aucun plan Jit ne remplace la validation manuelle des prérequis ou l’analyse Trivy déjà conservée.

## Sources officielles consultées

Pages consultées le 29 octobre 2026; les permissions, capacités, plans et conditions peuvent évoluer.

- [Intégrer Jit à GitHub — étapes, dépôts, scan initial et permissions](https://docs.jit.io/docs/integrating-with-github)
- [Résumé des scanners Jit et outils OSS associés](https://docs.jit.io/docs/security-tools)
- [GitHub Security Plan — contrôles et permissions PAT](https://docs.jit.io/docs/github-security-plan)
- [Détection des mauvaises configurations CI/CD](https://docs.jit.io/docs/github-misconfiguration-detection)
- [Sécurité IaC et scans runtime](https://docs.jit.io/docs/iac-security-scanners)
- [Scanners de conteneurs et Dockerfile](https://docs.jit.io/docs/container-security-scanners)
- [Minutes GitHub Actions utilisées par Jit](https://docs.jit.io/docs/add-minutes-to-github-actions)
- [Scan déclenché par déploiement et prérequis](https://docs.jit.io/docs/deployment-based-scanning)
- [Conditions d’utilisation Jit — définition et traitement du contenu client](https://www.jit.io/legal/terms/terms-of-use)
- [Politique de confidentialité Jit](https://www.jit.io/legal/terms/privacy-policy)
- [Sous-traitants Jit](https://www.jit.io/legal/terms/sub-processors)
- [Trust Portal et documents sécurité/DPA](https://www.jit.io/legal/terms)
- [Jit Security sur GitHub Marketplace — prix public affiché](https://github.com/marketplace/jit-security)
- [Page Jit SAST — offre gratuite annoncée](https://www.jit.io/lp/sast)
