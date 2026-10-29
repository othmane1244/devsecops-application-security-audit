# Préparation du contrôle des mauvaises configurations

**Statut : contrôles exécutés le 2026-10-29 UTC.** Les résultats détaillés et les limites figurent dans le [rapport partageable](rapport-partageable.md). Aucun démarrage d’application ni déploiement n’a été effectué.

## Objectif et périmètres

Le contrôle prévu recherchera les mauvaises configurations dans les fichiers d’infrastructure présents dans deux périmètres distincts :

1. **Laboratoire** : le worktree de ce dépôt, sur la branche `docs/project-readme`.
2. **Application** : les fichiers `/juice-shop` extraits de l’image locale `bkimminich/juice-shop:v20.3.0`, identifiée localement par `sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27` (Linux/amd64, 24 couches).

L’identité de configuration consignée dans le rapport initial est différente (`sha256:40606cfb23b8937b60c1cab5a5980362e0a372223c1f86f6c3e68c1b003a823c`), malgré les 24 couches communes. Le périmètre applicatif ci-dessus décrit donc l’arbre de l’image locale identifiée, sans affirmer qu’il s’agit à l’identique de l’image du rapport initial.

La présence d’un fichier décrit un artefact disponible, pas son utilisation. En particulier, aucun fichier d’infrastructure de ce dépôt ni ceux livrés avec Juice Shop ne prouvent qu’un service, un conteneur, un cluster ou une infrastructure Terraform les utilise actuellement.

## Inventaire par noms de fichiers

Inventaire fait à partir des chemins, sans afficher ni analyser les valeurs des fichiers.

| Périmètre | Fichiers trouvés | Ce que cela établit |
| --- | --- | --- |
| Dépôt du laboratoire | Aucun Dockerfile, fichier Compose, fichier Terraform, manifeste Kubernetes ou workflow sous `.github/workflows/` repéré. Les instructions Docker du README sont de la documentation. | Aucun de ces fichiers de configuration n’a été trouvé dans le worktree examiné. Cela ne décrit pas d’éventuels systèmes externes au dépôt. |
| `/juice-shop` de l’image locale | `infrastructure/Dockerfile`; `infrastructure/docker-compose.yml`, `infrastructure/docker-compose.test.yml`; `infrastructure/terraform/main.tf`, `networking.tf`, `outputs.tf`, `variables.tf`; exemples `data/static/codefixes/iacLeakedKeyChallenge_1.tf`, `_2.tf`, `_3_correct.tf`. | Sources d’infrastructure livrées avec l’application, dont des exemples de challenge/correction. Leur présence ne signifie pas qu’elles sont déployées. |
| `/juice-shop` de l’image locale | Aucun fichier candidat Kubernetes ni workflow GitHub Actions trouvé. | Aucun de ces fichiers n’a été repéré dans l’arbre examiné. |
| `/juice-shop` de l’image locale | 77 fichiers `.yml`/`.yaml` au total, incluant les deux fichiers Compose ci-dessus. Les autres comprennent notamment `.codeclimate.yml`, `crowdin.yaml`, `.dependabot/config.yml`, des fichiers de `config/`, `ftp/` et `data/static/`. | L’extension YAML seule ne permet pas de conclure qu’il s’agit d’un manifeste de déploiement; plusieurs fichiers sont des réglages d’application, de test, d’outil ou des données de challenge. |

## Outil et capacités vérifiés

Trivy **0.76.0** a été vérifié depuis l’image Docker locale, sans téléchargement (`docker run --pull=never ... --version`). Son image utilisée porte le digest `sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222`. L’aide de `trivy config --help` et `trivy fs --help` confirme notamment les options `--misconfig-scanners`, `--skip-check-update`, `--format`, `--output`, `--skip-dirs`, `--skip-files`, `--quiet`, `--disable-telemetry` et `--skip-version-check`.

La documentation Trivy 0.76 répertorie les fichiers Dockerfile/Containerfile, Terraform et Kubernetes parmi les formats IaC pris en charge. Compose n’est pas un scanner natif déclaré par cette version; les deux fichiers Compose seront inventoriés, mais ne seront pas présentés comme couverts par la commande ci-dessous. Les fichiers YAML génériques de Juice Shop ne bénéficient pas automatiquement de contrôles intégrés : l’activation d’un scanner YAML ou de règles personnalisées demanderait une méthode distincte. Les workflows GitHub Actions ne figurent pas parmi les types de scanner misconfiguration proposés par cette version.

La commande restreint les types de scanner aux formats rencontrés et exclut le dépôt Git et les dépendances vendoriées lorsqu’elles existent. `--skip-check-update` évite de récupérer un nouveau jeu de règles pendant l’exécution. La sortie JSON ne donne ni l’identifiant ni l’âge du bundle effectivement utilisé; l’absence de récupération a été demandée, mais la provenance cache/bundle intégré ne peut pas être établie pour ces exécutions.

Références : [couverture IaC Trivy 0.76](https://trivy.dev/docs/v0.76/guide/coverage/iac/), [contrôles intégrés Trivy 0.76](https://trivy.dev/docs/v0.76/guide/scanner/misconfiguration/check/builtin/), [limitation Compose suivie par le projet Trivy](https://github.com/aquasecurity/trivy/issues/8729).

## Exclusions et limites

- Pas de scan de vulnérabilités, de secrets, de dépendances ni de code applicatif.
- Pas de lecture des valeurs des configurations lors de l’inventaire; les fichiers bruts et résultats peuvent contenir des valeurs sensibles.
- Pas de démarrage de Juice Shop, de déploiement Terraform, Kubernetes ou Compose, ni de correction.
- Pas d’inspection de l’état réel d’un cluster, d’un compte cloud, d’un conteneur en exécution ou d’une plateforme CI.
- Compose, workflows GitHub Actions et YAML générique ne seront pas couverts par les commandes Trivy ci-dessous. L’inventaire ne vaut pas contrôle de ces formats.
- Trivy ne prouve pas à lui seul qu’une configuration est déployée, atteignable ou exploitable. Ses résultats devront être examinés selon le contexte et les preuves disponibles.
- L’écart entre l’identité de configuration de l’image locale et celle du rapport initial limite l’attribution des résultats à l’image auditée.

## Commandes exécutées (PowerShell)

Les deux commandes ci-dessous ont été exécutées avec l’image Trivy locale par digest et `--pull=never`. Les sources étaient montées en lecture seule. Les JSON et journaux bruts sont conservés hors du dépôt, dans `%LOCALAPPDATA%\JuiceShopAudit\misconfigurations\20261029T092643Z\`; les ACL ont été vérifiées et accordent le contrôle complet à l’utilisateur courant seulement. Les sorties brutes ne sont pas publiées.

```powershell
$repoRoot = (Get-Location).Path
$appRoot = Join-Path $env:LOCALAPPDATA 'JuiceShopAudit\secrets\20261029T012444Z-a81e3aef91924c399538ba4b5cf7dd08\juice-shop-files'
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$outDir = Join-Path $env:LOCALAPPDATA "JuiceShopAudit\misconfigurations\$runId"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
icacls $outDir /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null

$trivy = 'aquasec/trivy@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222'
docker image inspect $trivy --format '{{.Id}}'
docker run --pull=never --rm `
  --mount "type=bind,source=$repoRoot,target=/scan,readonly" `
  --mount "type=bind,source=$outDir,target=/results" `
  $trivy config --misconfig-scanners dockerfile,terraform,kubernetes `
  --skip-check-update --disable-telemetry --skip-version-check --quiet `
  --skip-dirs /scan/.git,/scan/node_modules `
  --format json --output /results/laboratoire.json /scan

docker run --pull=never --rm `
  --mount "type=bind,source=$appRoot,target=/scan,readonly" `
  --mount "type=bind,source=$outDir,target=/results" `
  $trivy config --misconfig-scanners dockerfile,terraform,kubernetes `
  --skip-check-update --disable-telemetry --skip-version-check --quiet `
  --skip-dirs /scan/.git,/scan/node_modules `
  --format json --output /results/juice-shop-image-locale.json /scan
```

Les variables ont été résolues vers ce worktree et vers l’arbre privé `juice-shop-files` extrait de `/juice-shop`. Cet arbre existe encore et contient 1 963 fichiers. Son rapport d’extraction documente un conteneur créé avec `docker create --pull=never`, vérifié arrêté, puis utilisé pour copier `/juice-shop`; il n’a jamais été démarré. L’image actuellement présente est `bkimminich/juice-shop:v20.3.0`, ID local et `RepoDigest` `sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27`, Linux/amd64, 24 couches. L’écart avec le digest de configuration du rapport initial reste une limite d’attribution.

Les deux commandes principales ont terminé avec le code **0**. Les rapports sont valides, créés respectivement à `2026-10-29T09:28:29.786484845Z` et `2026-10-29T09:29:06.097405743Z`, avec `Trivy.Version=0.76.0`. Le contrôle du laboratoire n’a retourné aucune cible de résultat : l’inventaire n’avait trouvé aucun Dockerfile, Terraform ou Kubernetes dans le worktree. Il s’agit de **l’absence de fichier pris en charge**, pas d’un scan de fichiers pris en charge sans détection. Le contrôle Juice Shop a retourné 66 constats; leur ventilation et leur statut sont dans le rapport partageable.

Le mode `--quiet` des commandes principales a produit des journaux vides; il ne permet pas à lui seul de confirmer les diagnostics de parsing. Une exécution diagnostique supplémentaire de l’arbre applicatif avec `--debug` a créé un JSON valide avec les mêmes 66 constats, mais s’est terminée avec le code **1**. Son journal privé ne contient aucun marqueur `error`, `parse` ou `failed`; la cause du code 1 n’est pas établie. La sortie Trivy contient des cibles avec constats pour `infrastructure/Dockerfile`, `infrastructure/terraform/main.tf`, `networking.tf` et les trois fichiers de challenge. Elle ne fournit pas une liste exhaustive des fichiers simplement analysés; l’absence de cible pour d’autres fichiers Terraform ne prouve donc ni leur absence de parsing ni l’absence de constat. Le parsing complet reste une limite ouverte.

Le rapport JSON n’identifie pas le bundle de règles. `--skip-check-update` a empêché de demander une mise à jour, mais l’âge et la source des règles chargées (cache ou bundle intégré) restent inconnus. Les informations de synthèse, les codes de sortie, les limites et les empreintes des rapports bruts sont consignés dans le [rapport partageable](rapport-partageable.md).
