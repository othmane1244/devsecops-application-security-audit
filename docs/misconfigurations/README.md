# Préparation du contrôle des mauvaises configurations

**Statut : préparation et inventaire seulement. Aucun scan Trivy n’a été exécuté dans cette étape.**

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

Trivy **0.76.0** a été vérifié depuis l’image Docker locale, sans téléchargement (`docker run --pull=never ... --version`). L’aide de `trivy config --help` et `trivy fs --help` confirme notamment les options `--misconfig-scanners`, `--skip-check-update`, `--format`, `--output`, `--skip-dirs`, `--skip-files`, `--quiet`, `--disable-telemetry` et `--skip-version-check`. Aucun scan n’a été lancé.

La documentation Trivy 0.76 répertorie les fichiers Dockerfile/Containerfile, Terraform et Kubernetes parmi les formats IaC pris en charge. Compose n’est pas un scanner natif déclaré par cette version; les deux fichiers Compose seront inventoriés, mais ne seront pas présentés comme couverts par la commande ci-dessous. Les fichiers YAML génériques de Juice Shop ne bénéficient pas automatiquement de contrôles intégrés : l’activation d’un scanner YAML ou de règles personnalisées demanderait une méthode distincte. Les workflows GitHub Actions ne figurent pas parmi les types de scanner misconfiguration proposés par cette version.

La commande restreint les types de scanner aux formats rencontrés et exclut le dépôt Git et les dépendances vendoriées lorsqu’elles existent. `--skip-check-update` évite de récupérer un nouveau jeu de règles pendant l’exécution; selon le cache local, Trivy utilisera ses règles intégrées ou déjà présentes. La disponibilité et l’âge de ce jeu de règles devront être consignés au moment du contrôle.

Références : [couverture IaC Trivy 0.76](https://trivy.dev/docs/v0.76/guide/coverage/iac/), [contrôles intégrés Trivy 0.76](https://trivy.dev/docs/v0.76/guide/scanner/misconfiguration/check/builtin/), [limitation Compose suivie par le projet Trivy](https://github.com/aquasecurity/trivy/issues/8729).

## Exclusions et limites

- Pas de scan de vulnérabilités, de secrets, de dépendances ni de code applicatif.
- Pas de lecture des valeurs des configurations lors de l’inventaire; les fichiers bruts et résultats peuvent contenir des valeurs sensibles.
- Pas de démarrage de Juice Shop, de déploiement Terraform, Kubernetes ou Compose, ni de correction.
- Pas d’inspection de l’état réel d’un cluster, d’un compte cloud, d’un conteneur en exécution ou d’une plateforme CI.
- Compose, workflows GitHub Actions et YAML générique ne seront pas couverts par les commandes Trivy ci-dessous. L’inventaire ne vaut pas contrôle de ces formats.
- Trivy ne prouve pas à lui seul qu’une configuration est déployée, atteignable ou exploitable. Ses résultats devront être examinés selon le contexte et les preuves disponibles.
- L’écart entre l’identité de configuration de l’image locale et celle du rapport initial limite l’attribution des résultats à l’image auditée.

## Commandes prévues (PowerShell)

Ces commandes sont préparées pour une exécution ultérieure. **Elles n’ont pas été exécutées dans cette étape.** Elles utilisent l’image Trivy locale par digest, interdisent son téléchargement et montent les sources en lecture seule. Les sorties restent hors du dépôt, dans un répertoire local privé; ne pas les ajouter à Git.

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

Avant exécution, vérifier que `$repoRoot` désigne bien ce worktree, que `$appRoot` est l’arbre extrait de l’image indiquée, que l’image Trivy locale correspond au digest attendu et que l’accès au moteur Docker ne télécharge aucune autre image. Le répertoire de sortie est protégé par les ACL Windows ci-dessus; ses résultats JSON et journaux devront rester hors Git. Les commandes utilisent des répertoires montés en lecture seule et ne démarrent pas Juice Shop.
