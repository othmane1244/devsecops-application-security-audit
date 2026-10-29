# Méthode d’audit des secrets

## Portée et état

Les contrôles prévus ci-dessous ont été exécutés le **2026-10-29**. Les résultats expurgés sont publiés dans le [rapport partageable](rapport-partageable.md); les JSON bruts et journaux restent dans un dossier privé hors dépôt.

Deux périmètres seront examinés séparément :

1. **Dépôt d’audit** : l’arborescence de travail du dépôt `audit-devsecops-work`, à partir de sa racine. Le contrôle porte sur les fichiers présents dans l’arborescence au moment de l’exécution, pas sur l’historique Git. `.git` et `reports` seront exclus : le premier contient l’historique et des données internes Git, le second les rapports de scans déjà produits. Les autres fichiers du worktree seront dans la portée, y compris les fichiers non suivis.
2. **Fichiers de l’application identifiée** : le contenu de `/juice-shop` dans l’image locale `bkimminich/juice-shop:v20.3.0` déjà auditée. Un conteneur temporaire a été créé à partir de l’identifiant d’image local vérifié, puis les fichiers ont été copiés sans démarrer le conteneur. Trivy `fs` a examiné cette copie. Cette portée couvre l’application livrée et ses dépendances sous `/juice-shop`; elle ne couvre pas les autres fichiers du système Debian, les couches supprimées de l’image ni l’état d’un runtime.

Le contrôle a confirmé l’ID local `sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27`, le tag `bkimminich/juice-shop:v20.3.0`, 24 couches et l’image Trivy locale **0.76.0**. L’écart avec l’identifiant `4060…` de l’export/rapport initial demeure documenté dans le [rapport partageable](rapport-partageable.md). Aucun pull n’a été autorisé et aucun conteneur Juice Shop n’a été démarré. Pour un contrôle ultérieur, refaire ces vérifications et arrêter si l’identité diffère.

## Capacités Trivy vérifiées

L’aide de `aquasec/trivy:0.76.0` a été consultée sans lancer de scan. Elle confirme pour `trivy fs` : `--scanners secret`, `--secret-config`, `--format json`, `--output`, `--skip-dirs`, `--skip-files`, `--disable-telemetry`, `--skip-version-check` et `--quiet`. `json` est un format disponible. L’image locale Trivy doit être exécutée avec `--pull=never` afin d’empêcher un téléchargement implicite. L’aide de Docker confirme aussi `docker create --pull=never` pour que l’étape de copie de fichiers ne récupère pas une image distante.

La commande sélectionne explicitement `--scanners secret`; elle n’active ni `vuln` ni les autres scanners. Les options `--skip-db-update` et `--skip-java-db-update` ne sont pas nécessaires pour le scanner de secrets. Aucun résultat brut ne doit être écrit dans le dépôt ou affiché dans le terminal.

## Exécution du 2026-10-29

Les deux commandes Trivy ont terminé avec le code **0**. Le scan du worktree a couvert le dépôt courant, hors `.git` et `reports`; il a émis **0 détection**. Le scan de `/juice-shop` a examiné **1 963 fichiers** et émis **5 détections** : trois `private-key` et deux `jwt-token`. Le détail expurgé et l’interprétation sont dans le [rapport partageable](rapport-partageable.md).

Le scan du dépôt s’est déroulé de **01:25:06.6657279 à 01:25:08.5693004 UTC**; celui des fichiers applicatifs de **01:28:16.7127862 à 01:28:57.6962735 UTC**. Les commandes ont utilisé `aquasec/trivy:0.76.0`, l’image locale Trivy n’a pas été tirée, et les deux sources ont été montées en lecture seule. Les bruts, journaux et fichiers copiés sont conservés dans un répertoire d’exécution `%LOCALAPPDATA%` avec ACL limitées au compte courant; ils ne sont pas dans Git.

## Préparation des chemins privés

Les commandes ont été exécutées depuis PowerShell, à la racine du dépôt. Les résultats bruts et l’extraction sont conservés sous `%LOCALAPPDATA%`, hors du dépôt, dans un répertoire d’exécution unique dont l’héritage ACL a été retiré et dont le seul compte autorisé est celui de l’audit. Ne pas partager ces fichiers : ils peuvent contenir des valeurs secrètes en clair.

```powershell
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path .).Path
$privateBase = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'JuiceShopAudit/secrets'))
$repoPrefix = $repoRoot.TrimEnd('\') + '\'
if ($privateBase.Equals($repoRoot, [StringComparison]::OrdinalIgnoreCase) -or
    $privateBase.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Le répertoire des résultats bruts est dans le dépôt; choisissez un emplacement hors Git.'
}
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N')
$runRoot = Join-Path $privateBase $runId
New-Item -ItemType Directory -Path $runRoot | Out-Null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $runRoot /inheritance:r
if ($LASTEXITCODE -ne 0) { throw 'Retrait de l’héritage ACL impossible.' }
icacls $runRoot /grant:r "${identity}:(OI)(CI)F"
if ($LASTEXITCODE -ne 0) { throw 'Attribution de l’ACL privée impossible.' }
$acl = Get-Acl -LiteralPath $runRoot
$otherAccounts = @($acl.Access | Where-Object { $_.IdentityReference.Value -ne $identity })
if ($otherAccounts.Count -ne 0) { throw 'ACL inattendue; aucun scan ne doit commencer.' }
$appFiles = Join-Path $runRoot 'juice-shop-files'
New-Item -ItemType Directory -Path $appFiles | Out-Null
```

Ne pas ajouter le dossier privé à Git, ne pas copier son contenu dans un ticket/chat et ne pas joindre les sorties brutes. Après traitement, conserver ou supprimer ces données selon la politique de conservation de l’audit, en gardant le rapport partageable expurgé.

## Commandes exécutées et reproductibles

### 1. Arborescence du dépôt d’audit

Cette commande scanne le worktree courant sauf `.git` et `reports`. Elle enregistre le JSON sensible dans le dossier privé et n’imprime pas le rapport dans la console.

```powershell
$repoRaw = Join-Path $runRoot 'repository.raw.json'
$repoLog = Join-Path $runRoot 'repository.trivy.log'
if (Test-Path -LiteralPath $repoRaw) { throw 'Le fichier brut existe déjà; choisissez un nouveau runId.' }
docker run --pull=never --rm `
    -v "${repoRoot}:/src:ro" `
    -v "${runRoot}:/out" `
    aquasec/trivy:0.76.0 fs `
    --scanners secret `
    --skip-dirs /src/.git --skip-dirs /src/reports `
    --format json --output /out/repository.raw.json `
    --quiet --disable-telemetry --skip-version-check /src *> $repoLog
if ($LASTEXITCODE -ne 0) { throw 'Trivy repository secret scan failed' }
```

La sortie mentionnée dans `$repoRaw` contient potentiellement les valeurs détectées; ne pas l’ouvrir dans un terminal partagé. Trivy `fs` examine ici le contenu actuel du worktree : ce n’est pas une recherche dans les commits antérieurs.

### 2. Fichiers de `/juice-shop` dans l’image locale

La valeur d’image utilisée doit être l’ID local confirmé juste avant l’extraction, et non une référence qui déclencherait un téléchargement. L’exemple ci-dessous fixe l’ID local enregistré pour cette cible. Si l’inspection ne renvoie pas ce même ID, arrêter et documenter l’écart avant tout scan.

```powershell
$imageId = 'sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27'
$imageTag = 'bkimminich/juice-shop:v20.3.0'
$observedId = docker image inspect --format '{{.Id}}' $imageTag
if ($LASTEXITCODE -ne 0 -or $observedId.Trim() -ne $imageId) {
    throw "L’image locale ne correspond pas à l’identifiant attendu; arrêt."
}

$extractName = "juice-shop-secret-extract-$([guid]::NewGuid().ToString('N'))"
$created = $false
try {
    $containerId = docker create --pull=never --name $extractName $imageId
    if ($LASTEXITCODE -ne 0) { throw 'Création du conteneur d’extraction impossible' }
    $created = $true

    # docker create prépare un conteneur arrêté; aucune commande applicative n’est démarrée.
    docker cp "${containerId}:/juice-shop/." $appFiles
    if ($LASTEXITCODE -ne 0) { throw 'Copie des fichiers /juice-shop impossible' }
}
finally {
    if ($created) { docker rm $containerId | Out-Null }
}

$appRaw = Join-Path $runRoot 'juice-shop-files.raw.json'
$appLog = Join-Path $runRoot 'application.trivy.log'
if (Test-Path -LiteralPath $appRaw) { throw 'Le fichier brut existe déjà; choisissez un nouveau runId.' }
docker run --pull=never --rm `
    -v "${appFiles}:/src:ro" `
    -v "${runRoot}:/out" `
    aquasec/trivy:0.76.0 fs `
    --scanners secret `
    --format json --output /out/juice-shop-files.raw.json `
    --quiet --disable-telemetry --skip-version-check /src *> $appLog
if ($LASTEXITCODE -ne 0) { throw 'Trivy application-files secret scan failed' }
```

Le conteneur d’extraction sert uniquement à lire les fichiers de l’image; le script n’appelle jamais `docker start` ou `docker run` sur Juice Shop. `docker run` exécute uniquement l’image Trivy, avec les fichiers sources montés en lecture seule. Les dossiers d’extraction et JSON bruts demeurent privés, hors Git.

## Interprétation des détections

Un résultat Trivy est un **secret potentiel** (correspondance à une règle), pas une preuve que la valeur est authentique, encore active ou acceptée par un service. Le rapport de synthèse attribuera une catégorie documentée :

- **Secret potentiel** : motif détecté; l’origine et le contexte sont à examiner.
- **Exemple pédagogique** : contexte de test, documentation ou valeur clairement factice étayant cette interprétation. Ne pas transformer une simple apparence en certitude.
- **Validité inconnue** : aucune vérification de fonctionnement n’est effectuée. La validité ne sera jamais testée auprès d’un service externe.

Ne jamais copier la valeur complète ni une portion qui permettrait de la reconstituer dans le rapport partageable. Masquer également les paramètres de requête, identifiants, chemins personnels et autres données sensibles du contexte.

## Format du rapport partageable

Le [rapport partageable de cette exécution](rapport-partageable.md) suit le format ci-dessous. Pour un contrôle ultérieur, le mettre à jour manuellement à partir des résultats expurgés, avec une ligne par détection et sans valeur brute :

| ID | Type de détection | Fichier et ligne | Contexte expurgé | Classement | Validité | Conclusion |
|---|---|---|---|---|---|---|
| S-001 | règle Trivy / catégorie | `chemin/relatif:ligne` | `clé de configuration : [masqué]` | secret potentiel / exemple pédagogique | inconnue | interprétation et preuve contextuelle, sans test externe |

Le rapport précise le périmètre scanné, la version de Trivy, la date UTC, les exclusions, le statut et les limites. Il ne contient ni JSON brut, ni valeur secrète, ni conclusion de validité obtenue par appel à un service.
