# Méthode d’audit des secrets

## Portée et état

Cette fiche prépare les contrôles; **aucun contrôle de secrets n’a été lancé**.

Deux périmètres seront examinés séparément :

1. **Dépôt d’audit** : l’arborescence de travail du dépôt `audit-devsecops-work`, à partir de sa racine. Le contrôle porte sur les fichiers présents dans l’arborescence au moment de l’exécution, pas sur l’historique Git. `.git` et `reports` seront exclus : le premier contient l’historique et des données internes Git, le second les rapports de scans déjà produits. Les autres fichiers du worktree seront dans la portée, y compris les fichiers non suivis.
2. **Fichiers de l’application identifiée** : le contenu de `/juice-shop` dans l’image locale `bkimminich/juice-shop:v20.3.0` déjà auditée. Un conteneur temporaire sera créé à partir de l’identifiant d’image local vérifié, puis les fichiers seront copiés sans démarrer le conteneur. Trivy `fs` examinera cette copie. Cette portée couvre l’application livrée et ses dépendances sous `/juice-shop`; elle ne couvre pas les autres fichiers du système Debian, les couches supprimées de l’image ni l’état d’un runtime.

Les identifiants documentés de l’image locale et de l’export du scan initial diffèrent (`cea5…` / `4060…`) malgré les 24 couches concordantes. Avant le futur contrôle, confirmer la cible locale avec `docker image inspect` et consigner l’identifiant utilisé. Le contrôle ne doit ni tirer une nouvelle image ni démarrer Juice Shop. Le moteur Docker doit être accessible et Trivy **0.76.0** doit être déjà présent localement.

## Capacités Trivy vérifiées

L’aide de `aquasec/trivy:0.76.0` a été consultée sans lancer de scan. Elle confirme pour `trivy fs` : `--scanners secret`, `--secret-config`, `--format json`, `--output`, `--skip-dirs`, `--skip-files`, `--disable-telemetry`, `--skip-version-check` et `--quiet`. `json` est un format disponible. L’image locale Trivy doit être exécutée avec `--pull=never` afin d’empêcher un téléchargement implicite. L’aide de Docker confirme aussi `docker create --pull=never` pour que l’étape de copie de fichiers ne récupère pas une image distante.

La commande sélectionne explicitement `--scanners secret`; elle n’active ni `vuln` ni les autres scanners. Les options `--skip-db-update` et `--skip-java-db-update` ne sont pas nécessaires pour le scanner de secrets. Aucun résultat brut ne doit être écrit dans le dépôt ou affiché dans le terminal.

## Préparation des chemins privés

Les exemples suivants sont à lancer ultérieurement depuis PowerShell, à la racine du dépôt. Les résultats bruts et l’extraction restent sous `%LOCALAPPDATA%`, hors du dépôt. Avant le scan, vérifier que le chemin résolu n’est pas à l’intérieur de la racine Git et que l’emplacement n’est ni synchronisé ni partagé. Restreindre ses ACL à l’utilisateur chargé de l’audit; ces fichiers peuvent contenir des valeurs secrètes en clair.

```powershell
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path .).Path
$privateRoot = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'JuiceShopAudit/secrets'))
$repoPrefix = $repoRoot.TrimEnd('\') + '\'
if ($privateRoot.Equals($repoRoot, [StringComparison]::OrdinalIgnoreCase) -or
    $privateRoot.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Le répertoire des résultats bruts est dans le dépôt; choisissez un emplacement hors Git.'
}
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N')
$appFiles = Join-Path $privateRoot "juice-shop-files-$runId"
if (Test-Path -LiteralPath $appFiles) { throw 'Le dossier d’extraction existe déjà; choisissez un nouveau runId.' }
New-Item -ItemType Directory -Force -Path $privateRoot, $appFiles | Out-Null
```

Ne pas ajouter le dossier privé à Git, ne pas copier son contenu dans un ticket/chat et ne pas joindre les sorties brutes. Après traitement, conserver ou supprimer ces données selon la politique de conservation de l’audit, en gardant le rapport partageable expurgé.

## Commandes reproductibles — à exécuter lors d’une étape ultérieure

### 1. Arborescence du dépôt d’audit

Cette commande scanne le worktree courant sauf `.git` et `reports`. Elle enregistre le JSON sensible dans le dossier privé et n’imprime pas le rapport dans la console.

```powershell
$repoRawName = "repository-$runId.raw.json"
$repoRaw = Join-Path $privateRoot $repoRawName
if (Test-Path -LiteralPath $repoRaw) { throw 'Le fichier brut existe déjà; choisissez un nouveau runId.' }
docker run --pull=never --rm `
    -v "${repoRoot}:/src:ro" `
    -v "${privateRoot}:/out" `
    aquasec/trivy:0.76.0 fs `
    --scanners secret `
    --skip-dirs /src/.git --skip-dirs /src/reports `
    --format json --output "/out/$repoRawName" `
    --quiet --disable-telemetry --skip-version-check /src
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

$appRawName = "juice-shop-files-$runId.raw.json"
$appRaw = Join-Path $privateRoot $appRawName
if (Test-Path -LiteralPath $appRaw) { throw 'Le fichier brut existe déjà; choisissez un nouveau runId.' }
docker run --pull=never --rm `
    -v "${appFiles}:/src:ro" `
    -v "${privateRoot}:/out" `
    aquasec/trivy:0.76.0 fs `
    --scanners secret `
    --format json --output "/out/$appRawName" `
    --quiet --disable-telemetry --skip-version-check /src
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

Après un contrôle ultérieur, préparer `docs/secrets/rapport-partageable.md` manuellement ou à partir des résultats expurgés. Garder une ligne par détection, sans valeur brute :

| ID | Type de détection | Fichier et ligne | Contexte expurgé | Classement | Validité | Conclusion |
|---|---|---|---|---|---|---|
| S-001 | règle Trivy / catégorie | `chemin/relatif:ligne` | `clé de configuration : [masqué]` | secret potentiel / exemple pédagogique | inconnue | interprétation et preuve contextuelle, sans test externe |

Le rapport précisera le périmètre scanné, la version de Trivy, la date UTC, les exclusions, le statut et les limites. Il ne contiendra ni JSON brut, ni valeur secrète, ni conclusion de validité obtenue par appel à un service.
