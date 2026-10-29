# Rapport partageable — contrôle Trivy des secrets

## Résumé

Contrôles réalisés le **2026-10-29 UTC** avec Trivy **0.76.0**, depuis l’image Docker locale `aquasec/trivy:0.76.0` (`sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222`). Chaque commande a utilisé exclusivement `--scanners secret`, `--pull=never`, `--quiet`, `--disable-telemetry` et `--skip-version-check`. Les codes de sortie des deux scans sont **0**. Aucune valeur détectée n’est reproduite ici; aucun identifiant n’a été vérifié auprès d’un service.

| Périmètre | Début UTC | Fin UTC | Fichiers | Résultat |
|---|---|---|---:|---:|
| Worktree du dépôt `audit-devsecops-work` | 01:25:06.6657279 | 01:25:08.5693004 | Worktree présent | 0 détection |
| Fichiers `/juice-shop` de l’image locale | 01:28:16.7127862 | 01:28:57.6962735 | 1 963 extraits | 5 détections |

## Cibles, identité et exclusions

Le dépôt a été scanné depuis sa racine, sur son worktree présent au moment du contrôle, fichiers suivis et non suivis compris. `.git` et `reports` étaient exclus. Trivy `fs` n’a pas examiné l’historique des commits.

Pour l’application, le tag local était `bkimminich/juice-shop:v20.3.0`. `docker image inspect` a confirmé l’ID local `sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27`, Linux/amd64 et 24 couches. Le conteneur temporaire d’extraction a été créé avec `docker create --pull=never`, vérifié à l’état arrêté, utilisé pour copier `/juice-shop`, puis supprimé. Il n’a jamais été démarré. Seul le contenu extrait de `/juice-shop` a été monté en lecture seule pour le scan; le système Debian, les couches supprimées et l’état runtime n’étaient pas dans ce périmètre.

L’ID observé localement (`cea5…`) diffère de l’`ImageID` `4060…` de l’export/rapport initial, bien que les 24 couches soient concordantes. Le contrôle présent a utilisé explicitement l’ID local `cea5…`; il ne résout pas cette divergence ni n’établit indépendamment un digest de manifeste de registre.

Les JSON bruts, journaux et fichiers extraits sont conservés sous `%LOCALAPPDATA%\JuiceShopAudit\secrets\<run-id>`, hors du dépôt, dans un répertoire ACL dont l’héritage a été retiré et auquel seul le compte courant a accès. Ils ne sont ni publiés ni attachés à ce rapport.

## Décomptes par règle

| Périmètre | Règle Trivy | Catégorie | Sévérité Trivy | Occurrences |
|---|---|---|---|---:|
| Worktree dépôt | — | — | — | 0 |
| Fichiers `/juice-shop` | `private-key` | `AsymmetricPrivateKey` | HIGH | 3 |
| Fichiers `/juice-shop` | `jwt-token` | `JWT` | MEDIUM | 2 |
| **Total application** |  |  |  | **5** |

Deux des trois occurrences `private-key` (source TypeScript et build JavaScript) contiennent le même matériel détecté; elles ne représentent pas deux clés distinctes. La troisième est dans la configuration Terraform. Aucune valeur détectée n’est incluse, même partiellement.

## Détail expurgé — une entrée par détection

| ID | Règle / emplacement | Contexte expurgé | Interprétation et conclusion |
|---|---|---|---|
| S-01 | `private-key` — `lib/insecurity.ts:21` — HIGH | Constante `privateKey` à valeur masquée. Le code source définit `authorize()` avec un appel à `jwt.sign(..., privateKey, ...)` à la ligne 54. | **Secret potentiel dans du code applicatif fixe.** La fonction dispose d’un chemin de signature JWT; ce résultat statique ne prouve pas à lui seul qu’une route l’a invoquée pendant ce contrôle. L’intention pédagogique possible de Juice Shop ne rend pas la clé automatiquement inutilisable ailleurs. Validité inconnue. |
| S-02 | `private-key` — `build/lib/insecurity.js:55` — HIGH | Constante compilée `privateKey` à valeur masquée; même matériel détecté qu’en S-01. Le build définit `authorize()` avec `jsonwebtoken.sign(..., privateKey, ...)` à la ligne 72. | **Même secret potentiel que S-01, présent dans le build livré.** La copie compilée est dans l’arborescence applicative de l’image; l’usage effectif dépend de l’appel de la fonction. Validité inconnue; aucune tentative de validation externe. |
| S-03 | `private-key` — `infrastructure/terraform/networking.tf:171` — HIGH | Attribut `private_key` avec valeur masquée, dans une configuration Terraform qui fournit aussi `certificate_body` depuis `file(...)` à la ligne 170. | **Secret potentiel dans une configuration d’infrastructure.** Le scan ne montre pas si Terraform a été exécuté, si la ressource a été déployée ni si cette clé est encore utilisée. Contexte de configuration possiblement pédagogique; validité inconnue. |
| S-04 | `jwt-token` — `frontend/src/app/app.guard.spec.ts:46` — MEDIUM | Valeur JWT masquée écrite dans `localStorage` par un test; l’assertion suivante porte sur `LoginGuard.tokenDecode`. | **Exemple pédagogique / fixture de test probable.** Cela qualifie le contexte du fichier, pas la validité du token : un token de test n’est pas présumé inutilisable ailleurs. Validité inconnue. |
| S-05 | `jwt-token` — `frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:72` — MEDIUM | Valeur JWT masquée écrite dans `localStorage` par un test avant `component.ngOnInit()`; le test vérifie ensuite l’appel du sanitizer. | **Exemple pédagogique / fixture de test probable.** Le test ne démontre ni que le token est invalide ni qu’il est accepté par un service. Validité inconnue. |

## Commandes utilisées

Les chemins hôtes privés sont représentés par `$runRoot`; ils ne sont pas publiés. Les options et cibles ci-dessous correspondent aux commandes exécutées.

**Worktree du dépôt :**

```powershell
$repoLog = Join-Path $runRoot 'repository.trivy.log'
docker run --pull=never --rm `
    -v "${repoRoot}:/src:ro" `
    -v "${runRoot}:/out" `
    aquasec/trivy:0.76.0 fs `
    --scanners secret `
    --skip-dirs /src/.git --skip-dirs /src/reports `
    --format json --output /out/repository.raw.json `
    --quiet --disable-telemetry --skip-version-check /src *> $repoLog
```

**Fichiers applicatifs :** un conteneur temporaire non démarré a fourni `/juice-shop` :

```powershell
$imageId = 'sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27'
$observedId = docker image inspect --format '{{.Id}}' 'bkimminich/juice-shop:v20.3.0'
if ($LASTEXITCODE -ne 0 -or $observedId.Trim() -ne $imageId) { throw 'Image identity mismatch' }
$extractName = "juice-shop-secret-extract-$([guid]::NewGuid().ToString('N'))"
$extractLog = Join-Path $runRoot 'application-extraction.log'
$containerId = docker create --pull=never --name $extractName $imageId 2>> $extractLog
if ($LASTEXITCODE -ne 0) { throw 'docker create failed' }
if ((docker inspect --format '{{.State.Running}}' $containerId 2>> $extractLog).Trim() -ne 'false') { throw 'Container is not stopped' }
docker cp "${containerId}:/juice-shop/." $appFiles *> $extractLog
if ($LASTEXITCODE -ne 0) { throw 'docker cp failed' }
docker rm $containerId *> $extractLog
if ($LASTEXITCODE -ne 0) { throw 'docker rm failed' }
$appLog = Join-Path $runRoot 'application.trivy.log'
docker run --pull=never --rm `
    -v "${appFiles}:/src:ro" `
    -v "${runRoot}:/out" `
    aquasec/trivy:0.76.0 fs `
    --scanners secret `
    --format json --output /out/juice-shop-files.raw.json `
    --quiet --disable-telemetry --skip-version-check /src *> $appLog
```

Les journaux d’exécution sont restés sous le même dossier privé. Aucun scan de vulnérabilités, contrôle réseau d’identifiants, test d’exploitation ou changement de l’application n’a été réalisé.

## Limites

Une détection Trivy indique qu’une règle a correspondu à du contenu; elle ne prouve pas que la valeur est authentique, active, acceptée par un service ou exploitable. Aucune validation externe n’a été faite. Le contexte de test ou de démonstration est distinct de la validité de la valeur.

Le résultat nul du worktree ne démontre pas l’absence de secrets : `.git` et `reports` étaient exclus, l’historique n’a pas été examiné, et tout scanner peut manquer des formes non reconnues. Le scan applicatif porte uniquement sur les fichiers présents sous `/juice-shop` dans l’image locale utilisée; il ne couvre pas les autres répertoires système, les couches supprimées ou la configuration d’un conteneur en cours d’exécution.
