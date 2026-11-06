# Laboratoire d’audit de sécurité applicative

Audit d’OWASP Juice Shop `v20.3.0` avec Trivy et (en reproduction open
source) le plan Jit : analyse des constats, corrections ciblées, contre-audit
et décision de livraison argumentée.

## État final (6 novembre 2026)

> **Verdict : non livrable en exposition réelle ; acceptable seulement
> comme cible d’entraînement isolée.** Voir la
> [décision de livraison](docs/decision-livraison.md).

| Étape du plan d’action | État |
|---|---|
| Scans Trivy (image, SBOM, secrets, configurations) | **Fait** : 98 détections au 20 octobre; analysées une à une ([fiches 01–21](docs/analysis/)) |
| Constats confirmés | **Fait** : [F-001](docs/findings/F-001-jwt-algorithm-confusion.md), [F-002](docs/findings/F-002-cle-privee-jwt-codee-en-dur.md), [F-003](docs/findings/F-003-jetons-sans-expiration.md) |
| Corrections et contre-audit | **Fait** sur le fork [`othmane1244/juice-shop`](https://github.com/othmane1244/juice-shop/tree/audit/corrections) : 124 → 105 détections, 19 supprimées toutes par les corrections; attaques JWT 200 → 401; tests 417/417 et 545/545 |
| CI | **Fait** : contrôle Trivy bloquant sur les nouvelles CRITICAL/HIGH, ligne de base de 28 exceptions justifiées (échéance 31 décembre 2026) |
| Jit | **Bloqué** : jit.io inaccessible ([constat](docs/jit/acces-bloque.md)). Plan « Minimal Viable Security » **reproduit** avec Semgrep, OSV-Scanner, Gitleaks, KICS et Trivy ([comparaison](docs/jit/comparaison-trivy-plan-jit.md)). Selon le plan d’action, cette reproduction **ne remplace pas** la tâche Jit. |
| Protection de branche avec refus démontré d’une PR | **Non fait** |
| AuditTrace, versions A/B/C (EventLab) | **Hors périmètre** : remplacés par Juice Shop (voir [feuille de route](docs/feuille-de-route.md)) |

## Parcours de lecture pour le jury

Environ une heure en lisant les étapes 1 à 6; les fiches de l’étape 7 se
consultent à la demande.

1. **[Décision de livraison](docs/decision-livraison.md)** : critères du
   plan, verdict, risques résiduels, conditions. C’est le résumé de tout le
   dossier.
2. **Ce qui a été audité** : [identité de l’image](docs/identite-image.md)
   (pourquoi `cea5…` et `4060…` désignent la même image).
3. **Les trois constats démontrés**, dans l’ordre de priorité :
   [F-002](docs/findings/F-002-cle-privee-jwt-codee-en-dur.md) clé JWT codée
   en dur, [F-001](docs/findings/F-001-jwt-algorithm-confusion.md) confusion
   d’algorithme, [F-003](docs/findings/F-003-jetons-sans-expiration.md)
   jetons sans expiration.
4. **Vue d’ensemble des 98 détections** :
   [bilan du scan initial](docs/analysis/20-bilan-scan-initial.md) puis
   [synthèse des risques](docs/analysis/21-synthese-des-risques.md).
5. **[Contre-audit](docs/contre-audit.md)** : corrections vérifiées,
   avant/après Trivy à périmètre constant, écart 98 → 124, CI, workflows,
   risques acceptés.
6. **Jit** : [accès bloqué](docs/jit/acces-bloque.md), puis
   [comparaison Trivy / plan Jit reproduit](docs/jit/comparaison-trivy-plan-jit.md)
   (ce que Semgrep trouve dans le code et que Trivy ne voit pas).
7. **À la demande** :
   - fiches par paquet [01](docs/analysis/01-authentification.md) à
     [19](docs/analysis/19-paquets-debian.md), en commençant par
     [01 authentification](docs/analysis/01-authentification.md),
     [07 MarsDB](docs/analysis/07-marsdb.md) et
     [13 file-type](docs/analysis/13-file-type.md);
   - [22 — tri des 28 détections apparues après le 20 octobre](docs/analysis/22-nouvelles-detections.md);
   - contrôles initiaux : [secrets](docs/secrets/rapport-partageable.md),
     [mauvaises configurations](docs/misconfigurations/rapport-partageable.md),
     [SBOM](docs/sbom/README.md);
   - préparation Jit : [étude](docs/jit/README.md),
     [procédure de connexion non exécutée](docs/jit/procedure-connexion-fork.md);
   - [feuille de route](docs/feuille-de-route.md) et le plan d’action
     `Plan_Action_AuditTrace_Trivy_Jit.docx`.

## Index des preuves

### Rapports bruts et résultats

| Preuve | Fichier | Utilisée dans |
|---|---|---|
| Scan Trivy initial, `v20.3.0`, 20 octobre (98 détections) | [reports/trivy-image-initial.json](reports/trivy-image-initial.json) | [20](docs/analysis/20-bilan-scan-initial.md), fiches 01–19 |
| Filtre CRITICAL/HIGH du scan initial (38) | [reports/trivy-image-high-critical.json](reports/trivy-image-high-critical.json) | [20](docs/analysis/20-bilan-scan-initial.md) |
| SBOM CycloneDX de l’image | [reports/sbom/juice-shop-initial.cdx.json](reports/sbom/juice-shop-initial.cdx.json) | [sbom](docs/sbom/README.md) |
| Rescan `v20.3.0`, base du 4 novembre (124) | [reports/trivy-image-v20.3.0-rescan.json](reports/trivy-image-v20.3.0-rescan.json) | [contre-audit § 4–5](docs/contre-audit.md) |
| Scan de l’image corrigée (105) | [reports/trivy-image-corrige.json](reports/trivy-image-corrige.json) | [contre-audit § 4](docs/contre-audit.md) |
| Comparaison avant/après | [reports/contre-audit/comparaison-trivy.json](reports/contre-audit/comparaison-trivy.json) | [contre-audit § 4](docs/contre-audit.md) |
| Comparaison initial / rescan | [reports/contre-audit/comparaison-initial-vs-rescan.json](reports/contre-audit/comparaison-initial-vs-rescan.json) | [contre-audit § 5](docs/contre-audit.md) |
| Tests JWT et parcours fonctionnel, origine (4/9) | [reports/contre-audit/jwt-fonctionnel-origine.json](reports/contre-audit/jwt-fonctionnel-origine.json) | [contre-audit § 2](docs/contre-audit.md) |
| Tests JWT et parcours fonctionnel, corrigé (9/9) | [reports/contre-audit/jwt-fonctionnel-corrige.json](reports/contre-audit/jwt-fonctionnel-corrige.json) | [contre-audit § 2](docs/contre-audit.md) |
| Modules chargés à l’exécution | [reports/contre-audit/modules-charges-execution.json](reports/contre-audit/modules-charges-execution.json) | [22](docs/analysis/22-nouvelles-detections.md) |
| Plan Jit reproduit : résultats par branche et par outil (SARIF, JSON; secrets expurgés) | [reports/plan-jit-oss/](reports/plan-jit-oss/) | [comparaison](docs/jit/comparaison-trivy-plan-jit.md) |
| Plan Jit reproduit : synthèse chiffrée | [reports/plan-jit-oss/synthese.json](reports/plan-jit-oss/synthese.json) | idem |

Les sorties brutes des contrôles de secrets restent hors du dépôt; seuls les
rapports expurgés sont versionnés. Les exports bruts Jit éventuels iraient
dans `reports/jit/brut/`, ignoré par git.

### Scripts (tous rejouables)

| Script | Rôle |
|---|---|
| [scripts/keycheck.py](scripts/keycheck.py) | Vérifie qu’une clé privée et `jwt.pub` forment une paire, sans afficher les clés (F-002) |
| [scripts/contre-audit-jwt.mjs](scripts/contre-audit-jwt.mjs) | Parcours fonctionnel et attaques JWT contre une instance; n’écrit aucune clé |
| [scripts/compare-trivy.mjs](scripts/compare-trivy.mjs) | Compare deux rapports Trivy (avant/après) |
| [scripts/dump-loaded.js](scripts/dump-loaded.js) | Relève les paquets chargés et les bibliothèques projetées d’un processus Node |
| [scripts/synthese-plan-jit.mjs](scripts/synthese-plan-jit.mjs) | Synthèse du plan reproduit et recoupement avec Trivy |

### Dans le fork [`othmane1244/juice-shop`](https://github.com/othmane1244/juice-shop)

| Preuve | Emplacement |
|---|---|
| Corrections | Branche [`audit/corrections`](https://github.com/othmane1244/juice-shop/tree/audit/corrections), commits signés |
| Code audité sans correction | Branche [`audit/base-v20.3.0`](https://github.com/othmane1244/juice-shop/tree/audit/base-v20.3.0) (`f189f52`) |
| Lockfile repris de l’image `v20.3.0` | [`package-lock.json`](https://github.com/othmane1244/juice-shop/blob/audit/corrections/package-lock.json) |
| Ligne de base CI justifiée | [`.trivyignore.yaml`](https://github.com/othmane1244/juice-shop/blob/audit/corrections/.trivyignore.yaml) |
| Contrôle Trivy bloquant | [`.github/workflows/audit-trivy.yml`](https://github.com/othmane1244/juice-shop/blob/audit/corrections/.github/workflows/audit-trivy.yml), runs dans [Actions](https://github.com/othmane1244/juice-shop/actions/workflows/audit-trivy.yml) |
| Plan Jit reproduit | [`.github/workflows/plan-jit-oss.yml`](https://github.com/othmane1244/juice-shop/blob/ci/plan-jit-oss/.github/workflows/plan-jit-oss.yml) ([PR #1](https://github.com/othmane1244/juice-shop/pull/1)), run [42073516164](https://github.com/othmane1244/juice-shop/actions/runs/42073516164); alertes dans l’onglet [Security](https://github.com/othmane1244/juice-shop/security/code-scanning) |

## Objectif et périmètre

- Application cible : OWASP Juice Shop.
- Environnement étudié : Windows, Docker Desktop et WSL 2.
- Plateforme d’image : `linux/amd64`.
- Accès à l’application : local uniquement.
- AuditTrace est facultatif et sera considéré après le socle.
- Aucun développement EventLab n’est prévu dans le périmètre actuel.

Juice Shop est une application tierce. Le laboratoire porte sur la
méthode d’audit, l’analyse, les corrections ciblées et l’automatisation.

Image locale auditée : `bkimminich/juice-shop:v20.3.0`, Linux/amd64,
24 couches. Docker indique localement l’ID/RepoDigest
`sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27`.
Cette valeur est le digest de l’**index OCI** multi-plateforme (Docker
Desktop utilise le stockage containerd). Son manifeste `linux/amd64`
(`sha256:590a4516…`) a pour configuration
`sha256:40606cfb23b8937b60c1cab5a5980362e0a372223c1f86f6c3e68c1b003a823c`,
qui est l’`ImageID` des rapports Trivy et du SBOM : il s’agit bien de la même
image. Voir [identite-image.md](docs/identite-image.md).

## Reproduire l’audit

Les sections 1 à 9 refont l’audit initial pas à pas. Le contre-audit (image
corrigée, avant/après, tests JWT) se rejoue avec les commandes et scripts du
[contre-audit](docs/contre-audit.md), à partir du fork.

## 1. Récupérer le dépôt

Dans PowerShell :

```powershell
git clone https://github.com/othmane1244/devsecops-application-security-audit.git
cd devsecops-application-security-audit
```

Utiliser la branche `main`, qui contient ce guide, le plan d’action,
les rapports initiaux et les fiches d’analyse. Pour refaire le laboratoire,
suivre les étapes ci-dessous. Ne pas remplacer le rapport initial lors
des contre-audits : utiliser un nouveau nom de fichier.

## 2. Vérifier les outils

Démarrer Docker Desktop, puis vérifier WSL, Git et Docker :

```powershell
wsl --list --verbose
git --version
docker version
docker run --rm hello-world
```

Résultats observés sur le poste initial : Ubuntu sous WSL 2, Git
`2.52.0.windows.1` et Docker `29.1.2`. Le test `hello-world` a réussi.
Ces versions décrivent le poste de référence ; elles ne sont pas des
prérequis universels.

## 3. Fixer les images utilisées

Les versions retenues sont Juice Shop `v20.3.0` et Trivy `0.76.0`.
Les digests fixent le contenu des images :

```powershell
$juiceImage = "bkimminich/juice-shop@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27"
$trivyImage = "aquasec/trivy@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222"
```

Redéfinir ces variables après l’ouverture d’une nouvelle session
PowerShell.

## 4. Télécharger et lancer Juice Shop

```powershell
docker pull $juiceImage
docker run -d --name juice-shop-audit -p 127.0.0.1:3000:3000 $juiceImage
docker ps --filter name=juice-shop-audit
docker logs --tail 50 juice-shop-audit
```

Ouvrir [http://localhost:3000](http://localhost:3000). Le message de
démarrage attendu est `Server listening on port 3000`. Les avertissements
Alchemy et LLM concernent des défis hors du périmètre initial.

Créer le conteneur une seule fois. Pour le gérer ensuite :

```powershell
docker stop juice-shop-audit
docker start juice-shop-audit
```

Le conteneur Juice Shop n’a pas besoin de fonctionner pendant le scan
de son image.

## 5. Préparer Trivy et son cache

```powershell
docker pull $trivyImage
docker run --rm $trivyImage --version
New-Item -ItemType Directory -Force .\reports
docker volume create trivy-cache
```

La version vérifiée sur le poste initial était `0.76.0`.

## 6. Télécharger la base Trivy

Commande standard :

```powershell
docker run --rm --mount "type=volume,source=trivy-cache,target=/root/.cache/trivy" $trivyImage image --db-repository ghcr.io/aquasecurity/trivy-db:2 --download-db-only --timeout 60m
```

Des erreurs DNS ont été rencontrées sur le poste initial. Si cela se
produit, essayer d’ajouter `--dns 8.8.8.8` après `--rm` :

```powershell
docker run --rm --dns 8.8.8.8 --mount "type=volume,source=trivy-cache,target=/root/.cache/trivy" $trivyImage image --db-repository ghcr.io/aquasecurity/trivy-db:2 --download-db-only --timeout 60m
```

Le DNS `10.23.126.175` a aussi fonctionné temporairement pendant le
diagnostic. Une autre source de base essayée était
`public.ecr.aws/aquasecurity/trivy-db:2`. Ces options dépendent du réseau ;
`8.8.8.8` n’est pas un prérequis universel.

## 7. Effectuer le scan initial de l’image

Depuis la racine du dépôt, lancer le scan distant :

```powershell
docker run --rm --mount "type=volume,source=trivy-cache,target=/root/.cache/trivy" --mount "type=bind,source=$($PWD.Path)\reports,target=/reports" $trivyImage image --db-repository ghcr.io/aquasecurity/trivy-db:2 --image-src remote --platform linux/amd64 --scanners vuln --timeout 15m --format json --output /reports/trivy-image-initial.json $juiceImage
$LASTEXITCODE
Get-Item .\reports\trivy-image-initial.json
```

Si le téléchargement distant échoue avec une erreur réseau ou
`unexpected EOF`, et si l’image exacte est déjà présente localement,
l’exporter puis scanner l’archive. Cette méthode a produit le rapport de
référence dans l’environnement Windows de ce laboratoire :

```powershell
docker save --output .\reports\juice-shop-image.tar $juiceImage
docker run --rm --dns 8.8.8.8 --mount "type=volume,source=trivy-cache,target=/root/.cache/trivy" --mount "type=bind,source=$($PWD.Path)\reports,target=/reports" $trivyImage image --db-repository ghcr.io/aquasecurity/trivy-db:2 --scanners vuln --timeout 15m --format json --output /reports/trivy-image-initial.json --input /reports/juice-shop-image.tar
$LASTEXITCODE
Get-Item .\reports\trivy-image-initial.json
Remove-Item .\reports\juice-shop-image.tar
```

Ajouter `--dns 8.8.8.8` uniquement si la résolution DNS du conteneur
Trivy pose problème. Vérifier que le code de sortie est `0` et que le
JSON a été créé. Un code `0` signifie que le scan s’est exécuté ; il ne
signifie pas qu’aucune vulnérabilité n’a été trouvée.

Le scan analyse les vulnérabilités connues de l’image figée, réutilise le
volume `trivy-cache` et écrit le résultat dans
`reports/trivy-image-initial.json`. Il ne lance pas l’application.

## 8. Lire le rapport

```powershell
$rapport = Get-Content -Raw .\reports/trivy-image-initial.json | ConvertFrom-Json
$constats = @($rapport.Results | ForEach-Object { $_.Vulnerabilities } | Where-Object { $null -ne $_ })
$constats.Count
$constats | Group-Object Severity | Select-Object Name, Count
```

Le premier rapport de référence, généré le 20 octobre 2026, contenait
98 détections : 11 critiques, 27 élevées, 49 moyennes et 11 faibles.
Ces lignes ne correspondent pas nécessairement à 98 CVE distinctes :
une même vulnérabilité peut apparaître pour plusieurs versions ou
paquets. Le résultat peut changer si la base Trivy est mise à jour.

Pour afficher le détail d’une détection :

```powershell
$rapport.Results |
    ForEach-Object { $_.Vulnerabilities } |
    Where-Object { $_.VulnerabilityID -eq "CVE-2015-9235" } |
    Select-Object -First 1 |
    Format-List VulnerabilityID, PkgName, PkgPath, InstalledVersion, FixedVersion, Severity, Title, Description, PrimaryURL
```

## 9. Première alerte étudiée : CVE-2015-9235

- Paquet : `jsonwebtoken`.
- Version étudiée : `0.1.0`.
- Chemin : `juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json`.
- Gravité indiquée par Trivy : `CRITICAL`.
- Version corrective indiquée pour cette CVE : `4.2.2`.
- Sujet : contournement de vérification si un jeton signé avec un
  algorithme asymétrique est présenté avec un algorithme symétrique.

Le rapport signale aussi cette CVE pour `jsonwebtoken` version `0.4.0`.
La version `0.1.0` est la première occurrence examinée. Une détection
ne prouve pas à elle seule qu’un chemin exploitable existe dans
l’application : il faut vérifier l’usage réel du paquet et les conditions
d’exploitation.

**Statut final :** usage confirmé dans le code
([01](docs/analysis/01-authentification.md),
[F-001](docs/findings/F-001-jwt-algorithm-confusion.md)); **corrigé** dans le
fork (`jsonwebtoken` 9.0.3, RS256 seul accepté). Les jetons forgés sont
refusés (HTTP 401) et la CVE n’apparaît plus dans le scan de l’image corrigée
([contre-audit](docs/contre-audit.md)).

## Principes d’interprétation

- Une détection ne prouve pas automatiquement qu’elle est exploitable.
- L’absence d’alerte ne garantit pas la sécurité.
- Une erreur technique signifie que l’audit est incomplet.
- Une exclusion n’est pas une correction.
- Toute correction doit être vérifiée par un nouveau contrôle et un
  test de fonctionnement.

## Équipe

- Othmane Aliouali
- Youssef AIT KARROUM
