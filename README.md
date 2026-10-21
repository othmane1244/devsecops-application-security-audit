# Laboratoire d’audit de sécurité applicative

Guide reproductible pour auditer OWASP Juice Shop avec Trivy et Jit,
analyser les constats, appliquer des corrections ciblées et vérifier
leurs effets.

## Objectif et périmètre

- Application cible : OWASP Juice Shop.
- Environnement étudié : Windows, Docker Desktop et WSL 2.
- Plateforme d’image : `linux/amd64`.
- Accès à l’application : local uniquement.
- AuditTrace est facultatif et sera considéré après le socle.
- Aucun développement EventLab n’est prévu dans le périmètre actuel.

Juice Shop est une application tierce. Le laboratoire porte sur la
méthode d’audit, l’analyse, les corrections ciblées et l’automatisation.

## 1. Récupérer le dépôt

Dans PowerShell :

```powershell
git clone https://github.com/othmane1244/devsecops-application-security-audit.git
cd devsecops-application-security-audit
```

Utiliser la branche `main`, qui contient ce guide et le plan d’action.
Le rapport du premier scan a été conservé sur la branche
`docs/project-readme` ; pour le consulter :

```powershell
git switch docs/project-readme
```

Pour refaire le laboratoire depuis `main`, revenir à `main` et suivre
les étapes ci-dessous. Ne pas remplacer le rapport initial lors des
contre-audits : utiliser un nouveau nom de fichier.

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

**Statut :** version affectée détectée ; exploitabilité locale à vérifier.
Aucune correction n’a encore été appliquée.

## 10. Suite du laboratoire

1. Préserver le rapport initial et consigner les métadonnées d’exécution.
2. Examiner le code qui utilise la première dépendance concernée.
3. Rédiger les fiches de constat et justifier les priorités.
4. Vérifier l’accès à Jit et les contrôles disponibles.
5. Compléter les analyses : secrets, configurations et SBOM.
6. Corriger un nombre limité de constats, reconstruire l’image et
   effectuer le contre-audit.
7. Ajouter les contrôles CI/CD et les tests fonctionnels.
8. Envisager AuditTrace après la réalisation du socle.

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
