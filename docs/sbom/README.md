# Inventaire SBOM de l’image Juice Shop

## Résultat

Le SBOM CycloneDX JSON est [publié ici](../../reports/sbom/juice-shop-initial.cdx.json). Il a été généré le **2026-10-29 à 01:04:27 UTC** avec Trivy **0.76.0**, exécuté depuis l’image Docker locale `aquasec/trivy:0.76.0` (ID/config `sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222`). Le conteneur Juice Shop est resté arrêté; aucun scan de vulnérabilités n’a été relancé.

SHA-256 du fichier : `899a73e942072ed92d95a92cfe35fd594e4ad5730ea9baa1754bc1986fb44fa9`.

## Image et rapprochement avec le scan initial

La cible était le tag local `bkimminich/juice-shop:v20.3.0`, exporté avec `docker save`, puis fourni à Trivy via `--input`. L’inspection Docker du tag a renvoyé l’ID d’image `sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27`, `linux/amd64`, 24 couches, ainsi que `RepoDigests` portant la même valeur. Cette valeur n’a pas été vérifiée indépendamment comme digest de manifeste OCI du registre.

L’export utilisé contient dans `manifest.json` un fichier de configuration dont le SHA-256 réel est `sha256:40606cfb23b8937b60c1cab5a5980362e0a372223c1f86f6c3e68c1b003a823c`. Trivy inscrit cette même valeur comme `ImageID` dans le SBOM; elle correspond aussi à l’`ImageID` du rapport initial. Les 24 DiffIDs du SBOM concordent avec les 24 couches consignées dans le rapport. Le SBOM porte les propriétés `Reference` et `RepoTag` égales à `bkimminich/juice-shop:v20.3.0`.

Les identifiants `cea5…` observé par `docker image inspect` et `4060…` relevé dans la configuration de l’export/les rapports sont différents. Les couches et le tag rapprochent les artefacts, mais cette différence d’identifiant reste à interpréter prudemment; le digest de manifeste du registre n’a pas été établi. Références complémentaires : [bilan du scan initial](../analysis/20-bilan-scan-initial.md) et [synthèse des risques](../analysis/21-synthese-des-risques.md).

## Génération reproductible

Depuis la racine du dépôt, dans PowerShell, avec le moteur Docker actif, le tag Juice Shop déjà présent et l’image Trivy déjà chargée. `--pull=never` empêche Docker de récupérer Trivy depuis un registre. L’export est temporaire et supprimé à la fin; il ne modifie pas l’image.

```powershell
$ErrorActionPreference = 'Stop'
$sbomDir = Join-Path (Get-Location) 'reports/sbom'
$archive = Join-Path $sbomDir '.juice-shop-sbom-export.tar'
New-Item -ItemType Directory -Force -Path $sbomDir | Out-Null
try {
    docker save --output $archive bkimminich/juice-shop:v20.3.0
    if ($LASTEXITCODE -ne 0) { throw 'docker save failed' }

    docker run --pull=never --rm `
        -v "${sbomDir}:/out" `
        -v "${archive}:/image.tar:ro" `
        aquasec/trivy:0.76.0 image `
        --input /image.tar `
        --format cyclonedx `
        --output /out/juice-shop-initial.cdx.json `
        --offline-scan --skip-db-update --skip-java-db-update `
        --disable-telemetry --skip-version-check
    if ($LASTEXITCODE -ne 0) { throw 'Trivy SBOM generation failed' }
}
finally {
    Remove-Item -LiteralPath $archive -ErrorAction SilentlyContinue
}
```

Les options utilisées sont présentes dans l’aide de Trivy 0.76.0. L’option `--input` lit l’archive locale; aucune recherche d’image distante n’est nécessaire. Trivy a confirmé dans sa sortie que `--format cyclonedx` désactive le scan de sécurité. `--offline-scan`, `--skip-db-update` et `--skip-java-db-update` ont également été passés; aucun résultat de vulnérabilité n’est recherché ici.

## Contenu et vérifications

Un SBOM (Software Bill of Materials) est un inventaire structuré des composants logiciels détectés dans un produit ou une image. Il aide à savoir quels composants et versions l’outil a trouvés. Un rapport de vulnérabilités associe plutôt des composants à des avis connus selon les sources et règles d’un scanner, à une date donnée. Un SBOM seul ne conclut pas qu’un composant est vulnérable ou exploitable.

CycloneDX est un format standard qui peut décrire des composants, leurs identifiants, des métadonnées et des relations de dépendance que l’outil a effectivement émises. Ce résultat reste limité à la détection de Trivy dans cette image : il ne prouve pas qu’un composant est exécuté ni qu’un chemin d’appel le rejoint. Il ne faut pas inventer de relation au-delà du graphe fourni.

Vérifications effectuées sur `reports/sbom/juice-shop-initial.cdx.json` :

- Le JSON se lit avec `json.loads`; `bomFormat` vaut `CycloneDX` et `specVersion` vaut `1.7`.
- Le validateur Python `jsonschema` a validé le document contre le [schéma JSON CycloneDX 1.7 officiel](https://github.com/CycloneDX/specification/blob/4b3f594/schema/bom-1.7.schema.json) et son [sous-schéma SPDX](https://github.com/CycloneDX/specification/blob/4b3f594/schema/spdx.schema.json), au commit `4b3f594` : **0 erreur**.
- Métadonnées : outil `aquasecurity/trivy` version `0.76.0`; composant cible `/image.tar`, avec propriétés image ID, tag/référence et DiffIDs.
- Le BOM contient **733 composants**, **734 enregistrements `dependencies`** et **733 arêtes**. Le graphe émis contient 719 références depuis le composant conteneur et 14 depuis le composant Debian 13.7; ces relations sont les enregistrements du SBOM et ne sont pas une reconstitution indépendante de l’arbre npm.
- La propriété `vulnerabilities` est un tableau vide. L’outil a indiqué que le format CycloneDX avait désactivé le scan de sécurité.

Les deux copies de `jsonwebtoken` apparaissent comme des composants distincts avec leurs PURL, versions et chemins : `pkg:npm/jsonwebtoken@0.1.0` sous `node_modules/express-jwt/node_modules/jsonwebtoken`, et `pkg:npm/jsonwebtoken@0.4.0` sous `node_modules/jsonwebtoken`. Le SBOM inclut aussi, parmi les composants déjà étudiés, `got@8.3.2`, `moment@2.0.0` et `moment@2.31.0`, ainsi que les trois copies minimatch `3.0.5`, `3.1.5` et `9.0.9`. Ces présences n’établissent pas l’applicabilité d’un avis ni un usage à l’exécution.

La fiche et le JSON décrivent un inventaire ponctuel; ils ne remplacent pas les rapports initiaux de vulnérabilités. L’export temporaire a été supprimé après génération. Juice Shop n’a pas été démarré et l’image n’a pas été modifiée.
