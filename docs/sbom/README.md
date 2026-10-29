# Inventaire SBOM de l’image Juice Shop

## État de cette étape

La génération de `reports/sbom/juice-shop-initial.cdx.json` est **bloquée** dans l’environnement vérifié le **2026-10-29**. Le client Docker existe, mais le moteur Docker Desktop refuse l’accès à son pipe (`permission denied`). La commande `trivy` n’est pas trouvée sur le `PATH`, aucun `trivy.exe` n’a été trouvé dans les emplacements usuels inspectés et aucun export local de l’image n’est présent dans le dépôt. Aucun fichier SBOM n’a donc été généré, validé ou haché. Le nom de fichier ci-dessus désigne la sortie attendue, pas un artefact existant.

La version **Trivy 0.76.0** est celle du contexte et des rapports déjà archivés; sa présence locale et ses options ne peuvent pas être vérifiées ici. La documentation officielle de Trivy 0.76 décrit `trivy image --format cyclonedx` comme une génération SBOM qui n’inclut pas les vulnérabilités par défaut. Le sélecteur `--image-src docker` limite la résolution à Docker et évite le repli implicite vers un registre. Voir [SBOM Trivy 0.76](https://trivy.dev/docs/v0.76/guide/supply-chain/sbom/) et [cibles image](https://trivy.dev/docs/v0.76/guide/target/container_image/).

## Image visée et identité connue

La cible documentée est `bkimminich/juice-shop:v20.3.0`. Le README et les analyses consignent la valeur Docker locale `sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27`, également rapportée comme `RepoDigest`. Cette valeur correspond à l’identifiant de configuration Docker local observé dans les preuves antérieures. Elle ne constitue pas, à elle seule, une vérification indépendante du digest de manifeste OCI du registre.

Le rapport initial Trivy consigne un autre identifiant d’image (`sha256:40606cfb23b8937b60c1cab5a5980362e0a372223c1f86f6c3e68c1b003a823c`) et 24 DiffIDs. Les analyses antérieures documentent la concordance des 24 couches et une différence d’identifiant de configuration liée au champ `created` de la configuration. Ces éléments rapprochent les artefacts sans permettre de lire l’image locale maintenant que le moteur est inaccessible. Références : [bilan du scan initial](../analysis/20-bilan-scan-initial.md) et [synthèse des risques](../analysis/21-synthese-des-risques.md).

## Commande de génération prévue

Depuis la racine du dépôt, dans PowerShell, lorsque Trivy 0.76.0 et le moteur Docker sont disponibles et que l’image cible est déjà chargée localement :

```powershell
New-Item -ItemType Directory -Force reports/sbom | Out-Null
trivy image --image-src docker --format cyclonedx --output reports/sbom/juice-shop-initial.cdx.json bkimminich/juice-shop:v20.3.0
```

Le choix explicite `--image-src docker` interdit de chercher l’image dans un registre si elle est absente du moteur local. Ne pas remplacer la référence par un tag ou une image téléchargée. La génération CycloneDX par défaut n’ajoute pas de résultats de vulnérabilités; cette étape ne demande pas de relancer le scanner de vulnérabilités.

Cette commande est la procédure documentée à partir de la documentation versionnée de Trivy 0.76. Son exécution et la présence de chaque option dans un binaire local n’ont pas pu être testées dans l’environnement bloqué.

## Ce que l’inventaire décrira

Un SBOM (Software Bill of Materials) est un inventaire structuré des composants logiciels détectés dans un produit ou une image. Il aide à savoir quels composants sont présents et à rapprocher leurs identifiants et versions d’autres informations.

Un rapport de vulnérabilités répond à une autre question : il associe des composants à des avis connus selon les sources et règles de détection d’un scanner, à une date donnée. Un SBOM n’est pas en lui-même une conclusion de vulnérabilité ou d’exploitabilité.

CycloneDX est un format standard pouvant représenter des composants, leurs identifiants, des métadonnées et des relations de dépendance lorsque l’outil les connaît et les émet. L’inventaire reste limité à ce que Trivy sait découvrir dans l’image : il peut omettre des éléments non reconnus, ne prouve pas qu’un composant est exécuté, ne démontre pas les chemins d’appel et ne garantit pas une relation transitive absente du résultat. Les relations ne doivent pas être déduites du seul nom ou de la version.

## Vérifications à consigner après déblocage

La génération devra être suivie d’une validation syntaxique JSON et du champ `bomFormat` (`CycloneDX`), puis de la validation de schéma si un validateur disponible est utilisé. Il faudra relever `specVersion`, les métadonnées Trivy, la cible, le nombre de composants et les relations `dependencies` effectivement présentes. Vérifier notamment comment les deux installations de `jsonwebtoken` relevées dans le rapport sont représentées, sans supposer qu’elles restent deux composants distincts.

Consigner dans cette fiche la date UTC exacte de la génération, la version obtenue avec `trivy version`, l’identité que Trivy inscrit dans le BOM, la commande réellement exécutée, les résultats de validation et le SHA-256 du fichier. À ce stade, ces valeurs et les observations sur les composants ne sont pas disponibles; aucun hash n’est attribué à un SBOM inexistant.
