# Identité de l’image auditée — écart `cea5…` / `4060…` résolu

Vérification du 4 novembre 2026, en lecture seule (aucun conteneur démarré).

## Constat

| Commande | Résultat |
|---|---|
| `docker info --format '{{json .DriverStatus}}'` | `[["driver-type","io.containerd.snapshotter.v1"]]` : Docker Desktop utilise le **stockage d’images containerd**. |
| `docker image inspect bkimminich/juice-shop:v20.3.0` | `Id` et `RepoDigests` = `sha256:cea5a4af…bf27`. |
| `docker buildx imagetools inspect …@sha256:cea5a4af…` | `MediaType: application/vnd.oci.image.index.v1+json` : `cea5…` est un **index OCI multi-plateforme** (amd64 `590a4516…`, arm64 `be6764a7…`). |
| `docker buildx imagetools inspect --raw …@sha256:590a4516…` | Configuration `sha256:40606cfb…823c`, 24 couches. |

Avec le stockage containerd, `docker image inspect` renvoie dans `.Id` le
digest de l’index, et non le digest de configuration comme avec l’ancien
stockage. Trivy, lui, inscrit dans `Metadata.ImageID` le digest de
configuration de la plateforme scannée.

## Conclusion

```text
cea5a4af… (index OCI, tag v20.3.0)
└─ 590a4516… (manifeste linux/amd64)
   └─ 40606cfb… (configuration = ImageID des rapports Trivy et du SBOM)
```

Les deux valeurs désignent **la même image** à deux niveaux différents. Ce
n’est pas une divergence de contenu. La fiche [01](analysis/01-authentification.md)
décrivait déjà correctement cette chaîne.

L’interprétation des fiches [13 (D-01)](analysis/13-file-type.md),
[20 (§ divergences, point 7)](analysis/20-bilan-scan-initial.md) et
[21](analysis/21-synthese-des-risques.md) — deux ID de configuration
différant par le label `org.opencontainers.image.created` (« ” » contre « ? »)
— est donc **erronée**. Le « ? » observé provenait vraisemblablement de
l’affichage de la console. Les mentions « limite d’attribution » dans le
README, le SBOM, les secrets et les mauvaises configurations n’ont plus lieu
d’être : les contrôles sur `cea5…` portent sur l’image des rapports.
