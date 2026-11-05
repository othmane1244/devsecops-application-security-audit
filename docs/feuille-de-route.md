# Feuille de route — suite de l’audit

État au 4 novembre 2026. Le sujet est « Audit des applications modernes à
l’aide de Trivy **et Jit** ». La partie Trivy (image, SBOM, secrets,
configurations, analyse des 98 détections) est réalisée. Il reste à couvrir
Jit, les corrections avec contre-audit et l’automatisation.

## Comparaison avec le plan d’action

| Phase du plan | État |
|---|---|
| P3 — Scans Trivy | Fait : vulnérabilités, SBOM, secrets, configurations. |
| P5 — Analyse et priorités | Fait : fiches 01–21, constats F-001 à F-003. |
| P4 — Intégration Jit réelle | **Prête** : procédure de connexion au seul fork rédigée ([procédure](jit/procedure-connexion-fork.md)); connexion à faire par le responsable. |
| P6 — Corrections et contre-audit | **En partie fait** : F-001 à F-003, `file-type`, `HEALTHCHECK` corrigés et vérifiés ([contre-audit](contre-audit.md)). Dépendances et image de base verrouillées sur `v20.3.0`. Reste `sanitize-html`. |
| CI/CD et protection de branche | **En partie fait** : workflow Trivy bloquant les nouvelles CRITICAL/HIGH ([contre-audit, section 6](contre-audit.md#6-contrôle-ci--ne-bloquer-que-les-nouvelles-criticalhigh)). Reste la protection de branche. |
| P7 — AuditTrace | Facultatif; à sacrifier en premier si le temps manque. |
| EventLab / versions A-B-C | Remplacé par Juice Shop (décision consignée dans le README). |

## Étapes proposées, dans l’ordre

1. **Fork de Juice Shop épinglé sur `v20.3.0`** dans le compte GitHub de
   l’équipe (code public, licence MIT). C’est la cible Jit : ne pas installer
   Jit sur ce dépôt d’audit, qui contient des rapports bruts
   (voir les règles de [jit/README.md](jit/README.md)).
2. **Jit sur le fork uniquement** : relever les permissions demandées,
   désactiver si possible la détection de secrets avant le premier scan, puis
   lancer SAST / SCA / Dockerfile / IaC. Consigner moteur, règles, commit et
   résultats; comparer qualitativement avec Trivy (ce que chaque outil
   trouve ou manque), sans additionner les alertes.
3. **Corrections ciblées dans le fork**, une branche par famille :
   - F-002 : clé chargée depuis un secret d’exécution, nouvelle paire ≥ 2048 bits;
   - F-001 / F-003 : `express-jwt` maintenu, `jsonwebtoken` ≥ 9.0.0, `jws` ≥ 3.2.3,
     `algorithms: ['RS256']`, `exp` exigé;
   - `file-type` ≥ 21.3.1 (CVE-2026-31808), `sanitize-html` récent;
   - Dockerfile : `HEALTHCHECK` (DS-0026).
4. **Contre-audit** (fait le 4 novembre 2026 pour la série JWT / `file-type` / `HEALTHCHECK`, voir [contre-audit.md](contre-audit.md)) : reconstruire l’image, relever son digest, relancer les
   mêmes commandes Trivy dans un **nouveau** fichier
   (`reports/trivy-image-corrige.json`), relancer Jit, exécuter un test
   fonctionnel (connexion, panier). Tableau avant/après par constat.
5. **Pipeline GitHub Actions** sur le fork : Trivy (`fs` + `image`) et
   contrôles Jit à chaque PR, protection de branche avec contrôle obligatoire;
   démontrer qu’une PR réintroduisant une dépendance vulnérable est bloquée.
6. **Restitution** : trois constats complètement défendus (F-002 clé JWT,
   CVE-2026-31808 upload `file-type`, une mauvaise configuration Terraform),
   verdict de livraison et risques résiduels.

## Points documentaires encore ouverts

- ~~Identité de l’image (`cea5…` / `4060…`)~~ **Résolu le 4 novembre 2026**,
  voir [identite-image.md](identite-image.md).
- ~~Relire `build/lib/insecurity.js` dans l’image~~ **Fait** : F-002 et F-003
  confirmés sur la copie compilée.
- Numéros de ligne : préciser dans chaque fiche s’ils viennent de l’image ou
  du tag publié (ex. `/b2b/v2` à `server.ts:452` dans 01, `:421` dans 12).
- ~~Fork sans `package-lock.json`~~ **Résolu le 4 novembre 2026** : lock et
  image de base figés sur `v20.3.0` ([contre-audit, section 4](contre-audit.md#4-trivy-avant--après)).
- ~~28 détections apparues dans la base Trivy après le 20 octobre~~ **Triées**
  dans la fiche [22](analysis/22-nouvelles-detections.md); `body-parser` à corriger en priorité ([contre-audit, section 5](contre-audit.md#5-pourquoi-124-détections-aujourdhui-contre-98-au-départ)).
- Piste Handlebars + fichiers inscriptibles : voir [06](analysis/06-handlebars.md).
