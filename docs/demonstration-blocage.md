# Démonstration du blocage — P4.5, cas T06

Réalisée le 6 novembre 2026 sur le fork
[`othmane1244/juice-shop`](https://github.com/othmane1244/juice-shop).

Le plan d’action demande (P4.5) de « définir le ou les contrôles
obligatoires dans la protection de branche » et de « vérifier par une
tentative réelle que la fusion est bloquée ». Le cas T06 prévoit une
« modification pré-testée réintroduisant T01 [une dépendance vulnérable] ;
contrôle obligatoire attendu en échec ».

**Résultat : les deux contrôles obligatoires ont échoué, et la fusion a été
refusée à un administrateur.**

## 1. Protection appliquée à `audit/corrections`

La configuration a été présentée puis validée par le responsable de l’audit
avant d’être appliquée (API GitHub
`PUT /repos/othmane1244/juice-shop/branches/audit/corrections/protection`).
Relecture après application :
[`reports/demonstration-blocage/protection-audit-corrections.json`](../reports/demonstration-blocage/protection-audit-corrections.json).

| Réglage | Valeur | Raison |
|---|---|---|
| PR obligatoire | oui, 0 approbation | Aucun push direct. Le responsable travaille seul et GitHub n’autorise pas d’approuver sa propre PR. |
| Checks obligatoires | « Dépendances, secrets et configuration (fichiers) » et « Image construite », produits par GitHub Actions (`app_id` 15368) | Ce sont les deux jobs du workflow « Audit Trivy ». GitHub exige des checks (jobs), pas un workflow. L’`app_id` empêche qu’un autre émetteur fournisse un check du même nom. |
| Branche à jour (`strict`) | oui | Les checks portent sur le résultat réel de la fusion. |
| Administrateurs inclus (`enforce_admins`) | **oui** | Sans ce réglage, le propriétaire du dépôt pourrait passer outre. La démonstration serait alors sans valeur pour lui. |
| Push forcé, suppression de la branche | interdits | Empêche de réécrire ou d’effacer l’historique corrigé. |
| Non obligatoires | « Plan Jit (reproduction OSS) », CodeQL | Mode non bloquant décidé pour le plan reproduit ([comparaison](jit/comparaison-trivy-plan-jit.md)). |

## 2. Modification de test

PR [#3 du fork](https://github.com/othmane1244/juice-shop/pull/3), titrée
« [NE PAS FUSIONNER] T06 — régression : jsonwebtoken 0.4.0 », branche
`test/t06-regression-jsonwebtoken`, commit `569724f`.

- `package.json` : `jsonwebtoken` `^9.0.3` → `0.4.0`, soit la version
  vulnérable corrigée pour [F-001](findings/F-001-jwt-algorithm-confusion.md)
  et [F-003](findings/F-003-jetons-sans-expiration.md).
- `package-lock.json` régénéré par `npm install --package-lock-only` :
  `jsonwebtoken` 0.4.0 réapporte `jws` 0.2.6 et `base64url` 0.0.6, comme
  dans l’image `v20.3.0`.
- Aucun de leurs avis n’est dans `.trivyignore.yaml` (vérifié avant le
  test).

**Pré-test local** (`trivy fs`, mêmes options que la CI, ligne de base
comprise) : code de sortie 1, avec exactement 6 alertes, toutes dues à la
régression.

| Gravité | Avis | Paquet |
|---|---|---|
| CRITICAL | CVE-2015-9235 | `jsonwebtoken` 0.4.0 |
| HIGH | CVE-2022-23539 | `jsonwebtoken` 0.4.0 |
| HIGH | NSWG-ECO-17 | `jsonwebtoken` 0.4.0 |
| HIGH | CVE-2016-1000223 | `jws` 0.2.6 |
| HIGH | CVE-2025-65945 | `jws` 0.2.6 |
| HIGH | NSWG-ECO-428 | `base64url` 0.0.6 |

## 3. Résultat dans GitHub

Run « Audit Trivy »
[42205422297](https://github.com/othmane1244/juice-shop/actions/runs/42205422297)
sur la PR :
[`reports/demonstration-blocage/run-audit-trivy-t06.json`](../reports/demonstration-blocage/run-audit-trivy-t06.json).

| Check obligatoire | Résultat | Étape en échec | Journal |
|---|---|---|---|
| Dépendances, secrets et configuration (fichiers) | **failure** | « Trivy fs — blocage sur nouvelles CRITICAL/HIGH corrigeables » | `Total: 6 (HIGH: 5, CRITICAL: 1)` : les 6 avis du pré-test |
| Image construite | **failure** | « Trivy image — blocage sur nouvelles CRITICAL/HIGH corrigeables » | `Total: 6 (HIGH: 5, CRITICAL: 1)` : mêmes avis, vus dans l’image construite |

La construction de l’image a réussi : les échecs viennent **uniquement** de
la politique de blocage, pas d’une erreur technique.

État de la PR : `mergeStateStatus = BLOCKED`, les 2 checks requis en
`FAILURE`.

**Tentative réelle de fusion**, le 6 novembre 2026 à 10:51:48 UTC, par
l’API avec le compte propriétaire et administrateur
(`PUT /repos/othmane1244/juice-shop/pulls/3/merge`) :

```
HTTP 405 — {"message":"2 of 2 required status checks are failing."}
```

Preuve : [`reports/demonstration-blocage/tentative-fusion.json`](../reports/demonstration-blocage/tentative-fusion.json).
`audit/corrections` est resté sur `b007fff` avant et après.

## 4. Nettoyage

- Commentaire d’explication ajouté sur la PR, puis PR **fermée sans
  fusion** (`mergedAt` vide) : [`reports/demonstration-blocage/pr-3-t06.json`](../reports/demonstration-blocage/pr-3-t06.json).
- Branche `test/t06-regression-jsonwebtoken` **supprimée** sur GitHub et en
  local ; l’API répond « Branch not found ».
- `audit/corrections` : inchangée (`b007fff`), toujours protégée.

## 5. Limites

- **Une seule régression testée** : une dépendance npm vulnérable connue.
  Un nouveau secret serait aussi bloqué, puisque la même étape scanne les
  secrets, mais ce n’est pas démontré. Une mauvaise configuration ne
  bloquerait pas, car `misconfig` est seulement collecté. Une vulnérabilité
  **sans correctif** ne bloquerait pas non plus (`--ignore-unfixed`,
  [contre-audit § 7](contre-audit.md#7-risques-résiduels-acceptés)).
- **Contournements restant possibles pour le propriétaire** : modifier ou
  retirer la protection (droit d’administration du dépôt), ou ajouter une
  entrée au `.trivyignore.yaml` dans la PR elle-même. Ce dernier cas est
  visible à la revue mais n’est pas bloqué automatiquement. Aucun journal
  d’audit GitHub n’est conservé ici.
- **Les autres branches ne sont pas protégées** (`audit/base-v20.3.0`,
  `master`) : elles ne sont pas livrées.
- **Les échecs techniques bloquent aussi** : un échec de Trivy (base
  indisponible, délai dépassé) ferait échouer le check, donc bloquerait la
  fusion. C’est cohérent avec le plan (« tout échec technique […] suspend la
  décision »), mais une PR légitime peut alors attendre.
