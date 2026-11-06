# Décision de livraison — OWASP Juice Shop v20.3.0 corrigé

Date : 6 novembre 2026. Objet : la version corrigée du fork
[`othmane1244/juice-shop`](https://github.com/othmane1244/juice-shop),
branche `audit/corrections`, image `juice-shop-corrige:audit-lock`.

> **Verdict : non livrable en exposition réelle. Acceptable seulement comme
> cible d’entraînement isolée**, aux conditions de la section 6.

## 1. Critères définis au départ

Les critères viennent du plan d’action (`Plan_Action_AuditTrace_Trivy_Jit.docx`,
section 04, étape P0.5 : « définir les critères de livraison avant les
scans »). Le plan prévoit quatre issues : **audit incomplet** (preuve
obligatoire absente ou contrôle invalide), **livraison bloquée** (audit valide
mais critère bloquant non satisfait), **sous conditions** (exceptions
autorisées à suivre), **critères satisfaits sur le périmètre**.

| Critère du plan | Condition attendue | Résultat | Preuve |
|---|---|---|---|
| Validité de l’audit | Tous les contrôles obligatoires terminés et rattachés à la bonne version | **Satisfait**. Trivy : complet et rattaché aux bonnes images (ImageID vérifiés). **Jit (P4) : réalisé par substitution validée par le professeur le 6 novembre 2026** (reproduction open source du plan, rattachée à `audit/base-v20.3.0` et `audit/corrections`). **Protection de branche (P4.5) : démontrée le 6 novembre 2026** (voir T06). | [identite-image](identite-image.md), [contre-audit § 1](contre-audit.md#1-ce-qui-a-été-comparé), [acces-bloque](jit/acces-bloque.md), [comparaison](jit/comparaison-trivy-plan-jit.md), [demonstration-blocage](demonstration-blocage.md) |
| T06 — Régression (cas T06 du plan) | Une modification réintroduisant une dépendance vulnérable fait échouer le contrôle obligatoire | **Satisfait** : la PR de test (retour à `jsonwebtoken` 0.4.0) fait échouer les 2 checks obligatoires d’« Audit Trivy » (6 alertes, dont CVE-2015-9235 CRITICAL). La fusion tentée par un administrateur est **refusée** (HTTP 405). PR fermée sans fusion, branche supprimée. | [demonstration-blocage](demonstration-blocage.md), [`reports/demonstration-blocage/`](../reports/demonstration-blocage/) |
| Défauts bloquants | Aucun défaut confirmé bloquant sans traitement autorisé | **Satisfait pour une cible d’entraînement, non satisfait pour une exposition réelle** (section 4) | [contre-audit § 7](contre-audit.md#7-risques-résiduels-acceptés), [comparaison § 6](jit/comparaison-trivy-plan-jit.md#6-effet-sur-la-décision-de-livraison) |
| Fonctionnement | Le parcours vérifié fonctionne après modification | **Satisfait** : connexion, `whoami`, panier, envoi d’image identiques avant/après; tests serveur 417/417 et API 545/545 | [contre-audit § 3](contre-audit.md#3-non-régression-fonctionnelle) |
| Exceptions | Motif, responsable, périmètre et échéance pour chacune | **Satisfait** : 28 exceptions dans `.trivyignore.yaml`, chacune avec motif (fiche ou tri), périmètre (purl), échéance (31 décembre 2026), acceptées par le responsable de l’audit le 4 novembre 2026. Le responsable n’est pas écrit dans chaque entrée, mais dans le contre-audit. | [contre-audit § 6–7](contre-audit.md#6-contrôle-ci--ne-bloquer-que-les-nouvelles-criticalhigh), [`.trivyignore.yaml`](https://github.com/othmane1244/juice-shop/blob/audit/corrections/.trivyignore.yaml) |

**Substitution de Jit.** Le plan dit : « Si Jit est inaccessible, […] noter
P4 comme bloqué et demander une solution d’accès ou un ajustement au
professeur. Une imitation de Jit ne remplace pas le travail demandé. »
L’ajustement a été demandé : **le professeur a validé le 6 novembre 2026 la
reproduction open source du plan Jit comme substitut à Jit**. P4 est donc
**réalisée par substitution validée**. La validation a été communiquée par
le responsable de l’audit ; sa trace écrite (courriel ou compte rendu) est à
joindre au dossier de soutenance. La substitution porte sur les **contrôles**
du plan. Les fonctions propres à Jit (déduplication, priorisation, backlog)
restent absentes ([comparaison § 7](jit/comparaison-trivy-plan-jit.md#7-limites)),
et les résultats restent présentés comme ceux des outils open source, pas
comme des résultats Jit.

## 2. Constats

### Trivy

| Mesure | Valeur | Preuve |
|---|---|---|
| Rapport initial `v20.3.0` (20 octobre 2026) | 98 détections : 11 CRITICAL, 27 HIGH, 49 MEDIUM, 11 LOW | [20](analysis/20-bilan-scan-initial.md) |
| Même image, base du 4 novembre | 124 détections (+28 / −2 par la seule base) | [contre-audit § 5](contre-audit.md#5-pourquoi-124-détections-aujourdhui-contre-98-au-départ) |
| Image corrigée, dépendances et base figées | **105** : 9 CRITICAL, 22 HIGH, 62 MEDIUM, 11 LOW, 1 UNKNOWN; **19 supprimées, toutes par les corrections, 0 ajoutée** | [contre-audit § 4](contre-audit.md#4-trivy-avant--après) |
| Secrets (audit initial) | 5 détections dans l’image, dont la clé JWT codée en dur | [secrets](secrets/rapport-partageable.md) |
| Mauvaises configurations (audit initial) | 66, dont 48 dans des exemples pédagogiques | [misconfigurations](misconfigurations/rapport-partageable.md) |

### Plan Jit reproduit (outils open source, pas Jit)

| Contrôle | Référence `v20.3.0` | Corrigé | Apport principal |
|---|---:|---:|---|
| SAST Semgrep | 43 | 46 | Injections SQL, `eval`, lecture de fichiers, listages : **invisibles pour Trivy** |
| SCA OSV-Scanner | 0 (pas de lockfile) | 67 | 59 avis communs avec Trivy |
| Secrets Gitleaks | 69 | 66 | Clé F-002 disparue |
| IaC KICS | 219 | 219 | Docker Compose et OpenAPI, hors du périmètre Trivy |
| Dockerfile Trivy | 7 | 5 | `HEALTHCHECK` et tag figé corrigés |

Détail : [comparaison Trivy / plan Jit reproduit](jit/comparaison-trivy-plan-jit.md).

## 3. Corrections vérifiées

| Constat | Correction | Vérification | Preuve |
|---|---|---|---|
| [F-001](findings/F-001-jwt-algorithm-confusion.md) confusion d’algorithme JWT | `express-jwt` 8, `jsonwebtoken` 9, `jws` 4; RS256 seul accepté | Jetons `alg: none` et HS256 forgés : HTTP 200 avant, **401** après | [contre-audit § 2](contre-audit.md#2-corrections-vérifiées), `reports/contre-audit/jwt-fonctionnel-*.json` |
| [F-002](findings/F-002-cle-privee-jwt-codee-en-dur.md) clé privée codée en dur | Clé fournie à l’exécution ou paire RSA-2048 éphémère | Jeton forgé avec l’ancienne clé : **401**; absente pour Semgrep, Gitleaks et Trivy | idem, [comparaison § 3](jit/comparaison-trivy-plan-jit.md#3-constats-communs-avec-trivy) |
| [F-003](findings/F-003-jetons-sans-expiration.md) jetons sans expiration | `jsonwebtoken` 9 applique `expiresIn` | `exp − iat = 6 h`; jeton expiré refusé (**401**) | [contre-audit § 2](contre-audit.md#2-corrections-vérifiées) |
| [13](analysis/13-file-type.md) CVE-2026-31808 (`file-type`) | 21.3.4 | Absente du scan; envoi d’image inchangé | [contre-audit § 2](contre-audit.md#2-corrections-vérifiées) |
| DS-0026 / DS-0001 (Dockerfile) | `HEALTHCHECK`; base épinglée par digest | Conteneur `healthy`; absents du scan Dockerfile | idem |
| Tags d’actions non figés (`audit-trivy.yml`) | Actions épinglées par SHA | Semgrep : 4 constats → 0 | [PR #2 du fork](https://github.com/othmane1244/juice-shop/pull/2) |

Non-régression : `tsc` et ESLint sans erreur, tests serveur 417/417, tests
d’intégration 545/545. Les 7 tests qui attendaient le **succès** des attaques
JWT ont été inversés.

## 4. Risques résiduels

| Risque | Atteignable ? | Correctif disponible ? | Effet sur la décision |
|---|---|---|---|
| **MarsDB** 0.6.11, GHSA-5mrr-rgp6-x4gr (CRITICAL) : sélecteurs `$where` construits à partir des routes puis passés au constructeur `Function` | **Oui** (fiches [07](analysis/07-marsdb.md), [21](analysis/21-synthese-des-risques.md)) | **Non** : avis sur toutes les versions, dépôt archivé | **Bloquant en exposition réelle** |
| **3 CRITICAL sans correctif** : `decompress` 4.2.1 (CVE-2026-101894, CVE-2026-53486) et MarsDB ci-dessus | `decompress` : chargé au démarrage, aucune extraction observée ([05](analysis/05-archives.md)) | Non | Suivi manuel; la CI ne les bloque pas (règle « pas de correctif = pas de blocage ») |
| **Défis volontaires de Juice Shop** relevés par Semgrep : injection SQL à la connexion et à la recherche, `eval` sur le profil, redirection ouverte, lecture de fichiers, listages de `/ftp`, `/encryptionkeys`, `/support/logs` | **Oui, sans authentification** pour la plupart | Non applicable : c’est la raison d’être de l’application | **Bloquant en exposition réelle**; attendu pour une cible d’entraînement |
| `hbs` 4.3.1, CVE-2021-32822 | Oui, authentifié (`/dataerasure`) | Non | Même chemin que le défi `layout` |
| `body-parser` 1.20.8, CVE-2026-111181 (HIGH) | Oui, sans authentification; plantage non reproduit | **Oui** (1.20.9) | À corriger en priorité ([22](analysis/22-nouvelles-detections.md)) |
| 28 exceptions CI (`.trivyignore.yaml`) | Variable, voir chaque entrée | Oui pour les 28 (seules les vulnérabilités corrigeables sont dans la ligne de base) | Revue obligatoire au **31 décembre 2026** |
| Clé éphémère par défaut, pas de révocation des jetons (6 h) | — | Configuration | Fournir `JWT_PRIVATE_KEY_FILE` en déploiement |

### Le filtre « sans correctif » respecte-t-il le plan ?

Le plan interdit d’« utiliser un filtre supprimant les vulnérabilités sans
correctif pour améliorer artificiellement le bilan ». Ici, `--ignore-unfixed`
ne sert **qu’à la politique de blocage** de la CI, que le plan demande de
séparer de la collecte. **Tous les bilans de ce dossier comptent les
vulnérabilités sans correctif** (124 et 105 détections), et les rapports
complets sont gardés en artefacts à chaque exécution. Le risque est
consigné au [contre-audit § 7](contre-audit.md#7-risques-résiduels-acceptés).

## 5. Verdict argumenté

**Exposition réelle (Internet, réseau d’entreprise, données réelles) :
livraison bloquée.** L’audit est valide sur son périmètre Trivy et ses
corrections sont prouvées. Mais des défauts confirmés, atteignables et
graves restent sans traitement autorisé pour ce contexte : injections SQL
non authentifiées, `eval`, MarsDB sans correctif possible, listage de
`/encryptionkeys`. Aucune exception ne peut couvrir ces défauts en
production : ils font partie du fonctionnement de Juice Shop.

**Cible d’entraînement isolée : acceptable, sous conditions.** Pour ce
contexte, ces défauts sont **l’objet même de l’application** et sont
documentés. Les corrections de l’audit (F-001 à F-003, `file-type`,
`HEALTHCHECK`) sont vérifiées sans régression fonctionnelle. Les exceptions
ont un motif, un périmètre, un responsable et une échéance.

**Validité.** Les contrôles obligatoires sont terminés :
- Trivy ;
- Jit par substitution validée par le professeur le 6 novembre 2026 ;
- protection de branche démontrée par un refus réel de fusion (T06).

L’audit est donc **valide**. Selon les issues prévues par le plan, le
verdict est :
- **livraison bloquée** pour l’exposition réelle ;
- **sous conditions** pour la cible d’entraînement isolée.

Il doit être présenté comme un audit « Trivy et plan Jit reproduit », pas
comme un audit réalisé avec la plateforme Jit. Les limites du blocage
(propriétaire administrateur, vulnérabilités sans correctif) sont décrites
dans la [démonstration](demonstration-blocage.md#5-limites).

## 6. Conditions

### Pour maintenir l’acceptation comme cible d’entraînement

1. Exécution **isolée** : écoute sur `127.0.0.1` ou sur un réseau de
   laboratoire sans accès entrant depuis Internet, sans données réelles.
2. Clé de signature fournie par `JWT_PRIVATE_KEY_FILE` si plusieurs
   instances ou redémarrages doivent conserver les sessions.
3. Revue des 28 exceptions au plus tard le **31 décembre 2026**.
4. `body-parser` mis à jour vers 1.20.9 à la prochaine série de
   corrections.

### Pour lever la réserve de validité

1. ~~Obtenir l’accès à Jit, ou faire valider par le professeur la
   reproduction open source comme ajustement de P4.~~ **Fait le 6 novembre
   2026** (validation du professeur ; trace écrite à joindre).
2. ~~Activer la protection de branche sur `audit/corrections`, avec
   « Audit Trivy » obligatoire, et démontrer qu’une PR qui réintroduit une
   dépendance vulnérable est refusée (cas T06 du plan).~~ **Fait le
   6 novembre 2026** ([démonstration](demonstration-blocage.md)).

Ces deux conditions étant remplies, la réserve de validité est levée.
Pour la maintenir : garder la protection active et ne pas ajouter
d’exception au `.trivyignore.yaml` sans motif, responsable et échéance.

### Pour passer à « livrable en exposition réelle »

1. Corriger les injections SQL (requêtes paramétrées), supprimer l’`eval`,
   valider les chemins de `res.sendFile` et la redirection.
2. Supprimer les listages `/ftp`, `/encryptionkeys` et `/support/logs`.
3. Remplacer MarsDB et ne plus passer de données de requête aux options de
   rendu `hbs`.
4. Désactiver les défis, ou livrer une autre application : en pratique,
   c’est cesser d’être Juice Shop.
5. Refaire le contre-audit complet (Trivy, plan reproduit, tests) **sans
   exception CRITICAL/HIGH atteignable**.

Ces trois derniers points montrent que, pour Juice Shop, l’exposition réelle
n’est pas un objectif atteignable : le verdict « non livrable » est
structurel, pas provisoire.
