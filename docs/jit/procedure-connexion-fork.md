# Procédure — connecter Jit au seul fork `othmane1244/juice-shop`

> **Non exécutée.** Le 5 novembre 2026, jit.io est inaccessible : voir
> [acces-bloque.md](acces-bloque.md). Le plan a été reproduit avec des outils
> open source ([comparaison](comparaison-trivy-plan-jit.md)). Cette
> procédure reste valable si le service redevient disponible.

Préparée le 4 novembre 2026, à exécuter par le responsable de l’audit. Elle
complète l’étude [README.md](README.md) (29 octobre) et en applique les
règles. **Rien n’a été connecté** à la date de rédaction.

Sources : documentation Jit (pages citées en fin de document), consultée le
4 novembre 2026 via un moteur de recherche. `docs.jit.io` ne se résolvait
pas depuis le réseau du poste ce jour-là, d’où l’impossibilité de relire les
pages en entier. **Comparer chaque écran réel à ce document et s’arrêter en
cas d’écart.**

## 0. Avant de commencer : trois décisions déjà prises

| Sujet | Décision | Raison |
|---|---|---|
| Dépôts autorisés | **Uniquement `othmane1244/juice-shop`**. | Le dépôt d’audit `othmane1244/devsecops-application-security-audit` est sur **le même compte** et contient des rapports bruts : il ne doit pas être sélectionné. |
| Détection de secrets | Acceptée sur le fork. | Jit l’active d’office et lance le premier scan dès la connexion. Les seules clés du fork sont publiques depuis des années dans le dépôt amont (clé JWT de l’historique, clé du défi Terraform). Aucun secret de l’équipe n’est dans le fork. |
| Ce qui part chez Jit | Constats et métadonnées seulement. | Ne jamais téléverser de JSON Trivy, de SBOM ou de rapport de secrets du dépôt d’audit (règle du README). |

## 1. Préparer le fork (5 min, avant Jit)

La branche par défaut `master` du fork est le `master` **actuel** du projet
amont (commit `717f5ef` du 23 octobre 2026, préparation de v20.4.0), pas
`v20.3.0`. Le scan initial de Jit, qui porte sur la branche par défaut,
analyserait donc une autre version que celle de l’audit. Avant de connecter
Jit :

1. Créer une branche de référence sur le code audité, sans correction :

   ```sh
   cd juice-shop-fork
   git push origin f189f52:refs/heads/audit/base-v20.3.0
   ```

2. Dans GitHub → `othmane1244/juice-shop` → **Settings → General → Default
   branch**, choisir `audit/corrections`.
   Effet secondaire : les workflows `pull_request_target` et
   `issue_comment` liront alors les fichiers de `audit/corrections`. Les
   workflows hérités qui s’y enregistreront sont à désactiver (procédure du
   [contre-audit, section 6](../contre-audit.md#workflows-hérités-du-projet-amont)).

Ainsi : scan initial = code corrigé; scan manuel de `audit/base-v20.3.0` =
avant correction. La comparaison avant/après Jit porte sur le même couple
que Trivy.

## 2. Créer le compte Jit

1. Depuis `https://www.jit.io`, ouvrir la connexion à la plateforme et
   choisir l’authentification **GitHub**, avec le compte `othmane1244`
   (adresse et libellés non revérifiés le 4 novembre : suivre ceux du site).
2. L’écran d’autorisation **OAuth** (identification) est distinct de
   l’installation de l’application : il ne doit demander que l’identité
   (profil, e-mail). S’il demande l’accès aux dépôts à ce stade, refuser.

## 3. Installer l’application GitHub Jit (point critique)

1. Lors de l’onboarding, Jit propose d’installer **Jit Security** sur un
   compte : choisir **`othmane1244`** (compte personnel, pas d’organisation).
2. Sur l’écran GitHub « Install Jit » :
   - cocher **Only select repositories**;
   - sélectionner **`othmane1244/juice-shop`** et rien d’autre.
   - **Ne pas** choisir « All repositories » : la documentation indique
     qu’avec ce choix, les dépôts futurs sont aussi analysés automatiquement.
3. Comparer les permissions affichées à ce tableau, issu de la documentation
   Jit (« Connect Jit with your GitHub Account ») :

   | Permission | Accès attendu | Usage annoncé par Jit | À accepter ? |
   |---|---|---|---|
   | Administration | Lecture | Voir la création/suppression de dépôts | Oui |
   | Issues | Lecture | — | Oui |
   | Metadata | Lecture | Métadonnées des dépôts (obligatoire pour toute app) | Oui |
   | Actions | Lecture et écriture | Déclencher les workflows de scan | Oui |
   | Checks | Lecture et écriture | Créer/mettre à jour les checks de PR | Oui |
   | Pull requests | Lecture et écriture | Commenter, ouvrir des PR | Oui |
   | Workflows | Lecture et écriture | Modifier des fichiers de workflow | Oui, mais relire toute modification (étape 5) |
   | Contents | Lecture et écriture | Lire le code; ouvrir des PR de correction sur une nouvelle branche | Oui, mais aucune fusion automatique |
   | Members | Lecture | Équipes et membres | Oui (sans effet sur un compte personnel) |
   | Deployments | Lecture et écriture (annoncé comme fonction future) | Bloquer des déploiements | Accepter seulement s’il est demandé; noter sa présence |

   **Arrêter et ne pas installer** si l’écran demande en plus, par exemple :
   écriture sur Administration, Secrets, Environments, Pages, Packages,
   Members ou Organization, ou l’accès à d’autres dépôts.
4. Faire une capture de l’écran des permissions et de la liste des dépôts
   choisis : preuves pour le rapport (voir étape 8).
5. Si Jit propose ou crée un **dépôt de configuration** ou ouvre une PR
   ajoutant un workflow : noter le nom du dépôt et le contenu, ne rien
   fusionner sans relecture, et ne **jamais** choisir le dépôt d’audit.

## 4. Ne pas fournir de jeton personnel (PAT)

Le **GitHub Security Plan** de Jit demande un PAT classique avec les
portées `repo`, `read:repo_hook`, `read:org`, `read:enterprise` et
`read:packages`. `repo` donne un accès complet à **tous** les dépôts du
compte, y compris le dépôt d’audit. **Ne pas créer ce jeton.** Le contrôle
de protection de branche reste disponible sans PAT d’après la documentation
(voir README, tableau des capacités).

## 5. Premier scan

D’après la documentation, le premier scan démarre **dès la connexion** et
la détection de secrets est **activée automatiquement**. Rien à faire,
sinon :

1. Dans GitHub → `othmane1244/juice-shop` → **Actions**, vérifier quels
   workflows Jit se lancent et sur quelle branche (attendu :
   `audit/corrections` si l’étape 1 a été faite).
2. Le fork étant **public**, les minutes GitHub Actions sur runners
   standards sont gratuites : pas de problème de quota.

## 6. Plan à activer

Le compte gratuit (« Starter ») est annoncé pour **1 développeur** sur la
fiche GitHub Marketplace et pour **3 développeurs** sur des pages Jit :
dans les deux cas, un compte personnel suffit. Vérifier sur
`https://www.jit.io/pricing` qu’aucun paiement n’est demandé.

1. Menu **ASPM → Security Plans** (libellé possible : **Plans**).
2. Choisir le **Minimal Viable Security Plan** (« MVS »). D’après la
   documentation, il couvre SAST, SCA, IaC, Kubernetes et sécurité CI/CD;
   le plan **Max** couvre tous les contrôles, y compris ceux qui demandent
   des accès cloud ou une application déployée.
3. Activer :

   | Élément | Outil annoncé | Pourquoi |
   |---|---|---|
   | Scan du code (SAST) | Semgrep | Comparer à F-001/F-002 et à CodeQL. |
   | Scan des dépendances (SCA) | OSV-Scanner | Comparer au lock et à Trivy. |
   | Secrets dans le code | Gitleaks | Déjà actif; vérifier qu’il trouve la clé Terraform. |
   | IaC | KICS | Le fork contient du Terraform (`terraform/`, `infrastructure/terraform/`). |
   | Dockerfile | Trivy (config) | Doit **ne plus** signaler l’absence de `HEALTHCHECK` sur `audit/corrections`. |
   | Protection de branche | contrôle Jit | Sans PAT; utile pour l’étape suivante de la feuille de route. |

4. Laisser **désactivés** : DAST (pas d’application déployée), contrôles
   cloud (AWS/GCP/Azure), tout élément qui demande un PAT, la remédiation
   automatique et les intégrations Slack/Jira.

## 7. Scanner la branche de référence

Après le scan initial, lancer un **scan manuel de branche** sur
`audit/base-v20.3.0` (fonction « Manual Branch Scanning », depuis la page
du dépôt dans Jit ou via son API). Noter l’identifiant et la date des deux
scans.

## 8. Exporter les résultats

1. Page **Backlog** (gestion des vulnérabilités) → filtrer sur le dépôt
   `juice-shop` → bouton **Export CSV** (en haut à droite). Faire un export
   par branche si le filtre le permet, sinon un seul export avec la colonne
   branche.
2. Où ranger :

   | Élément | Emplacement | Versionné ? |
   |---|---|---|
   | CSV brut | `reports/jit/brut/` dans le dépôt d’audit | **Non** : ajouter `reports/jit/brut/` au `.gitignore` **avant** l’export. Le CSV peut contenir des extraits de code et la valeur des clés détectées. |
   | Captures (permissions, dépôts choisis, plan, scans) | `docs/jit/captures/` | Oui, après vérification qu’aucune valeur de secret n’est visible. |
   | Synthèse | `docs/jit/resultats-AAAA-MM-JJ.md` | Oui. |

3. Contenu de la synthèse, sur le modèle de
   [secrets/rapport-partageable.md](../secrets/rapport-partageable.md) :
   date, plan et éléments activés, commits analysés (`f189f52` et
   `audit/corrections`), nombre de constats par contrôle et par gravité,
   rapprochement **qualitatif** avec F-001 à F-003, la fiche 22 et Trivy
   (ce que Jit trouve en plus ou ne trouve pas), sans additionner les
   alertes des deux outils et sans recopier de valeur de secret.

## 9. Retour arrière

- Retirer l’accès : GitHub → **Settings → Applications → Installed GitHub
  Apps → Jit → Configure** → retirer `juice-shop` ou **Uninstall**.
- Supprimer toute branche, PR ou dépôt de configuration créé par Jit.
- Remettre la branche par défaut du fork si elle a été changée.

## Sources

Consultées le 4 novembre 2026; les écrans réels font foi.

- [Connect Jit with your GitHub Account](https://docs.jit.io/docs/integrating-with-github) — permissions, sélection des dépôts, scans dans GitHub Actions.
- [GitHub Security Plan](https://docs.jit.io/docs/github-security-plan) — PAT et portées.
- [Onboarding Overview](https://docs.jit.io/docs/welcome-to-onboarding) — premier scan à la connexion.
- [Secrets Detection](https://docs.jit.io/docs/scan-code-for-hard-coded-secrets) — activation automatique, réglage depuis la page Plan.
- [Product Security Plans](https://docs.jit.io/v4.7.1/docs/security-plans) et [Jit Max Security Plan](https://docs.jit.io/docs/jit-max-security-plan) — contenu des plans.
- [Manual Branch Scanning](https://docs.jit.io/docs/manual-branch-scan).
- [Vulnerability management (Backlog)](https://docs.jit.io/docs/jit-backlog) — export CSV.
- [Pricing](https://www.jit.io/pricing) et [Jit Security sur GitHub Marketplace](https://github.com/marketplace/jit-security) — offre gratuite.
