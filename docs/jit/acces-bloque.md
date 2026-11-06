# Jit inaccessible — constat et solution retenue

Rédigé le 5 novembre 2026, mis à jour le 6 novembre 2026.

> **Statut de P4 : réalisée par substitution validée par le professeur le
> 6 novembre 2026.** Le professeur a accepté la reproduction open source du
> plan Jit comme substitut à Jit. La validation a été communiquée par le
> responsable de l’audit ; sa trace écrite est à joindre au dossier.

**Jit n’a jamais été connecté** dans cet audit : la
[procédure de connexion](procedure-connexion-fork.md) n’a pas pu être
exécutée. Les contrôles de son plan « Minimal Viable Security » ont été
**reproduits avec les outils open source qu’il orchestrait**
([comparaison](comparaison-trivy-plan-jit.md)). Ce n’est **pas** Jit : la
substitution validée porte sur les contrôles, pas sur les fonctions propres
à la plateforme (section 3).

## 1. Constat technique

### DNS

| Date (UTC) | Résolveur | Nom | Réponse |
|---|---|---|---|
| 2026-11-04 | DNS du réseau local (`10.19.66.106`) | `docs.jit.io` | `Non-existent domain` (NXDOMAIN) |
| 2026-11-05 17:08 | DNS du réseau local | `jit.io` | résolu |
| 2026-11-05 17:08 | DNS du réseau local | `www.jit.io`, `docs.jit.io`, `platform.jit.io` | NXDOMAIN |
| 2026-11-05 | Cloudflare `1.1.1.1` (DNS sur HTTPS) | `www.jit.io`, `docs.jit.io` | `Status: 3` (NXDOMAIN); autorité `pdns1.registrar-servers.com`, SOA `hostmaster.registrar-servers.com`, série `1789881361` |

Le résolveur public de Cloudflare donne la même réponse que le résolveur
local : **ce n’est pas un filtrage du réseau du poste**, contrairement à
l’hypothèse faite le 4 novembre. Les sous-domaines n’existent plus dans la
zone `jit.io`, désormais servie par les serveurs DNS par défaut du registrar
(`registrar-servers.com`), ce qui correspond habituellement à un domaine
dont l’hébergement DNS n’est plus configuré. Cette dernière interprétation
n’est pas vérifiée auprès de Jit.

### HTTP

Le 5 novembre 2026 : `curl` vers `https://www.jit.io`, `https://docs.jit.io`
et `https://platform.jit.io` échoue avec le code 6 (« Could not resolve
host »), sans aucune réponse HTTP.

### Service de supervision tiers

- Selon le responsable de l’audit, `jit.io` est en panne **pour tous les
  utilisateurs depuis plus d’une semaine** d’après isitdownrightnow.
- Page relue le 5 novembre 2026
  ([isitdownrightnow.com/jit.io.html](https://www.isitdownrightnow.com/jit.io.html)) :
  « jit.io is down for us too ».
- La durée exacte de la panne n’est pas lisible dans le texte extrait de la
  page; elle repose sur l’observation du responsable.

## 2. Contexte : rachat par Torq

- Le **19 mai 2026**, Torq (plateforme d’automatisation de SOC) a annoncé le
  rachat de Jit, pour un montant non communiqué.
- Selon la presse, l’objectif est d’intégrer à la plateforme SOC de Torq le
  « graphe de contexte » IA de Jit. Ce n’est pas l’offre de sécurité
  applicative destinée aux développeurs.
- Les articles consultés ne disent pas ce que devient le produit AppSec
  autonome; l’un indique une intégration des capacités de Jit à Torq
  « dans les prochains mois ».
- **Aucune source consultée n’annonce l’arrêt du service.** Le lien entre
  le rachat et l’indisponibilité est une hypothèse.

Sources :

- [Annonce Torq — « Torq Acquires Jit… »](https://torq.io/news/torq-acquires-jit/).
  L’adresse indiquée au départ, `torq.io/blog/torq-acquires-jit`, n’a pas été
  retrouvée; l’annonce officielle trouvée est publiée dans la rubrique
  *news*.
- [SiliconANGLE, 19 mai 2026 — « Torq acquires AI security startup Jit… »](https://siliconangle.com/2026/05/19/torq-acquires-ai-security-startup-jit-add-context-graphs-soc-platform/).
- [Business Wire, communiqué du 19 mai 2026](https://www.businesswire.com/news/home/20260519044833/en/Torq-Acquires-Jit-to-Unleash-the-First-Enterprise-AI-SOC-Context-Graphand-Rewrite-the-Future-of-SecOps).
- [SC Media — « Torq acquires Jit.io… »](https://www.scworld.com/brief/torq-acquires-jit-io-to-enhance-ai-driven-security-operations).

Ces pages ont été consultées par un moteur de recherche le 5 novembre 2026;
leur contenu n’a pas été archivé.

## 3. Conséquences pour l’audit

| Élément prévu | Situation |
|---|---|
| Connexion de l’app GitHub Jit au fork | Impossible. Rien n’a été installé, aucune permission accordée, aucune donnée transmise à Jit. |
| Plan « Minimal Viable Security » | **Reproduit**, substitution validée par le professeur le 6 novembre 2026, par le workflow `.github/workflows/plan-jit-oss.yml` du fork, avec les outils que Jit documentait pour ce plan : Semgrep (SAST), OSV-Scanner (SCA), Gitleaks (secrets), KICS (IaC), Trivy (Dockerfile). |
| Fonctions propres à Jit | **Non reproduites** : backlog centralisé, déduplication et priorisation des constats entre outils, contexte d’exécution (« context graph »), PR de remédiation, contrôles de posture GitHub. |
| Export CSV du backlog | Remplacé par les SARIF (onglet Security du fork) et les JSON en artefacts, copiés dans `reports/plan-jit-oss/`. |

Les règles et versions exactes que Jit aurait appliquées ne sont pas
connues : la reproduction utilise les jeux de règles demandés
(`p/javascript`, `p/typescript`, `p/owasp-top-ten` pour Semgrep) et les
réglages par défaut des autres outils. Ses résultats ne doivent pas être
présentés comme des résultats Jit.
