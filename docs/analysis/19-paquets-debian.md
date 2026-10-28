# 19 — Paquets Debian

## Résumé

Le rapport initial du 20 octobre 2026 contient 31 occurrences Debian `affected` (25 CVE distinctes) sur six paquets binaires de Debian 13.7 / Trixie : 21 occurrences `libc6`, 8 occurrences réparties sur quatre binaires issus de `gcc-14`, et 2 occurrences `zlib1g`. Toutes ont `FixedVersion: null`; cela décrit la sortie Trivy, pas l’absence d’un correctif Debian. Le Security Tracker consulté le 28 octobre confirme plusieurs statuts vulnérables pour Trixie, y compris avec les révisions Debian complètes; il classe également huit anciens avis glibc comme « open unimportant ». Deux résultats glibc présentent une limite de vérification dans le Tracker.

Cette analyse établit l’état des métadonnées du rapport et les états affichés aujourd’hui par les pages officielles consultées. Elle ne démontre ni l’exploitation ni l’état historique du Tracker au jour du scan.

## Périmètre et méthode

| Preuve | Constat |
|---|---|
| P-01 — `reports/trivy-image-initial.json`, métadonnées du rapport | `CreatedAt: 2026-10-20T11:28:17.521956103Z`; Trivy 0.76.0; cible Debian 13.7. La distribution correspond à la suite `trixie` du Security Tracker. |
| P-02 — même rapport, findings Debian aux lignes 2215–3979 | 31 enregistrements complets; chaque occurrence porte `Status: affected` et `FixedVersion: null`. Les sévérités et répétitions sont reprises ci-dessous. |
| P-03 — inventaire Debian du même rapport | `PkgPath` est absent pour ces paquets. Le JSON donne le binaire installé, son `PkgID`/`InstalledVersion`, `SrcName` et `SrcVersion`; il ne constitue pas une inspection des fichiers de l’image. |
| P-04 — Security Tracker Debian | Les pages source et CVE sont des données évolutives. Les statuts ci-dessous sont ceux consultés le 28 octobre 2026. Le site indique que ses données proviennent du dépôt de suivi de l’équipe sécurité Debian ([présentation du Tracker](https://security-tracker.debian.org/tracker/)). |

### Occurrences du rapport initial

Le suffixe `+b1` de `zlib1g` appartient à la version binaire. La version source Debian `zlib` affichée par le Tracker n’a pas ce suffixe. De même, `SrcVersion` seule n’est pas une comparaison suffisante : les révisions Debian et l’état par suite déterminent le statut de correction.

| Source Debian | Binaire et version complète installée | Occurrences (CVE, sévérité Trivy) | Champs Trivy |
|---|---|---|---|
| `glibc` (`SrcVersion: 2.41`) | `libc6` `2.41-12+deb13u4` | 13 MEDIUM : [CVE-2026-18374](https://security-tracker.debian.org/tracker/CVE-2026-18374), [19499](https://security-tracker.debian.org/tracker/CVE-2026-19499), [19542](https://security-tracker.debian.org/tracker/CVE-2026-19542), [5435](https://security-tracker.debian.org/tracker/CVE-2026-5435), [6238](https://security-tracker.debian.org/tracker/CVE-2026-6238), [6368](https://security-tracker.debian.org/tracker/CVE-2026-6368), [6791](https://security-tracker.debian.org/tracker/CVE-2026-6791), [77117](https://security-tracker.debian.org/tracker/CVE-2026-77117), [80489](https://security-tracker.debian.org/tracker/CVE-2026-80489), [8674](https://security-tracker.debian.org/tracker/CVE-2026-8674), [86805](https://security-tracker.debian.org/tracker/CVE-2026-86805), [89092](https://security-tracker.debian.org/tracker/CVE-2026-89092), [95818](https://security-tracker.debian.org/tracker/CVE-2026-95818). | Toutes `affected`; aucune `FixedVersion`. |
| `glibc` (`SrcVersion: 2.41`) | `libc6` `2.41-12+deb13u4` | 8 LOW : [CVE-2010-4756](https://security-tracker.debian.org/tracker/CVE-2010-4756), [CVE-2018-20796](https://security-tracker.debian.org/tracker/CVE-2018-20796), [CVE-2019-1010022](https://security-tracker.debian.org/tracker/CVE-2019-1010022), [CVE-2019-1010023](https://security-tracker.debian.org/tracker/CVE-2019-1010023), [CVE-2019-1010024](https://security-tracker.debian.org/tracker/CVE-2019-1010024), [CVE-2019-1010025](https://security-tracker.debian.org/tracker/CVE-2019-1010025), [CVE-2019-9192](https://security-tracker.debian.org/tracker/CVE-2019-9192), [CVE-2026-97399](https://security-tracker.debian.org/tracker/CVE-2026-97399). | Toutes `affected`; aucune `FixedVersion`. |
| `gcc-14` (`SrcVersion: 14.2.0`) | `gcc-14-base`, `libgcc-s1`, `libgomp1`, `libstdc++6`, chacun `14.2.0-19` | 2 CVE par binaire : CVE-2026-102010 et CVE-2026-95619, chacune MEDIUM. **8 occurrences conservées** (4 binaires × 2 avis). | Toutes `affected`; aucune `FixedVersion`. |
| `zlib` (`SrcVersion: 1.3.dfsg+really1.3.1`) | `zlib1g` `1:1.3.dfsg+really1.3.1-1+b1` | 2 MEDIUM : [CVE-2026-27171](https://security-tracker.debian.org/tracker/CVE-2026-27171), [CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-85091). | Toutes `affected`; aucune `FixedVersion`. |

Le rapport HIGH/CRITICAL ne signale aucune de ces occurrences : elles sont MEDIUM ou LOW dans le rapport initial. Le tableau ci-dessus regroupe les avis communs sans réduire le nombre d’installations binaires touchées par chaque avis GCC.

## Comparaison avec Debian Trixie

### `glibc` / `libc6` — 21 occurrences

La page du paquet source [`glibc`](https://security-tracker.debian.org/tracker/source-package/glibc) et les fiches CVE individuelles consultées classent les huit CVE LOW suivantes comme vulnérables dans Trixie mais « unimportant » : CVE-2010-4756, CVE-2018-20796, CVE-2019-1010022, CVE-2019-1010023, CVE-2019-1010024, CVE-2019-1010025 et CVE-2019-9192. Le Tracker documente notamment que les CVE de 2019 concernent des contournements de mitigations que l’amont ne traite pas comme des problèmes de sécurité; pour CVE-2010-4756, il précise qu’il s’agit du comportement POSIX de `glob` et que les applications doivent limiter elles-mêmes les motifs. La sévérité LOW de Trivy ne doit donc pas être lue comme un avis Debian de correction imminente.

Pour les MEDIUM, les fiches consultées déclarent Trixie vulnérable pour CVE-2026-18374, -19499, -19542, -5435, -6238, -6368, -6791, -77117, -80489, -86805 et -95818. Certains avis portent la note `<no-dsa>` (dont CVE-2026-86805 et -95818, « Minor issue »); cela n’équivaut pas à « corrigé ». La page glibc indexée par le Tracker énumère explicitement parmi ses problèmes ouverts Trixie CVE-2026-18374, -19499, -19542, -5435, -6238, -6368, -6791, -77117 et -80489.

Deux réserves de qualité des données :

- **CVE-2026-89092 : avis repérable, applicabilité Trixie non vérifiable ici.** La fiche Debian décrit un débordement de pile dans `nscd`, sous conditions (service activé, DNS non fiable et réponse suffisamment grande), mais la page récupérée ne contient pas de tableau des versions/statuts par suite. L’image n’a pas été inspectée pour établir si `nscd` est installé/activé. Le finding Trivy `libc6` ne suffit pas à confirmer que ce composant est utilisé.
- **CVE-2026-8674 : incohérence/non-vérification.** Le finding existe dans le JSON, mais aucune fiche CVE Debian correspondante n’a été retrouvée dans les résultats du Tracker consultés. Il est donc impossible d’en déduire un statut Debian Trixie ou une version corrigée. L’absence de fiche trouvée n’établit pas que le paquet est sain ni que le CVE est invalide.

Le Tracker expose un écart de révision entre vues : la page source glibc indexée indique `2.41-12+deb13u3`, tandis que plusieurs fiches individuelles actuelles indiquent `2.41-12+deb13u4`, version binaire présente dans le rapport. Pour les CVE vérifiées, les fiches individuelles maintiennent le statut Trixie `vulnerable` pour cette révision exacte; aucun correctif rétroporté applicable à ces avis n’est indiqué dans le champ de statut. Cette divergence de page/vues interdit d’affirmer une version courante unique du paquet à partir de la seule page source, mais ne transforme pas la version signalée en version corrigée.

### Famille `gcc-14` — 8 occurrences

La page Debian du source [`gcc-14`](https://security-tracker.debian.org/tracker/source-package/gcc-14) indique pour Trixie exactement `14.2.0-19`; elle classe CVE-2026-102010 et CVE-2026-95619 `vulnerable (no DSA)`. Le statut correspond donc à la version Debian complète du rapport, sans présumer qu’un changement du numéro amont aurait corrigé les binaires. Les deux avis sont reproduits pour `gcc-14-base`, `libgcc-s1`, `libgomp1` et `libstdc++6` : cela représente huit détections binaires mais deux avis du paquet source. Dans le Tracker, les versions forky/sid corrigées sont `14.4.0-3`; elles ne sont pas la version installée dans l’image. « no DSA » décrit le traitement de l’avis par Debian, non une absence de détection.

### `zlib` / `zlib1g` — 2 occurrences

La page source Debian [`zlib`](https://security-tracker.debian.org/tracker/source-package/zlib) donne Trixie `1:1.3.dfsg+really1.3.1-1` et marque les deux avis vulnérables. Le binaire du rapport est `1:1.3.dfsg+really1.3.1-1+b1`; `+b1` est une reconstruction binaire de la même révision source et ne démontre pas l’application d’un correctif de sécurité.

- CVE-2026-27171 : Trixie est `vulnerable (no DSA)`; le Tracker donne la version corrigée en forky `1:1.3.dfsg+really1.3.2-3` et en sid `…-4`. L’avis porte sur `crc32_combine64` / `crc32_combine_gen64`; le Tracker marque l’issue mineure sans DSA pour Trixie.
- CVE-2026-85091 : Trixie est `vulnerable`; la page source actuelle indique la correction en sid, sans correction Trixie visible dans la ligne consultée.

La comparaison Debian prend ainsi en compte l’époque `1:`, le suffixe Debian `dfsg+really`, la révision source et la révision binaire. Une comparaison limitée au numéro amont « 1.3.1 » ou à la borne amont de l’avis donnerait une conclusion insuffisante.

## Scan du 20 octobre et état consulté le 28 octobre 2026

À la date du scan, la seule preuve historique disponible ici est le rapport initial : il classe les 31 occurrences `affected` et ne fournit aucun `FixedVersion`. Les pages du Security Tracker sont des pages dynamiques et l’interface consultée ne fournit pas d’instantané historique du 20 octobre; je ne projette donc pas les statuts visibles aujourd’hui sur cette date. La page actuelle de glibc montre même des révisions différentes selon la vue consultée, ce qui renforce cette limite temporelle.

Au 28 octobre, le Tracker confirme les statuts Trixie vulnérables décrits plus haut pour les CVE vérifiées. Les versions corrigées annoncées pour forky/sid sont des versions de ces suites; elles ne corrigent pas rétroactivement les paquets Trixie présents. Aucun correctif Trixie n’est déduit du simple fait que `libc6` porte `+deb13u4`, ni du `+b1` binaire de zlib. Pour deux avis glibc, les données sont absentes ou insuffisantes pour conclure (CVE-2026-8674 et -89092).

## Conclusion et limites

Les 31 détections initiales se répartissent en 21 occurrences glibc, 8 occurrences GCC et 2 occurrences zlib; toutes ont été conservées. Le Security Tracker actuel corrobore le statut vulnérable Trixie pour les avis identifiés, avec huit avis glibc anciens classés « unimportant ». Les révisions Debian complètes montrent que les occurrences restent vulnérables selon les statuts consultés; aucun correctif Trixie rétroporté couvrant ces avis n’a été identifié dans ces pages. Trivy n’indique aucun correctif, mais cette absence seule n’aurait pas suffi à établir la conclusion.

CVE-2026-8674 reste sans fiche Debian retrouvée; CVE-2026-89092 a une description mais pas de statut de paquet exploitable dans la page consultée, et son prérequis `nscd` n’a pas été vérifié dans l’image. Le rapport d’inventaire ne prouve pas que les fonctions vulnérables sont atteignables. Aucun fichier de l’image n’a été inspecté dans cette analyse, aucun scan ou test d’exploitation n’a été lancé; une exploitation n’est pas démontrée.

## Références principales

1. Rapport initial : `reports/trivy-image-initial.json`, findings aux lignes 2215–3979; date de scan dans les métadonnées du rapport. Rapport HIGH/CRITICAL : aucun finding Debian de ces paquets.
2. Tracker Debian : [glibc](https://security-tracker.debian.org/tracker/source-package/glibc), [gcc-14](https://security-tracker.debian.org/tracker/source-package/gcc-14), [zlib](https://security-tracker.debian.org/tracker/source-package/zlib).
3. Fiches CVE citées dans les tableaux, chacune liée directement à l’avis du Tracker. En particulier : [CVE-2026-86805](https://security-tracker.debian.org/tracker/CVE-2026-86805), [CVE-2026-95818](https://security-tracker.debian.org/tracker/CVE-2026-95818), [CVE-2026-97399](https://security-tracker.debian.org/tracker/CVE-2026-97399), [CVE-2019-1010022](https://security-tracker.debian.org/tracker/CVE-2019-1010022), [CVE-2019-1010023](https://security-tracker.debian.org/tracker/CVE-2019-1010023), [CVE-2019-1010024](https://security-tracker.debian.org/tracker/CVE-2019-1010024), [CVE-2019-1010025](https://security-tracker.debian.org/tracker/CVE-2019-1010025), [CVE-2010-4756](https://security-tracker.debian.org/tracker/CVE-2010-4756), [CVE-2026-27171](https://security-tracker.debian.org/tracker/CVE-2026-27171), [CVE-2026-89092](https://security-tracker.debian.org/tracker/CVE-2026-89092).
