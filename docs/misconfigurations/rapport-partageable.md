# Résultats du contrôle des mauvaises configurations

**Date des contrôles principaux : 2026-10-29 UTC.** Contrôles Trivy config seulement; aucun démarrage de Juice Shop, déploiement, scan de vulnérabilités, contrôle de secrets, exploitation ou correction.

## Cibles, commandes et conservation

Trivy **0.76.0** a été lancé depuis l’image locale `aquasec/trivy@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222`. Les sources étaient montées en lecture seule. `--pull=never` a empêché le téléchargement de l’image Trivy. Les deux commandes principales étaient celles de [la méthode](README.md), avec les variables résolues comme suit :

| Périmètre | Cible | Image/contexte | Création UTC | Code | Résultat brut privé |
| --- | --- | --- | --- | ---: | --- |
| Laboratoire | Worktree du dépôt sur `docs/project-readme` | Dépôt d’audit local | 2026-10-29 09:28:29.786484845 | 0 | JSON valide, 725 octets; SHA-256 `9e33c20b75e8cfffa5a717a973abe8193d4a934aafdacec2cc7c4e96967044b8` |
| Juice Shop | Arbre extrait `/juice-shop`, 1 963 fichiers | `bkimminich/juice-shop:v20.3.0`; ID local/RepoDigest `sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27`; Linux/amd64; 24 couches | 2026-10-29 09:29:06.097405743 | 0 | JSON valide, 307 632 octets; SHA-256 `29fc3dcb96327df5d071381a31f30e762eede6ac66eb02782dbda49bfbdd063c` |

Les rapports et journaux bruts sont conservés hors du dépôt dans `%LOCALAPPDATA%\JuiceShopAudit\misconfigurations\20261029T092643Z\`. L’ACL a été remplacée par une autorisation de contrôle complet pour l’utilisateur courant; sa vérification a confirmé une seule entrée d’accès et aucun héritage. Aucun extrait de configuration ni valeur détectée n’est publié.

La provenance de l’arbre est documentée dans l’audit des secrets : un conteneur a été créé depuis l’image avec `docker create --pull=never`, confirmé à l’arrêt, puis `/juice-shop` a été copié. Le conteneur n’a jamais été démarré. Le chemin d’extraction documenté a été vérifié avant le contrôle; il existe et compte toujours 1 963 fichiers. L’image locale partage les 24 couches avec l’image rapprochée du rapport initial, mais son ID local/RepoDigest diffère du digest de configuration OCI `sha256:40606cfb23b8937b60c1cab5a5980362e0a372223c1f86f6c3e68c1b003a823c` rapporté initialement. Cette différence limite l’attribution à l’image initiale.

Options appliquées : `--misconfig-scanners dockerfile,terraform,kubernetes`, `--skip-check-update`, `--disable-telemetry`, `--skip-version-check`, `--quiet`, `--skip-dirs /scan/.git,/scan/node_modules`, `--format json`; aucun `--exit-code` personnalisé. Les sources ont été montées avec `readonly`. Aucun fichier de cache de règles n’a été monté. Le JSON ne donne pas l’identifiant ou l’âge du bundle. La mise à jour a été désactivée; il reste inconnu si les règles chargées venaient du cache de l’image Trivy ou du bundle intégré à cette version.

Une exécution diagnostique supplémentaire du périmètre Juice Shop avec `--debug` a créé un JSON valide avec les mêmes 66 constats, à `2026-10-29T09:31:27.261174766Z`, mais le processus a terminé avec le code **1**. Le journal diagnostique privé ne contenait pas de marqueur `error`, `parse` ou `failed`; la cause du code 1 reste inconnue. Cette exécution n’a pas remplacé le résultat principal (code 0).

## Résultats par périmètre

| Périmètre | Statut d’interprétation | CRITICAL | HIGH | MEDIUM | LOW | Total |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Worktree du laboratoire | **Aucun fichier pris en charge trouvé**; JSON sans cible `Results`, code 0. Ce n’est pas un contrôle de fichiers pris en charge sans détection. | 0 | 0 | 0 | 0 | 0 |
| Sources d’infrastructure livrées avec Juice Shop | Constats dans `infrastructure/`; ce sont des sources disponibles, pas une preuve de déploiement. | 4 | 4 | 1 | 9 | 18 |
| Exemples Terraform pédagogiques | Constats dans les trois fichiers `data/static/codefixes/iacLeakedKeyChallenge_*.tf`, y compris le fichier suffixé `_3_correct`. Ils restent des exemples livrés, pas une preuve de déploiement. | 12 | 12 | 3 | 21 | 48 |
| **Total Juice Shop** | **Contrôle principal terminé avec constats**; parsing exhaustif non démontré (voir limites). | **16** | **16** | **4** | **30** | **66** |

Les lignes ci-dessous décrivent les règles signalées. Chaque chemin et emplacement mentionné correspond à une occurrence distincte; les répétitions d’une même règle dans plusieurs fichiers sont conservées. Les constats ne prouvent ni le déploiement, ni l’accessibilité, ni l’exploitabilité des ressources AWS décrites dans les fichiers.

## Détail expurgé des 66 constats

| Règle | Gravité / nombre | Fichiers et lignes signalés | Constat expurgé, risque et contexte |
| --- | --- | --- | --- |
| `DS-0026` — No HEALTHCHECK defined | LOW / 1 | `infrastructure/Dockerfile` — Trivy n’a pas fourni de ligne. | Le Dockerfile ne définit pas de contrôle de santé. Un orchestrateur pourrait ne pas détecter certains états de service; aucun runtime ni orchestrateur n’a été examiné. |
| `AWS-0017` — CloudWatch log groups should be encrypted using CMK | LOW / 1 | `infrastructure/terraform/main.tf:126–134` | Le contrôle ne voit pas l’usage d’une clé gérée par le client pour le groupe de journaux. Cela peut réduire le contrôle sur le chiffrement des logs si cette source est déployée; le plan ou l’état AWS n’a pas été consulté. |
| `AWS-0037` — EFS Encryption has not been enabled | HIGH / 3 | Chacun des trois exemples `data/static/codefixes/iacLeakedKeyChallenge_1.tf`, `_2.tf`, `_3_correct.tf`: `250`. | EFS sans chiffrement au repos selon la source analysée. Risque de confidentialité si l’exemple était appliqué; ces fichiers sont des fixtures de challenge/correction et leur déploiement n’est pas établi. |
| `AWS-0052` — Load balancers should drop invalid headers | HIGH / 4 | Les trois exemples `iacLeakedKeyChallenge_1.tf`, `_2.tf`, `_3_correct.tf`: `121–132`; `infrastructure/terraform/networking.tf:122–133`. | Le réglage de rejet des en-têtes non valides est absent selon la règle. Un load balancer pourrait accepter des en-têtes inattendus; aucune ressource en service n’a été vérifiée. |
| `AWS-0053` — Load balancer is exposed to the internet | HIGH / 4 | Les trois exemples `iacLeakedKeyChallenge_1.tf`, `_2.tf`, `_3_correct.tf`: `123`; `infrastructure/terraform/networking.tf:124`. | La source décrit un load balancer public. Si déployé, il élargirait l’exposition réseau; l’exposition effective et les contrôles en amont sont inconnus. |
| `AWS-0054` — Use of plain HTTP | CRITICAL / 4 | Les trois exemples `iacLeakedKeyChallenge_1.tf`, `_2.tf`, `_3_correct.tf`: `156–165`; `infrastructure/terraform/networking.tf:157–166`. | Le listener utilise HTTP non chiffré selon la règle. Si déployé et utilisé, le trafic correspondant pourrait manquer de chiffrement; aucune connexion réelle n’a été testée. |
| `AWS-0104` — unrestricted egress to any IP address | CRITICAL / 12 | Dans chacun des trois exemples `iacLeakedKeyChallenge_1.tf`, `_2.tf`, `_3_correct.tf`: lignes `85`, `111`, `238` (3 ressources par fichier). Dans `infrastructure/terraform/networking.tf`: lignes `86`, `112`, `239` (3 ressources). | Trois règles de groupes de sécurité par fichier permettent une sortie très large selon le contrôle. Cela peut faciliter des communications non nécessaires si déployé; la connectivité effective et les règles complémentaires n’ont pas été vérifiées. |
| `AWS-0124` — Missing description for security group rule | LOW / 28 | Chaque exemple `iacLeakedKeyChallenge_1.tf`, `_2.tf`, `_3_correct.tf`: `67–72`, `74–79`, `81–86`, `100–105`, `107–112`, `227–232`, `234–239` (7 occurrences par fichier). `infrastructure/terraform/networking.tf`: `68–73`, `75–80`, `82–87`, `101–106`, `108–113`, `228–233`, `235–240` (7 occurrences). | Les règles de groupes de sécurité n’ont pas de description détectée. Cela réduit leur lisibilité et leur revue; le constat seul ne démontre pas une exposition réseau supplémentaire. |
| `AWS-0164` — Instances in a subnet should not receive a public IP address by default | HIGH / 5 | Chaque exemple `iacLeakedKeyChallenge_1.tf`, `_2.tf`, `_3_correct.tf`: `22`; `infrastructure/terraform/networking.tf:23` pour deux ressources de sous-réseau. | L’attribution d’adresse publique par défaut est signalée. Si appliquée, elle peut rendre des instances adressables depuis l’extérieur selon les autres contrôles; aucun réseau déployé n’a été inspecté. |
| `AWS-0178` — VPC Flow Logs should capture rejected traffic | MEDIUM / 4 | Les trois exemples `iacLeakedKeyChallenge_1.tf`, `_2.tf`, `_3_correct.tf`: `5–15`; `infrastructure/terraform/networking.tf:6–16`. | La journalisation du trafic rejeté n’est pas activée selon la règle. Cela limite la visibilité pour l’investigation si la VPC est déployée; aucun journal runtime n’a été consulté. |

Les 48 constats pédagogiques se répartissent chacun, par fichier, en 4 CRITICAL, 4 HIGH, 1 MEDIUM et 7 LOW. Le fichier `_3_correct.tf` porte un nom de correction mais conserve ces mêmes constats Trivy; il ne faut pas l’interpréter comme le fichier effectivement déployé ni comme une correction vérifiée.

## Fichiers reconnus, erreurs de parsing et limites

- Le JSON du worktree n’a pas de tableau `Results`; l’inventaire du worktree n’avait trouvé aucun Dockerfile, Terraform ou Kubernetes candidat. Conclusion : **aucun fichier pris en charge**, et non « aucun risque ».
- Pour l’arbre Juice Shop, le JSON contient des résultats associés à six fichiers avec constats : `infrastructure/Dockerfile`, `infrastructure/terraform/main.tf`, `infrastructure/terraform/networking.tf` et les trois exemples Terraform. Il contient aussi deux entrées de répertoire sans constat. Trivy n’émet pas dans ce rapport une liste exhaustive des fichiers analysés sans constat; les autres fichiers Terraform recensés ne peuvent donc pas être classés ici comme analysés sans détection.
- Les commandes principales utilisaient `--quiet`, qui a produit des journaux vides. Une exécution diagnostique `--debug` n’a pas relevé de marqueur textuel d’erreur/parsing, mais son code 1 reste inexpliqué. L’absence de ces marqueurs ne prouve pas l’absence de toute erreur; la vérification exhaustive du parsing demeure ouverte.
- Les deux fichiers Compose ne sont pas couverts par les scanners déclarés. La version examinée ne fournit pas de scanner de configuration GitHub Actions; aucun workflow n’a d’ailleurs été trouvé dans l’image. Les fichiers YAML génériques de configuration applicative ne sont pas automatiquement couverts par les règles intégrées de cette commande.
- Le scan analyse les sources présentes dans l’arbre extrait. Il n’évalue ni les valeurs de variables fournies au déploiement, ni les états Terraform, ni les comptes AWS, ni les services actifs. La configuration n’est pas une preuve de déploiement.
- Le rapport Trivy donne la version de l’outil, pas celle ni l’âge du bundle de règles. `--skip-check-update` a empêché de demander sa mise à jour, mais ne permet pas d’établir s’il a utilisé une copie en cache ou le bundle intégré.
- L’image locale n’a pas le même identifiant de configuration que celui associé au rapport initial, malgré les couches communes. Les résultats sont attribués à l’arbre de l’image locale décrit ici.
