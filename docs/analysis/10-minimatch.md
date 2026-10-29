# Analyse statique de minimatch

## Périmètre et détections Trivy

Les rapports initial et HIGH/CRITICAL contiennent les mêmes trois détections HIGH sur la copie `minimatch@3.0.5`, chemin `juice-shop/node_modules/replace/node_modules/minimatch/package.json` :

| CVE | GHSA | Mécanisme décrit par l’avis | Version corrigée selon les avis / rapports |
|---|---|---|---|
| `CVE-2026-26996` | `GHSA-3ppc-4f35-3m26` | ReDoS avec de nombreux `*` consécutifs suivis d’un littéral absent du chemin comparé | `3.1.3` |
| `CVE-2026-27903` | `GHSA-7r86-cg39-jmmj` | Backtracking combinatoire dans `matchOne()` avec plusieurs segments `**` non adjacents et un chemin qui ne correspond pas | `3.1.3` |
| `CVE-2026-27904` | `GHSA-23c5-xmqv-rm74` | ReDoS par extglobs `*()` imbriqués, générant des quantificateurs non bornés imbriqués | `3.1.4` |

Le rapport initial compte ces alertes parmi les HIGH, et le rapport filtré les conserve. Chaque ligne du tableau représente une détection pour cette installation dans chacun des rapports; les rapports JSON n’ont pas été modifiés. Les deux autres copies repérées dans l’inventaire Trivy (`3.1.5` et `9.0.9`) n’ont pas ces alertes : leurs versions dépassent les plages affectées décrites pour les trois avis.

## Installations résolues et consommateurs

| Version / chemin dans l’image | Consommateur résolu | Conclusion sur ces avis |
|---|---|---|
| `3.0.5` — `node_modules/replace/node_modules/minimatch` | `replace@1.2.2`, dépendance directe de Juice Shop (`replace: ^1.2.2` dans son manifeste; `replace@1.2.2` déclare `minimatch: 3.0.5`) | Seule installation à laquelle les rapports attachent les trois détections. |
| `3.1.5` — `node_modules/minimatch` | Copie présente à la racine de l’image; Trivy ne fournit pas le parent consommateur dans le finding. Aucun import direct observé dans le code applicatif consulté. | Présente, mais aucune détection parmi les trois avis; version supérieure aux seuils corrigés. |
| `9.0.9` — `node_modules/glob/node_modules/minimatch` | `glob@10.5.0` (version résolue indiquée par l’inventaire Trivy; Juice Shop déclare `glob: ^10.4.5`, et `glob` embarque cette copie imbriquée) | Présente, mais aucune détection parmi ces avis; version supérieure aux plages affectées. |

Les rapports d’image établissent les chemins et versions, pas toutes les arêtes « dépend de » pour chaque copie. Les relations ci-dessus sont confirmées par le manifeste et les manifestes des paquets pour `replace` et `glob`; le consommateur propre à la copie racine `3.1.5` ne peut pas être déterminé à partir des champs Trivy disponibles seuls. Aucun code applicatif n’importe `minimatch` directement dans les sources consultées.

## Chemin d’appel observé pour la copie signalée

Juice Shop importe `replace` dans `data/datacreator.ts`. Cette fonction de création des données inclut `prepareFilesystem()` dans sa liste de tâches exécutées au démarrage. La fonction appelle `replace()` avec les options suivantes :

- `regex`: chaîne fixe `http://localhost:3000`;
- `replacement`: valeur de configuration `server.baseUrl`;
- `paths`: chemin fixe `.well-known/csaf/provider-metadata.json`;
- `recursive`: `true`;
- aucune option `include` ou `exclude` applicative fournie.

Dans `replace@1.2.2` (`replace.js`), `canSearch(file, isFile)` appelle `minimatch(file, include, { matchBase: true })` pour chaque motif `include`, et `minimatch(file, exclude, { matchBase: true })` pour les exclusions. En l’absence d’options `include`/`exclude` du code Juice Shop, `include` est absent et les exclusions proviennent du fichier `replace/defaultignore` livré avec le paquet. Le chemin cible remis à `replace` est constant; les motifs d’exclusion sont ceux de cette liste fournie par la dépendance. Aucun motif ni chemin n’est construit depuis une route HTTP, un nom de fichier transmis par l’utilisateur, une requête, ou le contenu du fichier remplacé.

La récursion sur le répertoire ciblé signifie que l’appel peut examiner les chemins sous ce répertoire; elle ne rend pas le motif d’entrée utilisateur contrôlable. La provenance des entrées comparées reste le chemin cible constant et l’arborescence du système de fichiers de démarrage. Le contenu du JSON n’est pas l’argument motif de `minimatch`; la recherche/remplacement de son texte utilise la regex distincte fournie à `replace`.

### Extraits applicatifs et dépendances

Les chemins sont relatifs à Juice Shop v20.3.0, paquet `replace@1.2.2` et son fichier source publié `replace.js` :

| Preuve | Chemin et lignes | Extrait / constat |
|---|---|---|
| Import de `replace` et enregistrement de la tâche de démarrage | `data/datacreator.ts`, lignes 36–37, 40–62 du tag | `import replace from 'replace'`; `prepareFilesystem` figure dans la séquence des créateurs appelée au démarrage. |
| Valeurs utilisées par l’appel | `data/datacreator.ts`, lignes 747–754 du tag | `regex: 'http://localhost:3000'`; `replacement: config.get('server.baseUrl')`; `paths: ['.well-known/csaf/provider-metadata.json']`; `recursive: true`. |
| Passage au matcher | `replace@1.2.2/replace.js`, lignes 87–95; `minimatch@3.0.5/minimatch.js`, lignes 109–123, 679–720, 737–850 | `canSearch()` fournit `file` comme premier argument et les filtres comme patterns; `minimatch()` construit `Minimatch`, puis `match()` appelle `matchOne()`. `matchOne()` recourt à `f.match(p)` pour les segments regex (L837–L850) et explore récursivement les segments `GLOBSTAR` (L760–L820). |
| Origine des exclusions par défaut | `replace@1.2.2/replace.js`, lignes 50–56 | Les exclusions optionnelles sont concaténées à `replace/defaultignore`; l’appel Juice Shop n’en passe aucune. |
| Contenu de `defaultignore` | `replace@1.2.2/defaultignore`, lignes 1–64 de l’archive npm exacte | Motifs : `.git`, `.hg`, `.svn`, `.DS_Store`, `ehthumbs.db`, `Thumbs.db` et des motifs simples `*.ext` pour polices, médias, binaires, archives, journaux et bases de données. |
| Version de la dépendance | `replace@1.2.2/package.json`, `dependencies` | `"minimatch": "3.0.5"`; la copie résolue sous `replace/node_modules` correspond au finding Trivy. |

### Comparaison structurelle de `defaultignore` avec les avis

L’archive publiée exacte `replace@1.2.2` fournit `defaultignore` (lignes 1–64; extraits représentatifs : `.git` L2, `*.ttf` L7, `*.jpg` L17, `*.zip` L55, `*.sqlite` L59, noms Windows fixes L62–L64). Les entrées sont des chemins fixes ou un seul `*` suivi d’une extension littérale; le fichier ne contient ni séquences de multiples `*` suivies d’un littéral absent, ni segments `**`, ni extglobs `*()` imbriqués.

Par comparaison avec les prérequis des avis, les patterns livrés ne portent donc pas les structures d’entrée pattern déclencheuses décrites par `CVE-2026-26996`, `CVE-2026-27903` ou `CVE-2026-27904`. Ce constat porte sur la forme du fichier fourni, pas sur un appel de matching réalisé : aucune comparaison n’a été exécutée. Il n’écarte pas en général un motif ajouté par une option `exclude` dans un autre consommateur de `replace`; l’appel Juice Shop documenté n’en transmet pas.

## Avis officiels et prérequis par détection

### CVE-2026-26996 / GHSA-3ppc-4f35-3m26

L’avis officiel décrit un pattern comportant plusieurs wildcards `*` consécutifs suivis d’un caractère littéral qui n’existe pas dans la chaîne comparée. La conversion crée plusieurs groupes regex `[^/]*?`; une non-correspondance force le moteur V8 à explorer les distributions possibles. L’avis classe comme affectées les versions antérieures à `3.1.3` dans la branche 3.x. Prérequis applicatif : une donnée contrôlée par l’attaquant doit être utilisée comme **pattern** `minimatch`, et un appel doit comparer un chemin qui provoque l’échec. Ici, l’application passe les chemins de fichiers comme premier argument et les patterns fixes d’exclusion comme second; le pattern ne provient pas de l’utilisateur.

### CVE-2026-27903 / GHSA-7r86-cg39-jmmj

L’avis situe le coût non borné dans `matchOne()`: un pattern à plusieurs segments `**` non adjacents déclenche une exploration récursive des suffixes de chemin; une chaîne de chemin qui ne correspond pas produit le backtracking combinatoire. Les versions 3.x `<3.1.3` sont affectées. Prérequis : un pattern glob attaquant contrôlé, suffisamment de segments `**`, un appel à `minimatch` et une chaîne comparée non correspondante. Dans l’appel observé, les motifs viennent de `defaultignore`, tandis que le premier argument est le chemin issu de la cible de fichiers fixe. Aucun motif réseau ou route utilisateur n’a été trouvé.

### CVE-2026-27904 / GHSA-23c5-xmqv-rm74

L’avis décrit les extglobs imbriqués de la forme `*()` (et `+()`), convertis en groupes regex quantifiés imbriqués, puis évalués lors du matching. Dans le code exact `minimatch@3.0.5`, `plTypes` associe `*` à un groupe terminé par `)*` (`minimatch.js`, lignes 11–16); le parseur ouvre et ferme ces groupes aux lignes 383–415, compile la regex aux lignes 599–619, puis `matchOne()` teste la partie de chemin (lignes 737 et suivantes). Les versions 3.x `<3.1.4` sont affectées selon l’avis. Prérequis : fournir un pattern extglob imbriqué à l’API et une valeur comparée non correspondante. Pour la copie `3.0.5`, le code applicatif observé ne fournit que des motifs d’exclusion provenant du fichier par défaut du paquet, non des données utilisateur. Aucun tel pattern fourni par route n’a été observé.

## Démarrage, build et routes

- **Démarrage runtime : appel observé.** `prepareFilesystem()` fait partie du remplissage initial des données et appelle `replace()` sur la cible statique. `replace` peut alors exécuter les appels `minimatch()` de filtrage des exclusions. Les motifs restent ceux du fichier `defaultignore` du paquet.
- **Build : aucun appel de cette copie Minimatch observé.** Les scripts de build incluent plusieurs outils de développement, mais aucune preuve ne relie ici leurs appels à la copie `replace/node_modules/minimatch@3.0.5`. Les copies Minimatch utilisées par les outils de build ne sont pas interchangeables avec l’installation signalée.
- **Routes : aucun appel observé.** Aucune route n’importe `replace` ou `minimatch`, et aucun paramètre de requête/route n’est transmis à leur API dans le chemin inspecté.

## Synthèse et applicabilité

| Point | Conclusion |
|---|---|
| Version signalée | `minimatch@3.0.5` imbriquée sous `replace`, trois alertes HIGH dans chacun des deux rapports. |
| Code vulnérable disponible | Oui selon les plages et mécanismes des trois avis officiels; les trois avis décrivent des chemins de matching distincts. |
| Appels à `minimatch()` dans le consommateur | Oui : `replace@1.2.2/replace.js`, `canSearch()` applique le matcher aux filtres include/exclude. |
| Origine des patterns dans le chemin Juice Shop observé | `replace/defaultignore` fourni par la dépendance; Juice Shop ne passe ni options `include`/`exclude`, ni motifs issus d’une requête. |
| Origine des chemins comparés | Cible fixe `.well-known/csaf/provider-metadata.json` et fichiers rencontrés sous cette cible lors du parcours récursif au démarrage. |
| Entrée contrôlée depuis une route | Non observée. |
| Applicabilité | Conditionnelle; les motifs de déclenchement décrits par les avis ne sont pas issus d’une entrée utilisateur dans le chemin observé. Cela ne constitue pas une preuve qu’aucune configuration ou modification externe du filesystem ne puisse changer les entrées. |
| Exploitation démontrée | Non. Aucun motif malveillant, ralentissement mesuré ou test d’exploitation n’a été réalisé. |

La présence et le chemin d’appel de la dépendance sont établis; l’origine fixe des motifs dans l’appel observé ne permet pas de conclure à une exposition par les routes Juice Shop. Les détections Trivy demeurent des alertes de versions dépendantes, et non des preuves d’exploitation.

## Références

- [Avis officiel GHSA-3ppc-4f35-3m26 / CVE-2026-26996](https://github.com/advisories/GHSA-3ppc-4f35-3m26) — wildcards consécutifs, plages affectées et prérequis de pattern contrôlé.
- [Avis officiel GHSA-7r86-cg39-jmmj / CVE-2026-27903](https://github.com/advisories/GHSA-7r86-cg39-jmmj) — récursion `matchOne()` et segments globstar non adjacents.
- [Avis officiel GHSA-23c5-xmqv-rm74 / CVE-2026-27904](https://github.com/advisories/GHSA-23c5-xmqv-rm74) — extglobs imbriqués et `AST.toRegExpSource()`.
- [Code Juice Shop v20.3.0 `data/datacreator.ts`](https://github.com/juice-shop/juice-shop/blob/v20.3.0/data/datacreator.ts) — import, exécution au démarrage et appel `prepareFilesystem()`.
- [Code publié de `replace@1.2.2`](https://registry.npmjs.org/replace/-/replace-1.2.2.tgz) — `replace.js` appelle `minimatch(file, include/exclude)`; `package.json` déclare `minimatch@3.0.5`.
- [Archive npm exacte `replace@1.2.2`](https://registry.npmjs.org/replace/-/replace-1.2.2.tgz) — fichier `package/defaultignore`, lignes 1–64; comparaison structurelle des motifs, sans matching de test.
- [Code minimatch v3.0.5](https://github.com/isaacs/minimatch/blob/v3.0.5/minimatch.js) — source exacte de la copie signalée, notamment `parse()`, compilation regex et `matchOne()`.

## Limites de l’inspection

L’analyse est statique et s’appuie sur les manifestes et chemins rapportés par Trivy, le code Juice Shop v20.3.0 et les sources des avis officiels. Les contenus effectifs de configuration externe et l’état des fichiers du conteneur au démarrage ne sont pas établis par les rapports. Aucun nouveau scan, aucune requête de test ni aucun test d’exploitation n’a été effectué.
