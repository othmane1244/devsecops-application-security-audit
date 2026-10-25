# Analyse statique — crypto-js

## Périmètre et rapports

Analyse en lecture seule des rapports Trivy et des sources de l’image Juice Shop identifiée par le rapport. Le rapport initial conservé sur la branche `docs/project-readme` porte `CreatedAt: 2026-10-20T11:28:17.521956103Z`; le rapport filtré `reports/trivy-image-high-critical.json` porte `CreatedAt: 2026-10-21T14:42:43.231675625Z`. Il s’agit de deux rapports distincts.

Les deux rapports signalent les mêmes deux avis critiques pour `crypto-js@3.3.0`. Aucun scan, test d’exploitation, changement applicatif ou affichage de clé/mot de passe n’a été effectué.

## Détections

| Avis | Sévérité | Installation déclarée | Rapport initial | HIGH/CRITICAL |
|---|---:|---|---|---|
| CVE-2023-46233 | CRITICAL | `crypto-js@3.3.0`, `juice-shop/node_modules/crypto-js/package.json` | Présent | Présent |
| CVE-2026-71851 | CRITICAL | `crypto-js@3.3.0`, `juice-shop/node_modules/crypto-js/package.json` | Présent | Présent |

Le rapport initial contient donc deux détections et le filtre HIGH/CRITICAL en conserve deux. Les deux détections correspondent à des mécanismes différents : PBKDF2 pour CVE-2023-46233 et génération pseudo-aléatoire pour CVE-2026-71851.

## Installation, consommateurs et résolution

Le rapport SBOM ne liste qu’une installation de `crypto-js`: version 3.3.0 au chemin ci-dessus. La recherche dans les sources applicatives et leur compilation n’a trouvé aucun import direct de `crypto-js` ni appel direct à ses fonctions cryptographiques.

Le consommateur observé est PDFKit 0.11.0 (`juice-shop/node_modules/pdfkit`, dépendance déclarée `crypto-js: ^3.1.9-1`). Juice Shop importe PDFKit dans `routes/order.ts`, ligne 42, et crée un document avec `new PDFDocument()` à la ligne 43. Depuis le fichier d’exécution de PDFKit, `node_modules/pdfkit/js/pdfkit.js`, la résolution de `crypto-js` aboutit à `juice-shop/node_modules/crypto-js/index.js`, version 3.3.0. Il s’agit donc de la copie signalée par Trivy.

Références de code inspectées :

- `routes/order.ts:42-43` — import dynamique de PDFKit et création du document PDF sans options passées au constructeur.
- `node_modules/pdfkit/js/pdfkit.js:6` — import de `crypto-js` par PDFKit.
- `node_modules/pdfkit/js/pdfkit.js:849, 1016, 1024, 1110, 1130, 1156` — appels MD5 dans les routines PDFKit.
- `node_modules/pdfkit/js/pdfkit.js:1166, 1170, 1182, 1186` — appels SHA-256 dans les routines PDFKit.
- `node_modules/pdfkit/js/pdfkit.js:1035, 1176, 1192, 1205` — appels AES.encrypt dans le code de chiffrement PDF.
- `node_modules/pdfkit/js/pdfkit.js:852-853` — helper PDFKit `generateRandomWordArray(bytes)`, qui délègue à `CryptoJS.lib.WordArray.random(bytes)`.
- `node_modules/pdfkit/js/pdfkit.js:1164-1165, 1180-1181, 1196, 1200` — appels du helper pour générer des valeurs de 8, 32 et 4 octets dans les routines PDF chiffrées.
- `node_modules/pdfkit/js/pdfkit.js:857-861` — création de l’objet PDFSecurity conditionnée par les options de mot de passe utilisateur/propriétaire.

Les lignes citées sont des références aux sources de l’image. Aucun contenu de valeur de mot de passe, clé ou donnée secrète n’est reproduit ici.

## Usages observés et fonctions disponibles

| Fonction / famille | Présente dans crypto-js 3.3.0 | Appel observé dans l’application ou son consommateur | Contexte et paramètres visibles | Rapport aux avis |
|---|---|---|---|---|
| MD5 | Oui | Oui, dans PDFKit | Hashes internes utilisés par les routines de construction/sécurité PDF. Les données proviennent des structures internes du document. | Ne constitue pas un appel PBKDF2 et ne suffit pas à établir CVE-2023-46233. |
| SHA-256 | Oui | Oui, dans PDFKit | Appels des routines de sécurité PDF; ils traitent des structures internes de mot de passe/document lorsque le chiffrement PDF est activé. | Ce n’est pas PBKDF2. La présence de SHA-256 seule ne valide ni n’annule CVE-2023-46233. |
| AES.encrypt | Oui | Oui, dans PDFKit | Chiffrement PDF conditionnel aux options de sécurité du document. Juice Shop construit le `PDFDocument` sans transmettre ces options. Aucun secret ni valeur de clé n’a été relevé. | La seule présence d’AES ne correspond pas aux prérequis des deux avis Trivy. |
| `CryptoJS.lib.WordArray.random` | Oui | Oui via le helper de PDFKit; aucun appel direct dans Juice Shop | PDFKit transmet une longueur en octets : 8 pour les sels, 32 et 4 dans les valeurs du chemin de sécurité PDF. Ces appels appartiennent aux routines PDF chiffrées. PDFKit ne crée son objet PDFSecurity que si des options de mot de passe sont fournies; l’appel applicatif examiné n’en fournit pas. | API affectée disponible et appelée dans la dépendance; génération d’une valeur sensible dans le chemin Juice Shop non observée, car l’option de chiffrement n’est pas configurée par cet appel. |
| PBKDF2 | Oui, disponible dans la bibliothèque | Aucun appel trouvé dans les sources applicatives ou le fichier PDFKit effectivement résolu | Aucun appel observé : ni données d’entrée, ni options `hasher`, `iterations` ou `keySize` applicatives à relever. | Précondition d’usage de CVE-2023-46233 non observée dans le périmètre inspecté. |

Les bundles PDFKit autonomes contiennent aussi du code crypto-js embarqué et des définitions d’algorithmes. Leur présence ne démontre pas que ces définitions s’exécutent dans le chemin de l’application. L’analyse des consommateurs s’est concentrée sur la résolution Node utilisée par `routes/order.ts`, à savoir `pdfkit/js/pdfkit.js`.

## Avis officiels et conditions

### CVE-2023-46233 — paramètres faibles par défaut de PBKDF2

L’avis officiel GHSA-xwcq-pm8m-c4vf indique que les versions antérieures à 4.2.0 sont concernées. Dans les configurations par défaut décrites, PBKDF2 utilise SHA-1, une seule itération et une taille de clé par défaut de 128/32 mots. L’avis précise que l’impact est important lorsque cette dérivation sert à protéger des mots de passe ou à produire des signatures. Il recommande une configuration SHA-256 avec au moins 250 000 itérations comme mesure de contournement. La version 3.3.0 est dans la plage affectée.

La fonction PBKDF2 existe dans la bibliothèque installée, mais aucun appel PBKDF2 n’a été trouvé dans le code applicatif, le consommateur PDFKit effectivement résolu, ni dans les sources inspectées. Les appels SHA-256 et MD5 de PDFKit ne sont pas des appels PBKDF2. **Conclusion provisoire :** version signalée et fonction disponible; condition d’usage de l’avis non observée. L’absence d’appel dans le périmètre statique ne prouve pas l’absence de tout appel dynamique ou hors des fichiers inspectés.

[Avis officiel GHSA-xwcq-pm8m-c4vf](https://github.com/brix/crypto-js/security/advisories/GHSA-xwcq-pm8m-c4vf) · [CVE-2023-46233](https://nvd.nist.gov/vuln/detail/CVE-2023-46233)

### CVE-2026-71851 — générateur aléatoire cryptographiquement faible

L’avis officiel GHSA-rg76-677x-56q9 vise les versions antérieures à 4.0.0 et précise que `CryptoJS.lib.WordArray.random()` n’est pas un générateur cryptographiquement sûr. Le scénario ne dépend pas uniquement de la présence du paquet : l’application doit employer cette fonction pour produire une valeur sensible. L’avis cite notamment les secrets de portefeuille et phrases de récupération; passer ensuite le résultat dans PBKDF2 ou un hash ne recrée pas l’entropie perdue. La version 3.3.0 est concernée.

L’API est présente dans la version installée et PDFKit référence `WordArray.random` dans son code de sécurité PDF. Toutefois, `routes/order.ts` crée le document sans options; PDFKit ne construit l’objet PDFSecurity que si un mot de passe utilisateur ou propriétaire est fourni. Aucun mot de passe ou option de chiffrement n’est transmis par le chemin applicatif examiné, et aucun usage de portefeuille, phrase de récupération ou autre secret généré par `WordArray.random` n’a été trouvé. **Conclusion provisoire :** la version et le code vulnérable sont présents; l’usage sensible requis par l’avis n’est pas observé dans la fonctionnalité de génération PDF inspectée. Aucun effet d’exploitation n’a été démontré.

[Avis officiel GHSA-rg76-677x-56q9](https://github.com/brix/crypto-js/security/advisories/GHSA-rg76-677x-56q9) · [CVE-2026-71851](https://nvd.nist.gov/vuln/detail/CVE-2026-71851)

## Synthèse des preuves et limites

| Élément à distinguer | CVE-2023-46233 | CVE-2026-71851 |
|---|---|---|
| Version signalée | Oui — 3.3.0 est antérieure à 4.2.0. | Oui — 3.3.0 est antérieure à 4.0.0. |
| Fonction concernée présente | PBKDF2 est disponible dans crypto-js. | `WordArray.random` est disponible dans crypto-js. |
| Appel constaté | Aucun appel PBKDF2 dans les sources applicatives ou PDFKit résolu. | Appel référencé par le code de sécurité PDFKit; pas d’appel direct applicatif. |
| Condition d’exposition | Usage de PBKDF2 pour une dérivation de mot de passe ou signature, avec paramètres faibles. Non observé. | Production d’une valeur sensible par le PRNG vulnérable. Non observée pour le flux PDF, dont l’option de chiffrement n’est pas activée par l’appel inspecté. |
| Conclusion provisoire | Détection de version confirmée; applicabilité fonctionnelle non établie. | Détection de version confirmée; fonction présente, mais usage sensible non établi dans le chemin inspecté. |

Les conclusions sont limitées aux rapports fournis, aux sources de l’image identifiée et au consommateur PDFKit résolu depuis la route d’ordre. Elles ne démontrent ni l’exécution de chaque routine interne, ni l’absence d’autres appels indirects construits dynamiquement. Aucun secret n’a été affiché.
