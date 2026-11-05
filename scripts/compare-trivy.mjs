// Compare deux rapports Trivy JSON (vulnerabilites) : avant / apres correction.
// Usage : node scripts/compare-trivy.mjs <avant.json> <apres.json> [paquet ...]
// Une detection = couple (identifiant de vulnerabilite, paquet, version installee).
import fs from 'node:fs'

const [avantPath, apresPath, ...watch] = process.argv.slice(2)
const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

const load = (path) => {
  const report = JSON.parse(fs.readFileSync(path, 'utf8'))
  const map = new Map()
  for (const result of report.Results ?? []) {
    for (const v of result.Vulnerabilities ?? []) {
      map.set(`${v.VulnerabilityID}|${v.PkgName}|${v.InstalledVersion}`, v)
    }
  }
  return { meta: report.Metadata ?? {}, created: report.CreatedAt, map }
}
const count = (map) => Object.fromEntries(SEV.map((s) => [s, [...map.values()].filter((v) => v.Severity === s).length]))

const avant = load(avantPath)
const apres = load(apresPath)
const removed = [...avant.map.keys()].filter((k) => !apres.map.has(k))
const added = [...apres.map.keys()].filter((k) => !avant.map.has(k))

console.log(JSON.stringify({
  avant: { fichier: avantPath, image: avant.meta.ImageID, cree: avant.created, total: avant.map.size, ...count(avant.map) },
  apres: { fichier: apresPath, image: apres.meta.ImageID, cree: apres.created, total: apres.map.size, ...count(apres.map) },
  supprimees: { total: removed.length, ...count(new Map(removed.map((k) => [k, avant.map.get(k)]))) },
  ajoutees: { total: added.length, ...count(new Map(added.map((k) => [k, apres.map.get(k)]))) },
  paquetsSurveilles: Object.fromEntries(watch.map((p) => [p, {
    avant: [...avant.map.values()].filter((v) => v.PkgName === p).map((v) => `${v.VulnerabilityID} ${v.Severity} ${v.InstalledVersion}`),
    apres: [...apres.map.values()].filter((v) => v.PkgName === p).map((v) => `${v.VulnerabilityID} ${v.Severity} ${v.InstalledVersion}`)
  }])),
  detailAjoutees: added.map((k) => { const v = apres.map.get(k); return `${v.Severity} ${v.VulnerabilityID} ${v.PkgName}@${v.InstalledVersion} (corrige: ${v.FixedVersion || '-'})` })
}, null, 1))
