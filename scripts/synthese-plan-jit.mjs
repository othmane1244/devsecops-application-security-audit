// Synthèse des résultats du workflow « Plan Jit (reproduction OSS) » et
// recoupement avec Trivy. N'affiche aucune valeur de secret.
// Usage : node scripts/synthese-plan-jit.mjs <dossier plan-jit-oss> <trivy-image-corrige.json> <package-lock.json du fork>
import fs from 'node:fs'
import path from 'node:path'

const [dir, trivyPath, lockPath] = process.argv.slice(2)
const J = (p) => JSON.parse(fs.readFileSync(p, 'utf8'))
const count = (a, f) => a.reduce((m, x) => { const k = f(x); m[k] = (m[k] || 0) + 1; return m }, {})
const rel = (p) => String(p).replace(/^(\.\.\/)*\/?src\//, '')
const out = {}

for (const cible of ['reference', 'courant']) {
  const base = path.join(dir, cible)
  const sg = J(path.join(base, 'sast-semgrep/resultats.json'))
  const osv = J(path.join(base, 'sca-osv/resultats.json'))
  const gl = J(path.join(base, 'secrets-gitleaks/resultats.json'))
  const kc = J(path.join(base, 'iac-kics/resultats.json'))
  const tv = J(path.join(base, 'dockerfile-trivy/resultats.json'))
  const osvPk = (osv.results || []).flatMap((s) => s.packages)
  out[cible] = {
    semgrep: {
      constats: sg.results.length,
      erreurs: count(sg.errors, (e) => e.type?.[0] || e.type),
      severite: count(sg.results, (x) => x.extra.severity),
      regles: count(sg.results, (x) => x.check_id.split('.').pop()),
      liste: sg.results.map((x) => `${x.extra.severity} ${x.check_id.split('.').pop()} ${rel(x.path)}:${x.start.line}`)
    },
    osv: {
      sources: (osv.results || []).map((s) => rel(s.source.path)),
      paquetsVulnerables: osvPk.length,
      groupesAvis: osvPk.reduce((n, p) => n + (p.groups || []).length, 0)
    },
    gitleaks: {
      constats: gl.length,
      regles: count(gl, (x) => x.RuleID),
      dossiers: count(gl, (x) => rel(x.File).split('/').slice(0, 2).join('/')),
      valeursExpurgees: gl.every((x) => x.Secret === 'REDACTED'),
      liste: gl.map((x) => `${x.RuleID} ${rel(x.File)}:${x.StartLine}`)
    },
    kics: {
      total: kc.total_counter,
      severite: kc.severity_counters,
      plateformes: kc.queries.reduce((m, q) => { m[q.platform] = (m[q.platform] || 0) + q.files.length; return m }, {}),
      parEmplacement: kc.queries.flatMap((q) => q.files.map((f) => ({ q, f }))).reduce((m, { q, f }) => {
        const p = rel(f.file_name)
        const g = p.startsWith('data/static/codefixes') ? 'data/static/codefixes' : p.split('/').slice(0, 2).join('/')
        m[g] = m[g] || {}; m[g][q.severity] = (m[g][q.severity] || 0) + 1; return m
      }, {})
    },
    trivyDockerfile: (tv.Results || []).filter((r) => (r.Misconfigurations || []).length)
      .map((r) => ({ cible: r.Target, constats: r.Misconfigurations.map((m) => `${m.ID} ${m.Severity}`) }))
  }
}

// Différences référence -> courant (même outil)
const diff = (a, b) => ({ seulementReference: a.filter((x) => !b.includes(x)), seulementCourant: b.filter((x) => !a.includes(x)) })
out.differences = {
  semgrep: diff(out.reference.semgrep.liste.map((s) => s.split(' ').slice(1).join(' ')), out.courant.semgrep.liste.map((s) => s.split(' ').slice(1).join(' '))),
  gitleaks: diff(out.reference.gitleaks.liste, out.courant.gitleaks.liste)
}

// Recoupement OSV (dépôt, courant) / Trivy (image corrigée), paquets npm
const lock = J(lockPath).packages
const dev = {}
for (const [p, v] of Object.entries(lock)) {
  const n = p.replace(/.*node_modules\//, '')
  if (n) { const k = `${n}@${v.version}`; dev[k] = dev[k] === false ? false : !!v.dev }
}
const rows = J(path.join(dir, 'courant/sca-osv/resultats.json')).results.flatMap((s) => s.packages)
  .flatMap((p) => (p.groups || []).map((g) => ({ k: `${p.package.name}@${p.package.version}`, ids: [...g.ids, ...(g.aliases || [])], dev: dev[`${p.package.name}@${p.package.version}`] })))
const tvNpm = J(trivyPath).Results.filter((r) => r.Class === 'lang-pkgs').flatMap((r) => r.Vulnerabilities || [])
  .map((v) => ({ k: `${v.PkgName}@${v.InstalledVersion}`, id: v.VulnerabilityID, sev: v.Severity, vu: false }))
const tvOs = J(trivyPath).Results.filter((r) => r.Class === 'os-pkgs').flatMap((r) => r.Vulnerabilities || [])
let communs = 0
const osvSeul = []
for (const r of rows) {
  const m = tvNpm.filter((t) => t.k === r.k && r.ids.includes(t.id))
  if (m.length) { communs++; m.forEach((t) => { t.vu = true }) } else osvSeul.push(r)
}
out.recoupementSca = {
  osvGroupes: rows.length,
  osvProd: rows.filter((r) => !r.dev).length,
  osvDev: rows.filter((r) => r.dev).length,
  trivyImageNpm: tvNpm.length,
  trivyImageDebian: tvOs.length,
  communs,
  osvSeulement: osvSeul.map((r) => `${r.k} ${r.ids[0]}${r.dev ? ' (dev)' : ''}`),
  trivySeulementNpm: tvNpm.filter((t) => !t.vu).map((t) => `${t.k} ${t.id} ${t.sev}`)
}

console.log(JSON.stringify(out, null, 1))
