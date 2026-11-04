// Precharge via NODE_OPTIONS=--require : note les paquets npm charges (require.cache)
// et les bibliotheques partagees mappees par le processus, toutes les 10 s.
const fs = require('fs')
const out = process.env.DUMP_OUT || '/x/loaded.json'
const dump = () => {
  const pkgs = new Set()
  for (const k of Object.keys(require.cache)) {
    const m = k.match(/node_modules\/((?:@[^/]+\/)?[^/]+)/g)
    if (m) pkgs.add(m.map((s) => s.slice('node_modules/'.length)).join(' > '))
  }
  let libs = []
  try {
    libs = [...new Set(fs.readFileSync('/proc/self/maps', 'utf8').split('\n').map((l) => l.split(/\s+/)[5]).filter((p) => p && p.includes('.so')))]
  } catch {}
  try { fs.writeFileSync(out, JSON.stringify({ at: new Date().toISOString(), pid: process.pid, pkgs: [...pkgs].sort(), libs: libs.sort() }, null, 1)) } catch {}
}
if (process.argv[1] && process.argv[1].endsWith('app.js')) setInterval(dump, 10000).unref()
