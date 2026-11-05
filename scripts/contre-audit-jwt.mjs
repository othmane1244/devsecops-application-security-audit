// Contre-audit fonctionnel et JWT (F-001, F-002, F-003).
// Usage : node contre-audit-jwt.mjs <baseUrl> <ancienne-cle-privee.pem> <ancienne-cle-publique.pem>
// N'affiche jamais les cles ; affiche un tableau JSON des resultats.
import crypto from 'node:crypto'
import fs from 'node:fs'

const [base, oldKeyPath, oldPubPath] = process.argv.slice(2)
const oldKey = fs.readFileSync(oldKeyPath, 'utf8')
const oldPub = fs.readFileSync(oldPubPath, 'utf8')
const b64u = (x) => Buffer.from(typeof x === 'string' ? x : JSON.stringify(x)).toString('base64url')
const payload = { status: 'success', data: { id: 1, email: 'admin@juice-sh.op', role: 'admin' }, iat: Math.floor(Date.now() / 1000) }
const results = []
const rec = (test, ok, detail) => results.push({ test, ok, detail })

// 1. Connexion legitime
const login = await fetch(`${base}/rest/user/login`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ email: 'admin@juice-sh.op', password: 'admin123' })
})
const auth = (await login.json()).authentication
rec('connexion admin', login.status === 200 && !!auth?.token, `HTTP ${login.status}`)
const token = auth.token
const [h, p] = token.split('.').slice(0, 2).map((s) => JSON.parse(Buffer.from(s, 'base64url')))
rec('F-003 jeton contient exp', typeof p.exp === 'number', p.exp ? `exp-iat = ${(p.exp - p.iat) / 3600} h` : 'pas de exp')
rec('alg du jeton emis', h.alg === 'RS256', h.alg)
const signedWithOldKey = crypto.createVerify('RSA-SHA256').update(token.split('.').slice(0, 2).join('.')).verify(oldPub, Buffer.from(token.split('.')[2], 'base64url'))
rec('F-002 jeton NON signe par l\'ancienne cle', !signedWithOldKey, signedWithOldKey ? 'signe par la cle codee en dur' : 'autre cle')

// 2. Parcours fonctionnel : whoami + panier
const who = await (await fetch(`${base}/rest/user/whoami`, { headers: { cookie: `token=${token}` } })).json()
rec('whoami avec jeton legitime', who.user?.email === 'admin@juice-sh.op', who.user?.email ?? 'vide')
const bearer = { authorization: `Bearer ${token}`, 'content-type': 'application/json' }
// Un produit deja present declenche une contrainte d'unicite (HTTP 500) : on en choisit un absent.
const before = (await (await fetch(`${base}/rest/basket/${auth.bid}`, { headers: bearer })).json()).data?.Products ?? []
const productId = [24, 25, 26, 27, 28].find((id) => !before.some((pr) => pr.id === id))
const add = await fetch(`${base}/api/BasketItems`, { method: 'POST', headers: bearer, body: JSON.stringify({ ProductId: productId, BasketId: String(auth.bid), quantity: 1 }) })
const basket = await fetch(`${base}/rest/basket/${auth.bid}`, { headers: bearer })
const after = (await basket.json()).data?.Products ?? []
rec('panier : ajout + lecture', add.status === 200 && basket.status === 200 && after.length === before.length + 1, `ajout produit ${productId} HTTP ${add.status}, lecture HTTP ${basket.status}, ${before.length} -> ${after.length} produit(s)`)

// 3. Attaques : un jeton forge doit etre refuse (HTTP 401 sur une route protegee)
const forged = {
  'alg none': `${b64u({ typ: 'JWT', alg: 'none' })}.${b64u(payload)}.`,
  'HS256 signe avec l\'ancienne cle publique': (() => {
    const si = `${b64u({ typ: 'JWT', alg: 'HS256' })}.${b64u(payload)}`
    return `${si}.${crypto.createHmac('sha256', oldPub).update(si).digest('base64url')}`
  })(),
  'RS256 signe avec l\'ancienne cle privee': (() => {
    const si = `${b64u({ typ: 'JWT', alg: 'RS256' })}.${b64u(payload)}`
    return `${si}.${crypto.createSign('RSA-SHA256').update(si).sign(oldKey, 'base64url')}`
  })()
}
for (const [name, t] of Object.entries(forged)) {
  const r = await fetch(`${base}/rest/basket/1`, { headers: { authorization: `Bearer ${t}` } })
  rec(`attaque ${name} refusee`, r.status === 401, `HTTP ${r.status}`)
}

console.log(JSON.stringify({ base, results }, null, 1))
process.exitCode = results.every((r) => r.ok) ? 0 : 1
