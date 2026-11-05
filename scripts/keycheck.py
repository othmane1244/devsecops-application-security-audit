"""Vérifie, sans afficher la clé, que la clé privée codée en dur dans
lib/insecurity.ts correspond à encryptionkeys/jwt.pub (constat F-002).

Usage : python -I keycheck.py <chemin>/lib/insecurity.ts <chemin>/encryptionkeys/jwt.pub
Dépendance : paquet Python `cryptography`. Aucune valeur secrète n'est écrite.
"""
import re, base64, sys
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_public_key

src = open(sys.argv[1], encoding='utf-8').read()
m = re.search(r"const privateKey = '-----BEGIN RSA PRIVATE KEY-----(.*?)-----END RSA PRIVATE KEY-----'", src, re.S)
raw = m.group(1)
BS = chr(92)
print('backslash pairs:', sorted(set(raw[i:i + 2] for i in range(len(raw)) if raw[i] == BS)))
body = raw.replace(BS + 'r', '').replace(BS + 'n', '').replace(BS, '')
body = re.sub(r'\s', '', body)
der = base64.b64decode(body + '=' * (-len(body) % 4))
k = load_der_private_key(der, None)
p = load_pem_public_key(open(sys.argv[2], 'rb').read())
print('bits', k.key_size, 'MATCH' if k.public_key().public_numbers() == p.public_numbers() else 'NO MATCH')
