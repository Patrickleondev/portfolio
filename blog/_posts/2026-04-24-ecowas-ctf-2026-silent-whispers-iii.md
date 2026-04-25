---
layout: post
title: "ECOWAS CTF 2026 — Silent Whispers III [Steganography/500pts]"
date: 2026-04-24 10:13:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [steganography, stegsnow, aes-cbc, pcap, wireshark, key-extraction, network-forensics]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Steganography · **Difficulté :** ⭐⭐⭐ (Hard) · **Points :** 500  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `traffic.pcapng` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/13_silent_whispers_iii.pcapng) |

---

---

---

## Fichiers

- `information_III.txt` (838 octets) — message texte suspect
- `traffic.pcapng` (913 KB, 6057 paquets) — capture réseau

---

## Étape 1 — Stegsnow sur information_III.txt

Le fichier `information_III.txt` fait 838 octets alors que son contenu visible est minuscule :

```
Hey,

Traffic logs look normal. Nothing suspicious detected.
Let's proceed as planned.

Regards,
Admin
```

L'hexdump révèle des espaces et tabulations invisibles cachés entre les mots et en fin de lignes :

```
b"Hey,\t     \t       \t  \t   \t  ...\n\t\t \t  \t   ..."
```

→ C'est du **stegsnow** (whitespace steganography : tab = 1, espace = 0).

```bash
stegsnow -C information_III.txt
# U2FsdGVkX19RtlsoTBDs5pXFLJnfWK6+XRQis1plG/aJpuRH6stxdWNxL9EF5j2w
```

Le résultat est du **base64 OpenSSL chiffré AES-256-CBC** (préfixe `Salted__` une fois décodé).

---

## Étape 2 — Trouver le mot de passe dans le PCAP

Le PCAP contient 502 requêtes HTTP GET vers `127.0.0.1:80` — massivement du bruteforce de répertoires (dirbuster).

Parmi elles, une requête particulièrement notable :

```
GET /api?debug=ghostkey HTTP/1.1
```

→ **Le mot de passe est `ghostkey`**, dissimulé dans une requête HTTP en apparence anodine noyée dans le scan.

**Vérification** — avec l'outil tcpdump/tshark :
```bash
tshark -r traffic.pcapng -Y "http.request" -T fields -e http.request.uri | grep ghost
# /api?debug=ghostkey
```

---

## Étape 3 — Déchiffrement AES-256-CBC

```python
import base64, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

enc_b64 = "U2FsdGVkX19RtlsoTBDs5pXFLJnfWK6+XRQis1plG/aJpuRH6stxdWNxL9EF5j2w"
enc_data = base64.b64decode(enc_b64 + "==")

# Format OpenSSL : "Salted__" (8 octets) + sel (8 octets) + ciphertext
salt = enc_data[8:16]
ciphertext = enc_data[16:]

# Dérivation de clé OpenSSL avec SHA-256
def openssl_kdf(password, salt, key_len=32, iv_len=16):
    b, d = b'', b''
    while len(b) < key_len + iv_len:
        h = hashlib.sha256(d + password + salt).digest()
        b += h; d = h
    return b[:key_len], b[key_len:key_len+iv_len]

key, iv = openssl_kdf(b"ghostkey", salt)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
raw = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()

unpadder = padding.PKCS7(128).unpadder()
plaintext = (unpadder.update(raw) + unpadder.finalize()).decode()
print(plaintext)  # flag{c0v3rt_chAnn3l_m@st3r}
```

---

## Résumé de la chaîne stéganographique

```
information_III.txt
    └─ stegsnow (whitespace steg) 
           └─ Données chiffrées AES-256-CBC (base64 OpenSSL / Salted__)
                  └─ Mot de passe : "ghostkey"
                        └─ Trouvé dans traffic.pcapng : GET /api?debug=ghostkey
                               └─ FLAG : flag{c0v3rt_chAnn3l_m@st3r}
```

---

## Scripts utilisés

- `solve_13.py` — analyse initiale du PCAP (DNS, ICMP, SYN ISN, IP ID)
- `solve_13b.py` — HTTP streams complets, TTL analysis
- `solve_13c.py` — HTTP 200 responses, ghostkey URL detection
- `solve_13f.py` — PCAP packet structure, 838-byte payload identification
- Déchiffrement inline Python avec `cryptography`

---

## Flag

```
flag{c0v3rt_chAnn3l_m@st3r}
```

---

## Leçons

1. **Stegsnow** encode des bits dans les espaces/tabulations invisibles en fin de ligne
2. Un mot de passe peut être caché dans une URL noyée parmi des centaines de faux positifs (dirbuster)
3. OpenSSL AES-CBC avec `-md sha256` est le mode par défaut depuis OpenSSL 1.1.1
4. Le format de flag `flag{...}` peut différer de `EcowasCTF{...}` selon le challenge

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
