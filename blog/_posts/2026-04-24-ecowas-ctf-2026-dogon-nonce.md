---
layout: post
title: "ECOWAS CTF 2026 — Dogon Nonce [Crypto/Hard]"
date: 2026-04-24 10:30:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [crypto, ecdsa, hnp, lll, lattice, secp256k1, aes-cbc, hidden-number-problem, hard]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Crypto · **Difficulté :** ⭐⭐⭐ Hard · **Points :** 500  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `signatures.json.txt` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/56_dogon_nonce_signatures.txt) |

---

title: Dogon Nonce
ctf: ECOWAS CTF 2025
date: 2026-04-14
category: crypto
difficulty: hard
points: 500
flag_format: EcowasCTF{...}
flag: EcowasCTF{h1dd3n_numb3r_pr0bl3m_sh4k3s_th3_3ld3r}
author: team
---

# #56 – Dogon Nonce (Crypto, 500 pts)

## Challenge Description

> The Dogon elder signs every prophecy with the same ritual, but his hand trembles, always in the same direction.

## Files / Artifacts

- `signatures.json.txt` — JSON file containing:
  - 100 ECDSA signatures `(r, s)` on secp256k1 over random message hashes `z`
  - The public key `pub` (x, y coordinates)
  - An AES-CBC-128 encrypted flag (`iv` + `ct`)

## Overview

Classic **Hidden Number Problem (HNP)** exploiting biased ECDSA nonces. The phrase "his hand trembles, always in the same direction" signals that every signing nonce `k` shares a fixed MSB bias — the top 4 bits are always zero (`k < 2^252`). With 100 signatures and a 4-bit bias, an LLL lattice attack on a standard HNP basis recovers the secp256k1 private key `d`, which is used to derive the AES key and decrypt the flag.

## Solution

### Step 1: Recognise the HNP Setup

For each ECDSA signature `(r, s)` over message hash `z`:

$$k = s^{-1}(z + r \cdot d) \pmod{n}$$

If all $k_i < 2^{252}$ (top 4 bits always 0), we have the **Hidden Number Problem**: find secret $d$ given many equations where each $k_i$ is bounded.

From the file:
- **Curve:** secp256k1, $n$ = `0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`
- **Bias parameter:** $l = 4$ → all nonces satisfy $k_i < n / 2^4$
- **100 signatures** — more than enough for LLL to succeed with 4-bit bias

### Step 2: Build the LLL Lattice

Reformulate HNP as a Shortest Vector Problem. For $m = 99$ signature pairs, build an $(m+2) \times (m+2)$ integer matrix:

$$M = \begin{pmatrix}
nW & & & & \\
& nW & & & \\
& & \ddots & & \\
v_0 W & v_1 W & \cdots & 1 & 0 \\
u_0 W & u_1 W & \cdots & 0 & n
\end{pmatrix}$$

where:
- $W = 2^l = 2^4 = 16$ (bias scaling factor)
- $u_i = s_i^{-1} z_i \bmod n$
- $v_i = s_i^{-1} r_i \bmod n$

A short vector in the LLL-reduced basis has $d$ at position $m$.

```python
# solve_hnp.sage (SageMath)
M = Matrix(ZZ, m + 2, m + 2)
for i in range(m):
    M[i, i]   = q * W          # q = n
    M[m,   i] = vs[i] * W      # vs[i] = s_inv * r_i mod n
    M[m+1, i] = us[i] * W      # us[i] = s_inv * z_i mod n
M[m,   m]   = 1
M[m+1, m+1] = q

L = M.LLL()

for row in L:
    d_cand = int(row[m]) % q
    if d_cand > 0 and verify_d(d_cand, pub_x, pub_y):
        print(f"[+] d = {d_cand}")
        break
```

**Result:** `d = 67911827788850813800782243008577423926326109308252141481040446601251442842732`

### Step 3: Verify Key & Decrypt Flag

1. **Verify:** $d \cdot G \stackrel{?}{=} Q_{pub}$ → **matches** ✓
2. **Confirm bias:** compute all 100 nonces $k_i = s_i^{-1}(z_i + r_i d) \bmod n$ → all < $2^{252}$ ✓
3. **Derive AES key:** `sha256(d.to_bytes(32, 'big'))[:16]`
4. **Decrypt:** AES-CBC with recovered key and `iv` from JSON

```python
import json, hashlib
from Crypto.Cipher import AES

with open("signatures.json.txt") as f:
    data = json.load(f)

d  = 67911827788850813800782243008577423926326109308252141481040446601251442842732
iv = bytes.fromhex(data["iv"])
ct = bytes.fromhex(data["ct"])

key = hashlib.sha256(d.to_bytes(32, 'big')).digest()[:16]
pt  = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
pad = pt[-1]
print(pt[:-pad].decode())
# EcowasCTF{h1dd3n_numb3r_pr0bl3m_sh4k3s_th3_3ld3r}
```

## Full Solve Script

### solve_hnp.sage (SageMath — recovers d)

```sage
#!/usr/bin/env sage
# #56 Dogon Nonce — HNP/LLL attack to recover secp256k1 private key
import json
from sage.all import *

def verify_d(d_cand, Gx, Gy, pub_x, pub_y, q):
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    E = EllipticCurve(GF(p), [0, 7])
    G = E([Gx, Gy])
    return int(d_cand) * G == E([pub_x, pub_y])

with open("signatures.json.txt") as f:
    data = json.load(f)

q     = int(data["n"], 16)
pub_x = int(data["pub"][0], 16)
pub_y = int(data["pub"][1], 16)
sigs  = data["sigs"]
Gx    = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy    = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

m = 99       # number of signatures to use
l = 4        # MSB bias: k < 2^(256 - l) = 2^252
W = 2**l

us = [(pow(int(s["s"]), -1, q) * int(s["z"])) % q for s in sigs[:m]]
vs = [(pow(int(s["s"]), -1, q) * int(s["r"])) % q for s in sigs[:m]]

M = Matrix(ZZ, m + 2, m + 2)
for i in range(m):
    M[i, i]   = q * W
    M[m,   i] = vs[i] * W
    M[m+1, i] = us[i] * W
M[m,   m]   = 1
M[m+1, m+1] = q

L = M.LLL()
for row in L:
    d_cand = int(row[m]) % q
    if d_cand > 0 and verify_d(d_cand, Gx, Gy, pub_x, pub_y, q):
        print(f"[+] d = {d_cand}")
        break
```

### decrypt_flag.py (Python — decrypts flag with recovered d)

```python
#!/usr/bin/env python3
# #56 Dogon Nonce — AES-CBC decrypt with SHA-256(d) key
import json, hashlib
from Crypto.Cipher import AES
from ecdsa import SECP256k1

with open("signatures.json.txt") as f:
    data = json.load(f)

n    = int(data["n"], 16)
pub  = (int(data["pub"][0], 16), int(data["pub"][1], 16))
sigs = data["sigs"]
iv   = bytes.fromhex(data["iv"])
ct   = bytes.fromhex(data["ct"])

# Private key recovered by LLL (solve_hnp.sage)
d = 67911827788850813800782243008577423926326109308252141481040446601251442842732

# Verify d matches public key
curve = SECP256k1
G = curve.generator
Q = d * G
assert (Q.x(), Q.y()) == pub, "Key mismatch!"
print(f"[+] Public key verified")

# Confirm all nonces are < 2^252 (4-bit MSB bias)
bias = sum(
    1 for s in sigs
    if (pow(int(s["s"]), -1, n) * (int(s["z"]) + int(s["r"]) * d)) % n < 2**252
)
print(f"[+] Nonces with k < 2^252: {bias}/100")

# Decrypt flag: key = SHA-256(d as 32-byte big-endian)[:16]
key  = hashlib.sha256(d.to_bytes(32, 'big')).digest()[:16]
pt   = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
pad  = pt[-1]
flag = pt[:-pad].decode()
print(f"[+] Flag: {flag}")
# EcowasCTF{h1dd3n_numb3r_pr0bl3m_sh4k3s_th3_3ld3r}
```

## Flag

```
EcowasCTF{h1dd3n_numb3r_pr0bl3m_sh4k3s_th3_3ld3r}
```

## Lessons Learned

- "Trembles in the same direction" = **MSB-biased nonces** → HNP (not LSB, not fixed nonce).
- Standard HNP lattice with `l = 4`, 99 equations is sufficient for secp256k1 (256-bit key) even with moderate bias.
- AES key derivation pattern: `sha256(d_bytes)[:16]` — try this first before exotic formats.
- Verify the recovered `d` with scalar multiplication before attempting decryption.

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
