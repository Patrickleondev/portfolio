---
layout: post
title: "ECOWAS CTF 2026 — Abnormal Chain [Misc/100pts]"
date: 2026-04-24 10:52:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [misc, encoding, base64, base85, hex, base32, reverse-string, layered-encoding, cyberchef]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Misc · **Difficulté :** ⭐ (Easy) · **Points :** 100  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Description

> The wise know that to move forward, you must sometimes retrace your steps.

**Fichier `cipher.txt` :**

```
RyZuUmhIOTBqa0ctZnE0Ry1FVmxHK3tNaUctTmIyR2NxKH1IRE5Wakcmd2I0Ry...
```

## Analyse

### Indice clé — "retrace your steps"

Le titre **"Abnormal Chain"** + "retrace your steps" = plusieurs encodages imbriqués (chain), et il faut **inverser la chaîne** à un moment (retracing = going backward).

### Identifier les encodages un par un

**Règle générale :** Quand on voit un texte encodé, on regarde le charset :

- Que des `a-zA-Z0-9+/=` → Base64
- Que des `0-9a-f` → Hexadécimal
- Que des `A-Z2-7=` → Base32
- Mix alphanum + `!#$%...` → Base85 ou Base91
- Mix alphanum `a-km-zA-HJ-NP-Z1-9` (pas de 0, l, I, O) → Base58

## Script complet

```python
import base64

data = open('cipher.txt', 'rb').read().strip()

# Étape 1: Base64
step1 = base64.b64decode(data)

# Étape 2: Base85
step2 = base64.b85decode(step1)

# Étape 3: Hex
step3 = bytes.fromhex(step2.decode())

# Étape 4: Base32
step4 = base64.b32decode(step3)

# Étape 5: Reverse + Base64
s = step4.decode()
reversed_s = s[::-1]
padded = reversed_s + '=' * (-len(reversed_s) % 4)
flag = base64.b64decode(padded)

print(flag.decode())
```

## Récapitulatif de la chaîne

```
cipher.txt
    ↓ Base64 decode
    ↓ Base85 decode
    ↓ Hex decode
    ↓ Base32 decode
    ↓ REVERSE la string  ← "retrace your steps"
    ↓ Base64 decode
    FLAG: EcowasCTF{n3st3d_l4y3rs_0f_s4nk0f4_w1sd0m}
```

## Flag

```
EcowasCTF{n3st3d_l4y3rs_0f_s4nk0f4_w1sd0m}
```

## Ressources

- [dCode - Identifier un encodage](https://www.dcode.fr/identification-chiffrement)
- [CyberChef - Magic (auto-detect)](https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,''))
- [Base64 vs Base32 vs Base85 — différences](https://en.wikipedia.org/wiki/Base64)

---

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
