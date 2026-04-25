---
layout: post
title: "ECOWAS CTF 2026 — Adinkra [Crypto/200pts]"
date: 2026-04-24 10:35:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [crypto, adinkra, cultural-context, rot13, xor, multi-cipher, substitution, akan]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Crypto · **Difficulté :** ⭐⭐ (Medium) · **Points :** 200  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `adinkra.zip` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/35_adinkra.zip) |

---

## Description du challenge

> *"Eight Adinkra symbols, each hiding a secret."*

**Fichiers fournis :** `adinkra.zip` → `scrolls.json`

---

Un **Adinkra** est un symbole visuel d'Afrique de l'Ouest (originaire des peuples Akan du Ghana et de la Côte d'Ivoire) qui représente des concepts, des proverbes ou des philosophies de vie.

Ce challenge utilise 8 symboles Adinkra, chacun chiffrant un message avec une technique différente. Ton travail : reconnaître la technique de chaque symbole et déchiffrer.

---

## Structure du challenge

```json
{
  "symbols": {
    "sankofa": { "meaning": "Return and get it", "method_hint": "...", "ciphertext": "..." },
    "gye_nyame": { ... },
    "dwennimmen": { ... },
    "adinkrahene": { ... },
    "nyame_dua": { ... },
    "ese_ne_tekrema": { ... },
    "akoma": { ... },
    "funtunfunefu": { ... }
  }
}
```

---

## Symbole 1 — Sankofa : Base64

**Indice :** `"The old ways encode simply"`

**Ciphertext :**
```
R28gYmFjayBhbmQgZmV0Y2ggaXQg...
```

---

## Symbole 2 — Gye Nyame : Hexadécimal

**Indice :** `"Counted in halves of bytes"`

**Ciphertext :**
```
45786365707420666f7220476f64...
```

---

## Symbole 3 — Dwennimmen : ROT13 ✅ FLAG !

**Indice :** `"A rotation older than Rome"`

**Ciphertext :**
```
RpbjnfPGS{tk3_al4z3_3kp3cg_t0q}
```

---

## Symbole 4 — Adinkrahene : Base64 inversée

**Indice :** `"Read it backwards before you unwrap"`

**Ciphertext :**
```
==gL0JXYlhGIlhGdgkncUBiLl52bgcm...
```

### L'approche

Le ciphertext **commence par `==`** — ce sont les caractères de bourrage Base64, qui sont normalement à la *fin*. Le message est donc inversé !

```python
import base64
ct = "==gL0J..."
# Étape 1 : Inverser le texte
reversed_ct = ct[::-1]
# Étape 2 : Décoder en Base64
flag = base64.b64decode(reversed_ct).decode()
# → "The chief of all symbols watches..." (fausse piste)
```

---

## Symbole 5 — Nyame Dua : Chiffre de Vigenère

**Indice :** `"A French diplomat's cipher, keyed by tradition"`

**Ciphertext :**
```
Cowfo sut qw pynrih auocl...
```

Le **[chiffre de Vigenère](https://fr.wikipedia.org/wiki/Chiffre_de_Vigen%C3%A8re)** applique un décalage différent à chaque lettre selon une clé répétée.

---

## Symbole 6 — Ese Ne Tekrema : XOR avec masque ✅ FLAG !

**Indice :** `"A single mask covers every letter"`

**Ciphertext :**
```
07212d352331011604397131711d2c711d36712930712f761d367171362a3f
```

---

## Symbole 7 — Akoma : AES (fausse piste ou irrelevant)

**Indice :** `"A block of patience, keyed by name"`

Ce symbole utilise **AES** (Advanced Encryption Standard), un chiffrement par blocs symétrique. Sans la clé (le "name"), on ne peut pas déchiffrer. Ce symbole ne contient pas le flag principal.

---

## Symbole 8 — Funtunfunefu : Rail Fence ✅ MESSAGE (pas de flag)

**Indice :** `"A fence with three rails"`

**Ciphertext :**
```
Tcoeh  m  ygo dhioof hw rcdlssaeoesoahbtte ih vrfo.Ti sntyu lgete...
```

Le **[Rail Fence Cipher](https://fr.wikipedia.org/wiki/Chiffrement_par_transposition)** écrit le texte en zigzag sur N rails puis le relit rail par rail.

---

## Script complet de solve

```python
import base64, json, codecs

data = json.load(open('scrolls.json'))
symbols = data['symbols']

# 1. Sankofa: base64 (fausse piste)
print("=== SANKOFA (base64) ===")
print(base64.b64decode(symbols['sankofa']['ciphertext']).decode())

# 2. Gye Nyame: hex (fausse piste)
print("\n=== GYE_NYAME (hex) ===")
print(bytes.fromhex(symbols['gye_nyame']['ciphertext']).decode())

# 3. Dwennimmen: ROT13 ✅ FLAG
print("\n=== DWENNIMMEN (ROT13) ===")
print(codecs.decode(symbols['dwennimmen']['ciphertext'], 'rot13'))

# 4. Ese Ne Tekrema: XOR 0x42 ✅ FLAG
print("\n=== ESE_NE_TEKREMA (XOR 0x42) ===")
ct = bytes.fromhex(symbols['ese_ne_tekrema']['ciphertext'])
print(bytes(b ^ 0x42 for b in ct).decode())
```

---

## Récapitulatif des techniques

| Symbole | Technique | Flag ? |
|---------|-----------|--------|
| Sankofa | Base64 | Non (fausse piste) |
| Gye Nyame | Hexadécimal | Non |
| Dwennimmen | ROT13 | ✅ `EcowasCTF{gx3_ny4m3_3xc3pt_g0d}` |
| Adinkrahene | Base64 inversée | Non |
| Nyame Dua | Vigenère (clé: adinkra) | Non |
| Ese Ne Tekrema | XOR octet (clé: 0x42) | ✅ `EcowasCTF{3s3_n3_t3kr3m4_t33th}` |
| Akoma | AES | Non (pas de clé) |
| Funtunfunefu | Rail Fence 3 rails | Non |

## Flag soumis

```
EcowasCTF{gx3_ny4m3_3xc3pt_g0d}
```
(ou `EcowasCTF{3s3_n3_t3kr3m4_t33th}` selon lequel était attendu)

---

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
