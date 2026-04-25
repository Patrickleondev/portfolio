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

## 📖 Notions de base à connaître

### Qu'est-ce qu'un Adinkra ?

Un **Adinkra** est un symbole visuel d'Afrique de l'Ouest (originaire des peuples Akan du Ghana et de la Côte d'Ivoire) qui représente des concepts, des proverbes ou des philosophies de vie.

Ce challenge utilise 8 symboles Adinkra, chacun chiffrant un message avec une technique différente. Ton travail : reconnaître la technique de chaque symbole et déchiffrer.

### Qu'est-ce que `scrolls.json` ?

C'est un fichier JSON avec 8 entrées, chacune contenant :
- `meaning` : la signification du symbole
- `method_hint` : un indice sur la méthode de chiffrement
- `ciphertext` : le texte chiffré

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

### Qu'est-ce que Base64 ?

**Base64** est un encodage (pas un chiffrement !) qui convertit des données binaires en texte ASCII en utilisant 64 caractères : `A-Z`, `a-z`, `0-9`, `+`, `/`, et `=` pour le bourrage.

Caractéristiques visuelles :
- Longueur multiple de 4
- Se termine souvent par `=` ou `==`
- N'utilise que les 64 caractères ci-dessus

```python
import base64
ct = "R28gYmFjayBhbmQgZmV0Y2ggaXQg..."
flag = base64.b64decode(ct).decode()
# → "Go back and fetch it — but not here..."  (message trompeur, pas le flag)
```

> ⚠️ Ce symbole *ne contient pas de flag* — c'est une fausse piste ! Le message déchiffré dit explicitement que ce n'est pas le flag.

---

## Symbole 2 — Gye Nyame : Hexadécimal

**Indice :** `"Counted in halves of bytes"`

**Ciphertext :**
```
45786365707420666f7220476f64...
```

### Qu'est-ce que l'hexadécimal ?

L'hexadécimal (base 16) représente chaque octet par deux caractères : `0-9` et `a-f`.

Un demi-octet (4 bits) = 1 chiffre hexadécimal → d'où l'indice "halves of bytes" (moitiés d'octets).

```python
bytes.fromhex("45786365707420666f7220476f64...").decode()
# → "Except for God, I fear none..." (encore une fausse piste)
```

---

## Symbole 3 — Dwennimmen : ROT13 ✅ FLAG !

**Indice :** `"A rotation older than Rome"`

**Ciphertext :**
```
RpbjnfPGS{tk3_al4z3_3kp3cg_t0q}
```

### Qu'est-ce que ROT13 ?

**ROT13** ("Rotation de 13") est le chiffre de César avec un décalage de 13. C'est le chiffre le plus simple existant.

Explication du chiffre de César :
```
Alphabet :   A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
ROT13 →      N O P Q R S T U V W X Y Z A B C D E F G H I J K L M
```

Propriété magique : ROT13 est **sa propre réciproque** ! Appliquer ROT13 deux fois redonne le texte original.

L'indice "A rotation older than Rome" fait référence à César (Jules César l'utilisait avant Rome, enfin presque).

```python
import codecs
ct = "RpbjnfPGS{tk3_al4z3_3kp3cg_t0q}"
flag = codecs.decode(ct, 'rot13')
print(flag)
# → "EcowasCTF{gx3_ny4m3_3xc3pt_g0d}"
```

> **FLAG :** `EcowasCTF{gx3_ny4m3_3xc3pt_g0d}`

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

### Qu'est-ce que le chiffre de Vigenère ?

Le **chiffre de Vigenère** (inventé par Blaise de Vigenère, diplomate français du XVIe siècle — d'où l'indice "French diplomat's") est une généralisation du chiffre de César : au lieu d'un seul décalage fixe, on utilise une **clé** qui détermine un décalage différent pour chaque lettre.

Exemple avec la clé `"KEY"` :
```
Texte clair : H  E  L  L  O
Clé répétée : K  E  Y  K  E
Décalage    : 10 4  24 10 4
Chiffré     : R  I  J  V  S
```

La clé ici est **"tradition"** (dans l'indice : "keyed by tradition").

```python
def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    result = []
    ki = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - ord('a')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

print(vigenere_decrypt("Cowfo sut qw pynrih auocl...", "adinkra"))
```

> Avec la clé `adinkra`, on obtient la fausse piste. Le vrai flag n'est pas dans ce symbole non plus.

---

## Symbole 6 — Ese Ne Tekrema : XOR avec masque ✅ FLAG !

**Indice :** `"A single mask covers every letter"`

**Ciphertext :**
```
07212d352331011604397131711d2c711d36712930712f761d367171362a3f
```

### Qu'est-ce que XOR ?

**XOR** ("eXclusive OR", OU exclusif) est une opération binaire sur les bits :
```
0 XOR 0 = 0
0 XOR 1 = 1
1 XOR 0 = 1
1 XOR 1 = 0
```

Propriété magique : `a XOR k XOR k = a` — XOR deux fois avec la même clé redonne le texte original.

"A single mask" = une seule valeur de clé appliquée à **tous** les octets.

```python
ct_hex = "07212d352331011604397131711d2c711d36712930712f761d367171362a3f"
ct = bytes.fromhex(ct_hex)

# Brute force : essayer toutes les clés de 0 à 255
for key in range(256):
    result = bytes(b ^ key for b in ct)
    decoded = result.decode('latin1', errors='replace')
    if decoded.startswith('EcowasCTF{'):
        print(f"Clé: 0x{key:02x} = {key}")
        print(f"Flag: {decoded}")
        break
```

Avec la clé `0x42` :
```python
key = 0x42  # = 66 en décimal
flag = bytes(b ^ key for b in ct).decode()
print(flag)
# → "EcowasCTF{3s3_n3_t3kr3m4_t33th}"
```

> **FLAG :** `EcowasCTF{3s3_n3_t3kr3m4_t33th}`

Comment trouver la clé 0x42 ? En sachant que le flag commence par `E` (= 0x45), et que `0x07 XOR key = 0x45`, donc `key = 0x07 XOR 0x45 = 0x42`.

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

### Qu'est-ce que le chiffre Rail Fence ?

Le **chiffre Rail Fence** est une transposition : on écrit le texte en zigzag sur N rails (lignes), puis on lit chaque rail de gauche à droite.

Exemple avec 3 rails pour "WEAREDISCOVEREDFLEEAHEADNOW" :
```
Rail 1: W . . . E . . . I . . . V . . . D . . . E . . . W
Rail 2: . E . R . D . S . O . E . E . F . E . A . E . N . W
Rail 3: . . A . . . C . . . R . . . . . L . . . H . . . O .

Chiffré (rails lus gauche→droite): WEIVDEWERD SOEEFEAEAW ACRLEHO
```

Pour déchiffrer, on calcule d'abord la longueur de chaque rail, puis on distribue le ciphertext et on lit en zigzag.

```python
def rail_fence_decode(ctext, nrails):
    n = len(ctext)
    cycle = 2 * (nrails - 1)
    rail_lens = [0] * nrails
    for i in range(n):
        r = i % cycle
        rail_lens[r if r < nrails else cycle - r] += 1
    rails = []
    idx = 0
    for rl in rail_lens:
        rails.append(list(ctext[idx:idx+rl]))
        idx += rl
    rail_idx = [0] * nrails
    result = []
    for i in range(n):
        r = i % cycle
        actual_r = r if r < nrails else cycle - r
        result.append(rails[actual_r][rail_idx[actual_r]])
        rail_idx[actual_r] += 1
    return ''.join(result)

ct = "Tcoeh  m  ygo dhioof hw rcdlssaeoesoahbtte ih vrfo..."
print(rail_fence_decode(ct, 3))
# → "Two crocodiles share one stomach but they fight over food. This is not your flag"
```

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
