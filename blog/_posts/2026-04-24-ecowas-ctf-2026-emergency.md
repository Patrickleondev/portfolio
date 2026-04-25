---
layout: post
title: "ECOWAS CTF 2026 — Emergency [Crypto/100pts]"
date: 2026-04-24 10:39:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [crypto, rot8000, unicode, cjk, rail-fence, cultural-context, ghana, cyberchef]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Crypto · **Difficulté :** ⭐ (Easy) · **Points :** 100  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `output.txt` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/39_emergency_output.txt) |

---

---

---

## Description du challenge

> *Call the Police please someone!!!!!!!*

**Fichier fourni :**
- `output.txt` — une ligne de caractères CJK (caractères asiatiques/chinois)

---

## 🔍 Première observation

En ouvrant `output.txt`, on voit quelque chose comme :

```
籨籂籱籯籮簾籎籽簼籬簻籬簺籷籨籭籸粀籬籷簾粀籨簼籾籁籪籽籨籯簹籼簹籼籨簽粆籌类簹簾籂籂籝粄籾籭籂簼籏籷簺
```

Des caractères **CJK** (idéogrammes chinois/japonais/coréens). C'est bizarre pour un challenge Crypto ! Ces caractères ne sont clairement **pas** du texte chinois — c'est du texte chiffré déguisé.

---

## 🧠 La vraie question : quel chiffre utilise des caractères étranges ?

**ROT8000** — le grand frère de ROT13 pour Unicode !

### ROT13 vs ROT8000

| Chiffre | Alphabet | Nombre de caractères | Rotation |
|---------|----------|---------------------|---------|
| ROT13 | a-z, A-Z | 26 + 26 = 52 | 13 positions |
| ROT5 | 0-9 | 10 | 5 positions |
| ROT8000 | Quasi-tout l'Unicode | Des milliers de groupes | Moitié du groupe |

**ROT8000** applique une rotation à des **groupes de caractères Unicode** — dont les caractères CJK, les symboles mathématiques, les emojis, etc. C'est ROT13 pour la quasi-totalité d'Unicode.

Après décodage ROT8000, on obtient du texte ASCII ordinaire... mais dans le mauvais ordre. Il faut une deuxième étape !

---

## 🌍 L'indice caché dans le challenge

Le challenge s'appelle **"Emergency"**. La description dit *"Call the Police"*. Le pays organisateur est le **Ghana**.

**Quel est le numéro d'urgence au Ghana ?** → **112**

Ce numéro va nous livrer les paramètres du deuxième chiffre :
- **1 1 2** → **Key = 11, Offset = 2**

C'est le **Rail Fence Cipher** (chiffre de la grille de clôture) !

---

### Le Rail Fence Cipher (chiffre zigzag)

Le **Rail Fence Cipher** est un chiffre de transposition classique. Le texte est écrit en zigzag sur plusieurs « rails » (rangées), puis lu rail par rail.

#### Exemple avec 3 rails

Texte original : `WEAREDISCOVEREDRUN`

```
W . . . E . . . I . . . V . . . D . . .
. E . R . D . S . O . E . E . R . N . .
. . A . . . I . . . C . . . R . . . U .
```

Lecture rail par rail : `WEIVRDEERDSOEERANR IACRU` → texte chiffré

#### Le paramètre Offset

Le **offset** (décalage) indique à quelle position dans le cycle le premier caractère se place. Avec offset=0, on commence au début d'un cycle. Avec offset=2, on commence 2 positions plus loin dans le zigzag.

C'est un paramètre optionnel qui complique le déchiffrement si on ne le connaît pas !

---

## 🔧 Solution étape par étape

### Étape 1 : Identifier ROT8000

Les caractères CJK dans `output.txt` sont des "lettres ASCII ROT8000-encodées". Sous le capot, chaque caractère du flag a été converti en un codepoint Unicode dans la plage CJK. En pratique, le bas octet du codepoint moins 9 donne le caractère original :

```python
ct = open('output.txt', encoding='utf-8').read().strip()
inter = ''.join(chr((ord(c) & 0xFF) - 9) for c in ct)
# → "_9hfe5Et3c2c1n_dowcn5w_3u8at_f0s0s_4}Cr0599T{ud93Fn1"
```

Ce texte intermédiaire contient les bonnes lettres... mais dans le mauvais ordre !

### Étape 2 : Rail Fence decode avec offset

Le texte intermédiaire est le résultat d'un **Rail Fence encode Key=11, Offset=2**. Pour décoder, on implémente la version avec offset du Rail Fence :

```python
def rail_fence_decode_offset(ct, n_rails, offset=0):
    n = len(ct)
    period = 2 * (n_rails - 1)
    
    def get_rail(pos):
        cycle_pos = (pos + offset) % period
        if cycle_pos < n_rails:
            return cycle_pos
        else:
            return period - cycle_pos
    
    # Compter les caractères par rail
    rail_lens = [0] * n_rails
    for i in range(n):
        rail_lens[get_rail(i)] += 1
    
    # Diviser le texte chiffré en rails
    rails = []
    idx = 0
    for l in rail_lens:
        rails.append(list(ct[idx:idx+l]))
        idx += l
    
    # Lire dans l'ordre zigzag
    result = []
    rail_idx = [0] * n_rails
    for i in range(n):
        r = get_rail(i)
        result.append(rails[r][rail_idx[r]])
        rail_idx[r] += 1
    return ''.join(result)

flag = rail_fence_decode_offset(inter, 11, 2)
print(flag)
```

### D'où vient Key=11, Offset=2 ?

Le numéro d'urgence au Ghana est **112** :
- **11** → Key (nombre de rails)
- **2** → Offset (décalage dans le cycle)

---

## ✅ Résultat

```
EcowasCTF{r0t_w1th_f3nc3_s0und5_fun_ce952d580499139}
```

Le flag confirme même l'approche :
- `r0t` = ROT (ROT8000)
- `w1th` = with
- `f3nc3` = fence (Rail Fence)
- `s0und5_fun` = sounds fun !

---

## 🛠️ Script de solve complet

```python
#!/usr/bin/env python3
"""
Emergency Challenge Solver
ECOWAS CTF 2026 - Challenge 39
Crypto | 100pts | Easy

Solution:
  1. Decode ROT8000 (bas octet - 9 donne le ASCII original)
  2. Rail Fence decode Key=11, Offset=2
  Indice: numéro d'urgence Ghana = 112 → Key=11, Offset=2
"""

def rail_fence_decode_offset(ct, n_rails, offset=0):
    n = len(ct)
    period = 2 * (n_rails - 1)
    
    def get_rail(pos):
        cycle_pos = (pos + offset) % period
        if cycle_pos < n_rails:
            return cycle_pos
        else:
            return period - cycle_pos
    
    rail_lens = [0] * n_rails
    for i in range(n):
        rail_lens[get_rail(i)] += 1
    
    rails = []
    idx = 0
    for l in rail_lens:
        rails.append(list(ct[idx:idx+l]))
        idx += l
    
    result = []
    rail_idx = [0] * n_rails
    for i in range(n):
        r = get_rail(i)
        result.append(rails[r][rail_idx[r]])
        rail_idx[r] += 1
    return ''.join(result)

ct = open('challs/Crypto/39_Emergency/output.txt', encoding='utf-8').read().strip()

# Étape 1 : ROT8000 decode (low_byte - 9)
inter = ''.join(chr((ord(c) & 0xFF) - 9) for c in ct)
print(f"Intermédiaire : {inter}")

# Étape 2 : Rail Fence decode Key=11, Offset=2
flag = rail_fence_decode_offset(inter, 11, 2)
print(f"Flag : {flag}")
```

---

## 💡 Leçons apprises

1. **ROT8000** : Quand le ciphertext contient des caractères Unicode inhabituels (CJK, symboles math, emojis), penser à ROT8000. C'est le ROT13 de l'Unicode.

2. **Contexte géographique** : Le pays organisateur du CTF fait partie des indices. Le Ghana organise l'ECOWAS CTF → numéro d'urgence 112 → paramètres du chiffre.

3. **Rail Fence avec Offset** : Le Rail Fence classique n'a pas d'offset. CyberChef propose un paramètre "Offset" qui décale la position de départ dans le cycle zigzag. Les implémentations Python standard ne l'incluent souvent pas — **toujours vérifier cet offset** !

4. **Le nom du challenge est un indice !** : "Emergency" → appel d'urgence → 112 → Key=11, Offset=2. Les CTF organizers embedent souvent les paramètres dans le thème du challenge.

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
