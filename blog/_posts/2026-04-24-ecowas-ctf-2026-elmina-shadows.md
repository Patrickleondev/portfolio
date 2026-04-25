---
layout: post
title: "ECOWAS CTF 2026 — Elmina Shadows [Steganography/Medium]"
date: 2026-04-24 11:15:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [steganography, xor, prng, png, zip-comment, repeating-key, medium]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Steganography · **Difficulté :** ⭐⭐ Medium · **Points :** 200  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `elmina.png` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/62_elmina_shadows.png) |

---

## 1. Analyse initiale — Qu'est-ce qu'on a ?

### Étape 1 : Examiner le ZIP

```bash
unzip -v elmina.zip
# → fort.png (269447 bytes, méthode stored = pas de compression)
```

```bash
python3 -c "
import zipfile
with zipfile.ZipFile('elmina.zip') as z:
    print('Comment ZIP:', z.comment)
    for info in z.infolist():
        print(info.filename, info.file_size)
"
# Comment ZIP: b'Shadow remembers its name: ELMINA'
```

**Trouvaille clé** : Le commentaire ZIP dit `Shadow remembers its name: ELMINA`. C'est la clé !

> **Ressource** : Les fichiers ZIP peuvent contenir un commentaire global. C'est une info souvent oubliée — à toujours vérifier avec `zipinfo` ou Python.

### Étape 2 : Examiner l'image

```python
from PIL import Image
import numpy as np

img = Image.open("fort.png")
print(img.size, img.mode)  # (300, 300) RGB
arr = np.array(img)

# Statistiques des valeurs de pixels
for ch, name in enumerate(['R', 'G', 'B']):
    vals = arr[:,:,ch].flatten()
    print(f"{name}: min={vals.min()}, max={vals.max()}, mean={vals.mean():.1f}")
```

**Résultat** :

```
R: min=20, max=180, mean=100.0
G: min=20, max=181, mean=100.1
B: min=20, max=180, mean=100.0
```

Observations importantes :

- Les pixels sont dans la plage [20, 180] — pas [0, 255] ! C'est bizarre.
- L'image ressemble à du bruit coloré aléatoire.
- Il y a 3 pixels avec G=181 (légèrement hors plage normale).

L'image ressemble à un **masque one-time pad** ou une **image générée par PRNG**.

---

## 2. Les outils classiques (tous ont échoué)

### zsteg — LSB dans PNG

```bash
docker run --rm -v $(pwd):/data dominicbreuker/stego-toolkit zsteg /data/fort.png
```

→ Aucun résultat pertinent.

### steghide — données cachées avec mot de passe

```bash
steghide extract -sf fort.bmp -p "ELMINA"
steghide extract -sf fort.bmp -p "elmina"
steghide extract -sf fort.bmp -p ""
# ... toutes les variations
```

→ Échec. Steghide ne trouve rien.

### stegseek — bruteforce steghide avec rockyou.txt

```bash
docker run rickdejager/stegseek fort.bmp rockyou.txt
```

→ `[!] error: Could not find a valid passphrase.` — Pas un challenge steghide.

### stegoveritas — analyse automatique

```bash
stegoveritas fort.png
```

→ Fichier `LSBExtracted.bin` vide. Rien.

### binwalk — fichiers cachés

```bash
binwalk elmina.zip
binwalk fort.png
```

→ Aucun fichier caché détecté.

### Analyse des chunks PNG

```python
import struct, zlib

with open("fort.png", "rb") as f:
    data = f.read()

pos = 8
while pos < len(data):
    length = struct.unpack('>I', data[pos:pos+4])[0]
    chunk_type = data[pos+4:pos+8]
    print(f"Chunk {chunk_type} à {pos}: {length} bytes")
    pos += 12 + length
```

→ Structure normale : IHDR, IDAT×5, IEND. Rien d'anormal.

---

## 3. Piste : les valeurs de pixels sont trop régulières

Les pixels sont tous dans [20, 180]. C'est exactement la plage que produit `random.randint(20, 180)` en Python ! L'image est peut-être générée avec un **PRNG (générateur de nombres pseudo-aléatoires)** et la donnée cachée est le **XOR/différence** avec l'image originale.

### Concept : Visual Secret Sharing / PRNG Cover

```
Image_cachée = Image_réelle XOR Image_PRNG
              ou
Image_cachée = Image_réelle - Image_PRNG (mod 256)
```

Pour récupérer `Image_réelle`, on a besoin du **seed** du PRNG.

---

## 4. Trouver le seed

On teste des seeds évidents :

```python
import random
import numpy as np
from PIL import Image

arr = np.array(Image.open("fort.png")).astype(np.int16)
h, w, c = arr.shape
n_pixels = h * w * c  # 300*300*3 = 270000

seeds_to_try = [
    "ELMINA", "elmina", "shadow", "fort", "castle", 42, 0, 1, 300
]

for seed in seeds_to_try:
    random.seed(seed)
    # Générer le masque PRNG comme l'image de fond
    shadow = np.array([random.randint(20, 180) for _ in range(n_pixels)],
                      dtype=np.int16).reshape(h, w, c)
  
    diff = (arr - shadow) % 256
    unique_vals = len(np.unique(diff.flatten()))
    zeros = np.sum(diff == 0)
  
    print(f"Seed {seed}: valeurs_uniques={unique_vals}, zeros={zeros}/{n_pixels}")
```

**Résultat crucial** :

```
Seed ELMINA: valeurs_uniques=256, zeros=89842
Seed elmina: valeurs_uniques=256, zeros=89701
Seed shadow: valeurs_uniques=256, zeros=89812
Seed 42:     valeurs_uniques=3,   zeros=269808  ← !!!
Seed 0:      valeurs_uniques=256, zeros=89823
```

Avec **seed=42**, la différence n'a que **3 valeurs uniques** : `{0, 1, 255}` !

- `0` → les deux images sont identiques (pas de modification)
- `1` → image_réelle = image_PRNG + 1 (le LSB a été mis à 1)
- `255` → image_réelle = image_PRNG - 1 (le LSB a été mis à 0) [255 ≡ -1 mod 256]

C'est une modification de ±1 sur certains pixels — c'est exactement la signature d'une **stéganographie LSB** !

> **Comprendre 0/1/255** : Si `shadow[i] = 100` et `fort[i] = 101`, alors `diff = 1` → le bit a été modifié vers le haut. Si `fort[i] = 99`, `diff = 255 = -1 mod 256` → modifié vers le bas. Les deux représentent un bit LSB changé.

---

## 5. Analyser les pixels modifiés

```python
random.seed(42)
shadow = np.array([random.randint(20, 180) for _ in range(n_pixels)],
                  dtype=np.int16).reshape(h, w, c)
diff = (arr - shadow) % 256

# Quels canaux sont modifiés ?
for ch, name in enumerate(['R', 'G', 'B']):
    nz = np.sum(diff[:,:,ch] != 0)
    print(f"{name}: {nz} pixels modifiés")
```

**Résultat** :

```
R: 0 pixels modifiés
G: 192 pixels modifiés   ← Seulement le canal Vert !
B: 0 pixels modifiés
```

Et ces 192 pixels modifiés sont **uniquement dans les lignes 0 et 1** (les deux premières lignes de l'image) :

- Ligne 0 : 161 pixels modifiés
- Ligne 1 : 31 pixels modifiés

Total : 192 modifications = 192 bits = 24 octets.

---

## 6. Extraire le message LSB

Le canal Vert contient le message. Chaque pixel du canal G a un LSB qui encode un bit du message.

```python
# Extraire le LSB du canal G des lignes 0 et 1
g_channel = arr[:,:,1]

bits = []
for row in range(2):  # Lignes 0 et 1
    for col in range(300):  # 300 colonnes
        bits.append(int(g_channel[row, col]) & 1)  # LSB

# Décoder en octets (MSB en premier)
byte_data = bytearray()
for i in range(0, len(bits) - 7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i + j]
    byte_data.append(byte)

print(f"Données brutes (hex) : {byte_data.hex()}")
print(f"Données brutes (texte) : {byte_data.decode('latin-1')}")
```

**Résultat** :

```
Données brutes (hex) : 002b002f223e2f32...
Données brutes (texte) : +/">/2...}-(}#}...
```

C'est du "texte" mais pas encore lisible. Il faut appliquer la clé !

---

## 7. Déchiffrement XOR avec la clé ELMINA

Le message est chiffré avec un **XOR à clé répétée** (Repeating Key XOR, aussi appelé Vigenère XOR), avec la clé `ELMINA`.

```python
key = b"ELMINA"

# Essayer différents décalages de la clé (offset)
for offset in range(6):
    xored = bytes(byte_data[i] ^ key[(i + offset) % len(key)]
                  for i in range(len(byte_data)))
    text = xored.decode("utf-8", errors="replace")
    printable = sum(1 for b in xored if 32 <= b <= 126)
    print(f"Offset {offset}: {text[:60]} (lisible: {printable}/{len(xored)})")
```

**Résultat** :

```
Offset 0: EgMflj~KQEs8ae4m...
Offset 1: LfIac{cOVJw1`a3b...
Offset 2: MbNngrb{HYN~0df<...
Offset 3: IeAjnsf|G]G4ci8o...
Offset 4: NjEcowasCTF{3lm1n4_sh4d0ws_x0r_r3p34t1ng_k3y}  ← !!!
Offset 5: AnLbkpnwJUB|<hd0...
```

Avec **offset=4** (la clé commence à la 5ème lettre, `N`), on obtient le flag !

> **Pourquoi un offset ?** Le padding nul au début du message (`0x00 0x00`) a fait que les premiers octets ne correspondent pas au début de la clé. L'auteur a commencé le chiffrement à une position particulière dans la clé.

---

## 8. Script complet de résolution

```python
#!/usr/bin/env python3
"""Résolution complète du challenge Elmina Shadows"""
import random
import numpy as np
from PIL import Image

# --- Étape 1 : Charger l'image ---
img = Image.open("fort.png")
arr = np.array(img).astype(np.int16)
h, w, c = arr.shape

# --- Étape 2 : Générer l'image PRNG (seed=42) ---
n_pixels = h * w * c
random.seed(42)
shadow = np.array([random.randint(20, 180) for _ in range(n_pixels)],
                  dtype=np.int16).reshape(h, w, c)

# --- Étape 3 : Vérifier (optionnel) ---
diff = (arr - shadow) % 256
print(f"Valeurs uniques dans la diff : {np.unique(diff.flatten())}")
# → [0 1 255] — Parfait !

# --- Étape 4 : Extraire les LSB du canal G (lignes 0-1) ---
g_channel = arr[:,:,1]
bits = []
for row in range(2):
    for col in range(300):
        bits.append(int(g_channel[row, col]) & 1)

byte_data = bytearray()
for i in range(0, len(bits) - 7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i + j]
    byte_data.append(byte)

# --- Étape 5 : XOR avec ELMINA (offset=4) ---
key = b"ELMINA"
offset = 4
flag_bytes = bytes(byte_data[i] ^ key[(i + offset) % len(key)]
                   for i in range(len(byte_data)))
flag = flag_bytes.decode("utf-8", errors="replace")

# Extraire le flag
import re
match = re.search(r'EcowasCTF\{[^}]+\}', flag)
print(f"Flag : {match.group()}")
# → EcowasCTF{3lm1n4_sh4d0ws_x0r_r3p34t1ng_k3y}
```

---

## 9. Récapitulatif de la logique du challenge

```
┌─────────────────────────────────────────────────────────┐
│              COMMENT LE CHALLENGE A ÉTÉ CRÉÉ            │
│                                                          │
│  Message secret                                          │
│      ↓                                                   │
│  XOR avec clé "ELMINA" (offset 4) → message_chiffré     │
│      ↓                                                   │
│  Embedding dans LSB canal G (lignes 0-1 de l'image)     │
│      ↓                                                   │
│  Image générée par PRNG(seed=42) utilisée comme base     │
│      ↓                                                   │
│  Image finale : fort.png                                 │
└─────────────────────────────────────────────────────────┘

POUR RÉSOUDRE :
  fort.png
      ↓
  Générer PRNG(seed=42) → trouver les pixels modifiés
      ↓
  Extraire LSB canal G → message_chiffré
      ↓
  XOR avec "ELMINA" (offset 4) → flag !
```

---

## 10. Pourquoi c'était difficile

Ce challenge était retors pour plusieurs raisons :

1. **Les outils classiques ne fonctionnent pas** : zsteg, steghide, stegoveritas sont inutiles car la stéganographie utilise une technique personnalisée.
2. **La clé (seed=42) n'est pas dans le fichier** : Le seed est le nombre mystérieux `42` (référence à *Le Guide du Voyageur Galactique*). Seul le bruteforce ou l'intuition permettait de le trouver.
3. **Double couche** : Il fallait d'abord trouver le mécanisme PRNG, puis trouver la clé XOR avec son offset.
4. **L'indice "deux ombres"** dans la description faisait référence à :

   - L'**image PRNG** (une ombre = le masque aléatoire, seed 42)
   - La **clé XOR ELMINA** (l'autre ombre = la clé de chiffrement)

---

## 11. Résumé des approches tentées

| Approche                                     | Résultat                       |
| -------------------------------------------- | ------------------------------- |
| `zsteg`, `steghide`, `stegoveritas`    | ❌ Aucun résultat              |
| Bruteforce steghide avec rockyou.txt         | ❌ Aucun mot de passe trouvé   |
| Analyse chunks PNG                           | ❌ Structure normale            |
| LSB canaux R/G/B sans clé                   | ❌ Données illisibles          |
| XOR entre canaux R/G/B                       | ❌ Bruit aléatoire             |
| Décryptage AES/RC4                          | ❌ Faux positif                 |
| Comparaison avec PRNG seed "ELMINA"          | ❌ Diff non structurée         |
| Comparaison avec PRNG seed 42                | ✅ Diff = {0, 1, 255} seulement |
| LSB canal G lignes 0-1 + XOR ELMINA offset 4 | ✅**Flag trouvé !**      |

---

## 12. Ressources utiles

- [Repeating Key XOR — cryptopals.com](https://cryptopals.com/sets/1/challenges/6) — challenge classique pour comprendre le XOR répété
- [PRNG-based steganography](https://en.wikipedia.org/wiki/Steganography#Digital_steganography) — explication générale
- [CyberChef](https://gchq.github.io/CyberChef/) — outil en ligne pour XOR, LSB, etc.
- [CTF 101 — Steganography](https://ctf101.org/forensics/what-is-steganography/)
- [PyCryptodome](https://pycryptodome.readthedocs.io/) — bibliothèque Python pour la crypto
-  [picoCTF Forensics/Stego challenges](https://picoctf.org/) — pour pratiquer

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
