---
layout: post
title: "ECOWAS CTF 2026 — Adinkra Echoes [Steganography/Medium]"
date: 2026-04-24 11:00:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [steganography, lsb, png, alpha-channel, vigenere, medium]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Steganography · **Difficulté :** ⭐⭐ Medium · **Points :** 200  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `adinkra.png` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/61_adinkra_echoes.png) |

---

## 1. Outillage recommandé

Avant de plonger, voici les outils utiles pour la stéganographie :

| Outil             | Usage                             | Installation                 |
| ----------------- | --------------------------------- | ---------------------------- |
| `file`, `xxd` | Identifier le type de fichier     | Natif Linux                  |
| `exiftool`      | Lire les métadonnées            | `apt install exiftool`     |
| `zsteg`         | LSB dans PNG/BMP                  | `gem install zsteg`        |
| `steghide`      | Stéganographie avec mot de passe | `apt install steghide`     |
| `stegoveritas`  | Analyse automatique               | `pip install stegoveritas` |
| Python + Pillow   | Analyser les pixels               | `pip install Pillow numpy` |
| `binwalk`       | Chercher des fichiers cachés     | `apt install binwalk`      |

> **Ressource débutant** : [CTF Steganography Checklist](https://github.com/DominicBreuker/stego-toolkit) — un Docker avec tous les outils préconfigurés.

---

## 2. Première analyse — « Qu'est-ce qu'on voit ? »

```bash
file adinkra.png
# → PNG image data, 200 x 200, 8-bit/color RGBA, non-interlaced
```

L'image est en **RGBA** (4 canaux : Rouge, Vert, Bleu, Alpha). La présence du canal Alpha est déjà suspecte — en PNG, l'alpha gère la transparence, mais c'est aussi un endroit classique pour cacher des données.

### Lire les métadonnées

```bash
exiftool adinkra.png
```

Ou en Python :

```python
from PIL import Image

img = Image.open("adinkra.png")
print(img.format, img.size, img.mode)  # PNG (200, 200) RGBA

# Lire les chunks PNG (métadonnées)
from PIL import PngImagePlugin
for key, val in img.info.items():
    print(f"{key}: {val}")
```

**Résultat** : Un chunk `tEXt` contient :

```
hint: Nyansapo keeps the key
```

Le mot **Nyansapo** est un symbole Adinkra signifiant "nœud de sagesse" — il représente la connaissance et l'astuce. C'est clairement notre clé !

> **Ressource** : [PNG chunk types expliqués](https://www.w3.org/TR/PNG/#11Chunks)

---

## 3. Extraction LSB du canal Alpha

### Pourquoi le canal Alpha ?

En stéganographie LSB (Least Significant Bit), on cache des données dans le **bit de poids faible** de chaque pixel. Modifier le LSB change la valeur de ±1, ce qui est imperceptible à l'œil nu.

Le canal Alpha va de 0 (transparent) à 255 (opaque). Si tous les pixels sont opaques (alpha=255=`11111111`), on peut modifier leur LSB sans changer l'apparence visuelle.

### Code d'extraction

```python
from PIL import Image
import numpy as np

img = Image.open("adinkra.png")
arr = np.array(img)

# Extraire le LSB du canal Alpha (canal 3)
alpha = arr[:, :, 3]
lsb_bits = alpha.flatten() & 1  # Garde seulement le bit de poids faible

# Regrouper les bits en octets (MSB first)
bytes_data = bytearray()
for i in range(0, len(lsb_bits) - 7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | int(lsb_bits[i + j])
    bytes_data.append(byte)

print(bytes_data.decode("utf-8", errors="replace"))
```

**Résultat** :

```
RaojssRHS{3pz03g_0f_4d1bxp4_n1v3a3r3}
```

Ça ressemble à un flag chiffré ! On voit la structure `XXXXX{...}` et des l33tspeak (lettres remplacées par des chiffres). Le texte correspond à `EcowasCTF{3ch03s_0f_4d1nkr4_v1g3n3r3}` chiffré — mais avec quoi ?

---

## 4. Identifier le chiffrement — Vigenère

Le nom du challenge s'appelle "Adinkra **Echoes**", et le hint mentionne "Nyansapo **keeps the key**". Le terme "clé" + chiffrement de substitution alphabétique → **Chiffre de Vigenère**.

### C'est quoi le Vigenère ?

Le chiffre de Vigenère chiffre lettre par lettre en utilisant une clé qui se répète :

```
Texte clair  : H  E  L  L  O
Clé          : K  E  Y  K  E   (répétée)
Décalage     : 10 4  24 10 4
Texte chiffré: R  I  J  V  S
```

Formule : `C[i] = (P[i] + K[i % len(K)]) mod 26` pour les lettres

> **Ressource** : [Vigenère sur Wikipedia](https://fr.wikipedia.org/wiki/Chiffre_de_Vigenère)
> **Outil en ligne** : [dcode.fr Vigenère](https://www.dcode.fr/chiffre-vigenere)

Notre clé est `NYANSAPO`.

---

## 5. Première tentative (échec) — Vigenère standard

On essaie le déchiffrement Vigenère classique :

```python
def vigenere_decrypt_standard(ciphertext, key):
    """Vigenère classique : la clé n'avance QUE sur les lettres alphabétiques"""
    key = key.upper()
    key_idx = 0
    result = ""
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            if char.isupper():
                result += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                result += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            key_idx += 1  # ← Avance SEULEMENT sur les lettres
        else:
            result += char  # ← Les non-lettres passent sans avancer la clé
    return result

ciphertext = "RaojssRHS{3pz03g_0f_4d1bxp4_n1v3a3r3}"
print(vigenere_decrypt_standard(ciphertext, "NYANSAPO"))
```

**Résultat** : `EcowasCTF{3rz03t_0n_4d1mjc4_p1v3n3z3}`

Pas tout à fait le bon flag. Les lettres dans `{...}` ne correspondent pas. Quelque chose cloche avec la gestion des caractères non-alphabétiques.

---

## 6. Comprendre le problème — Avance de la clé

Le problème est dans **quand on avance l'index de la clé**.

### Variante A : Vigenère standard

La clé n'avance que sur les lettres alphabétiques. `{`, `_`, et les chiffres ne consomment pas de position dans la clé.

### Variante B : Vigenère étendu (utilisé ici)

La clé avance sur **tous les caractères** (y compris `{`, `_`, chiffres), mais ne déplace que les lettres alphabétiques.

```python
def vigenere_decrypt_extended(ciphertext, key):
    """La clé avance sur TOUS les caractères, mais déplace seulement les lettres"""
    key = key.upper()
    key_idx = 0
    result = ""
    for char in ciphertext:
        shift = ord(key[key_idx % len(key)]) - ord('A')
        key_idx += 1  # ← Avance sur TOUS les caractères
      
        if char.isalpha():  # ← Mais déplace seulement les lettres
            if char.isupper():
                result += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                result += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
        else:
            result += char  # Les non-lettres passent TELS QUELS
    return result

print(vigenere_decrypt_extended("RaojssRHS{3pz03g_0f_4d1bxp4_n1v3a3r3}", "NYANSAPO"))
```

**Résultat** : `EcowasCTF{3ch03s_0f_4d1nkr4_v1g3n3r3}` ✅

> **Leçon** : En CTF, les implémentations de chiffres classiques peuvent avoir des variantes subtiles. Si le déchiffrement "presque marche", essayez de modifier la logique d'avancement de la clé.

---

## 7. Flag final

```
EcowasCTF{3ch03s_0f_4d1nkr4_v1g3n3r3}
```

Traduit du l33tspeak : "echoes of adinkra vigenere" — une belle référence au thème du challenge !

---

## 8. Script complet

```python
#!/usr/bin/env python3
from PIL import Image
import numpy as np

# --- Étape 1 : Lire l'image ---
img = Image.open("adinkra.png")
arr = np.array(img)

# Vérifier le hint dans les métadonnées
print("Métadonnées:", img.info)  # hint: Nyansapo keeps the key

# --- Étape 2 : Extraire le LSB du canal Alpha ---
alpha = arr[:, :, 3]
lsb_bits = alpha.flatten() & 1

bytes_data = bytearray()
for i in range(0, len(lsb_bits) - 7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | int(lsb_bits[i + j])
    bytes_data.append(byte)

# Trouver le message
raw = bytes_data.decode("latin-1")
start = raw.find("Ecowas") if "Ecowas" in raw else 0
# Chercher la structure XxxxxXXX{...}
import re
match = re.search(r'[A-Za-z]+\{[^}]+\}', raw)
ciphertext = match.group() if match else raw
print(f"Texte chiffré : {ciphertext}")

# --- Étape 3 : Déchiffrer Vigenère (variante étendue) ---
def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    key_idx = 0
    result = ""
    for char in ciphertext:
        shift = ord(key[key_idx % len(key)]) - ord('A')
        key_idx += 1  # Avance sur TOUS les caractères
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
        else:
            result += char
    return result

key = "NYANSAPO"
flag = vigenere_decrypt(ciphertext, key)
print(f"Flag : {flag}")
```

---

## 9. Résumé des approches

| Étape                            | Approche                        | Résultat                                   |
| --------------------------------- | ------------------------------- | ------------------------------------------- |
| Analyse initiale                  | `exiftool`, métadonnées PNG | ✅ Trouvé hint "Nyansapo keeps the key"    |
| Extraction des données           | LSB canal Alpha                 | ✅ Texte chiffré extrait                   |
| Déchiffrement Vigenère standard | Clé n'avance que sur alpha     | ❌`EcowasCTF{3rz03t_0n_4d1mjc4_p1v3n3z3}` |
| Déchiffrement Vigenère étendu  | Clé avance sur tous les chars  | ✅ Flag correct                             |

---

## 10. Ressources pour aller plus loin

- 📖 [Introduction à la stéganographie](https://ctf101.org/forensics/what-is-steganography/)
- 🔧 [Stego Toolkit (Docker)](https://github.com/DominicBreuker/stego-toolkit)
- 🔧 [StegOnline — outil LSB visuel](https://georgeom.net/StegOnline/upload)
- 📖 [Chiffre de Vigenère — dcode.fr](https://www.dcode.fr/chiffre-vigenere)
- 📖 [LSB Steganography expliqué](https://www.geeksforgeeks.org/lsb-based-image-steganography-using-matlab/)
- 🎓 [PicoCTF — challenges stéganographie pour débutants](https://picoctf.org/)

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
