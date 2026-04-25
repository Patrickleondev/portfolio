---
layout: post
title: "ECOWAS CTF 2026 — Kora Strings [Misc/200pts]"
date: 2026-04-24 10:59:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [misc, audio, wav, riff, xor, metadata, steganography, west-africa, kora]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Misc · **Difficulté :** ⭐⭐ (Medium) · **Points :** 200  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `kora.wav` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/59_kora.wav) |

---

## 1. Outillage recommandé

| Outil                 | Usage                           | Commande                                       |
| --------------------- | ------------------------------- | ---------------------------------------------- |
| `file`              | Identifier le type              | `file kora.wav`                              |
| `xxd` / `hexdump` | Lire le fichier en hexadécimal | `xxd kora.wav                                  |
| `exiftool`          | Lire les métadonnées          | `exiftool kora.wav`                          |
| `strings`           | Trouver du texte lisible        | `strings kora.wav`                           |
| Python `wave`       | Analyser l'audio                | natif Python                                   |
| Python `numpy`      | Traitement du signal            | `pip install numpy`                          |
| Audacity              | Visualiser l'audio              | [audacityteam.org](https://www.audacityteam.org/) |

> **Ressource débutant** : [Format WAV expliqué](https://fr.wikipedia.org/wiki/WAV) — un format audio très simple basé sur des "chunks" RIFF.

---

## 2. Analyse initiale

### Étape 1 : Identifier le fichier

```bash
file kora.wav
# → RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 8000 Hz
```

```bash
exiftool kora.wav
#Dans comment je retrouve littérallement un truc
#   Comment: the string is tuned to 0x5B   ← INDICE !
```

**Trouvaille clé** : Le métadonnée `Comment` dit `the string is tuned to 0x5B`.

- `0x5B` en hexadécimal = **91** en décimal = **`[`** en ASCII
- "The string" fait référence à la corde d'un instrument de musique... ou à une chaîne de texte (string en anglais)
- "tuned to" = accordée à = la **clé** de déchiffrement est `0x5B`

> **Comprendre hex** : `0x` indique une valeur hexadécimale (base 16). `0x5B` = 5×16 + 11 = 91. En Python : `chr(0x5B)` → `'['`. [Tableau ASCII](https://www.asciitable.com/)

### Étape 2 : Chercher des strings

```bash
strings kora.wav
```

Ou en Python :

```python
import re

with open("kora.wav", "rb") as f:
    raw = f.read()

# Chercher toutes les séquences de caractères imprimables de 5+ chars
runs = re.findall(b'[ -~]{5,}', raw)
for r in runs:
    print(r)
```

**Résultat** :

```
b'WAVEfmt '
b'LIST('
b'INFOICMT'
b'the string is tuned to 0x5B'
b'flag)'
b'84,:('
b' 0k)o'
b'(/)j5<('
b'0j77&'
```

Il y a un chunk `flag` dans le fichier WAV ! Et son contenu ressemble à des données chiffrées.

---

## 3. Structure du format WAV

Le format WAV est basé sur le format **RIFF** (Resource Interchange File Format). Un fichier WAV est constitué de "chunks" (blocs de données), chacun ayant :

- 4 octets : identifiant du chunk (ex: `RIFF`, `fmt `, `data`)
- 4 octets : taille du chunk (little-endian)
- N octets : données

```
RIFF (fichier principal)
├── WAVEfmt  (format audio)
├── data     (samples audio)
└── LIST     (métadonnées optionnelles)
    └── INFO
        ├── ICMT  (commentaire) → "the string is tuned to 0x5B"
        └── flag  (chunk personnalisé !) → données cachées
```

> **Ressource** : [Spécification RIFF/WAV](https://www.mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html) — un fichier WAV peut contenir des chunks personnalisés en plus des chunks standard !

C'est exactement ça : l'auteur a ajouté un chunk personnalisé nommé `flag` dans le bloc `LIST/INFO`, contenant les données chiffrées. Cette technique est similaire au chunk `tEXt` dans le challenge Adinkra Echoes.

---

## 4. Extraire le chunk `flag`

```python
with open("kora.wav", "rb") as f:
    raw = f.read()

# Trouver le chunk 'flag'
flag_pos = raw.find(b'flag')
print(f"Chunk 'flag' trouvé à l'offset {flag_pos}")

# Structure d'un chunk RIFF :
# 4 octets : identifiant ('flag')
# 4 octets : taille en little-endian
# N octets : données

flag_data_start = flag_pos + 4  # après 'flag'
flag_len = int.from_bytes(raw[flag_data_start:flag_data_start + 4], 'little')
print(f"Taille des données : {flag_len} octets")

flag_data = raw[flag_data_start + 4:flag_data_start + 4 + flag_len]
print(f"Données hex : {flag_data.hex()}")
print(f"Données brutes : {flag_data}")
```

**Résultat** :

```
Chunk 'flag' trouvé à l'offset 16092
Taille des données : 41 octets
Données hex : 1e38342c3a28180f1d20306b296f04282f296a353c2804236b29046b35680439222f6804306a373726
Données brutes : b'\x1e84,:(\x18\x0f\x1d 0k)o\x04(/)j5<(\x04#k)\x04k5h\x049"/h\x040j77&'
```

Les données ne sont pas lisibles directement — il faut les déchiffrer.

---

## 5. Le déchiffrement XOR

Le commentaire nous dit : `the string is tuned to 0x5B`. La clé de chiffrement est `0x5B`.

### Déchiffrement

```python
key = 0x5B  # la "note" = 91 = '['

# XOR chaque octet avec la clé
decrypted = bytes(b ^ key for b in flag_data)
print(decrypted.decode('utf-8'))
```

**Résultat** :

```
EcowasCTF{mdr}
```

---

## 6. Analyse de l'audio (approches échouées d'abord)

Pour être complet, voici les pistes qu'on pourrait explorer — et pourquoi elles ne fonctionnent pas ici.

### Steganographie LSB audio

```python
import wave, numpy as np

with wave.open("kora.wav", 'r') as w:
    frames = w.readframes(w.getnframes())
    sr = w.getframerate()

samples = np.frombuffer(frames, dtype=np.int16)
print(f"Samples: {len(samples)}, SR: {sr}Hz")
# → Samples: 8000, SR: 8000Hz (1 seconde de son)

# Extraire le LSB de chaque sample
lsb = samples & 1
byte_data = bytearray()
for i in range(0, len(lsb) - 7, 8):
    byte = sum(int(lsb[i+j]) << (7-j) for j in range(8))
    byte_data.append(byte)

print(byte_data.decode('utf-8', errors='replace')[:50])
# → Données répétitives illisibles ❌
```

→ Rien d'utile dans le LSB des samples.

### Spectre de fréquences (FFT)

```python
# FFT par tranche pour chercher un changement de fréquence
for i in range(0, 8000, 400):
    chunk = samples[i:i+400]
    fft = np.abs(np.fft.rfft(chunk))
    freq = np.fft.rfftfreq(len(chunk), 1/sr)
    dominant = freq[np.argmax(fft)]
    print(f"Chunk {i}-{i+400}: {dominant:.0f} Hz")
```

→ Le son est une simple sinusoïde à 220 Hz (note La, octave 3). Pas de modulation cachée.

**Morale** : En CTF, avant de chercher des techniques stéganographiques complexes, toujours utiliser `strings` et examiner la structure du fichier !

---

## 7. Script complet de résolution

```python
#!/usr/bin/env python3
"""Solution complète : Kora Strings"""
import re

with open("kora.wav", "rb") as f:
    raw = f.read()

# --- Étape 1 : Chercher le commentaire (hint) ---
comment_pos = raw.find(b'ICMT')
if comment_pos >= 0:
    icmt_len = int.from_bytes(raw[comment_pos+4:comment_pos+8], 'little')
    icmt_data = raw[comment_pos+8:comment_pos+8+icmt_len]
    print(f"Commentaire WAV : {icmt_data.decode('ascii', errors='replace')}")
    # → the string is tuned to 0x5B

# --- Étape 2 : Extraire le chunk 'flag' ---
flag_pos = raw.find(b'flag')
flag_data_start = flag_pos + 4
flag_len = int.from_bytes(raw[flag_data_start:flag_data_start+4], 'little')
flag_data = raw[flag_data_start+4:flag_data_start+4+flag_len]
print(f"Données chiffrées ({flag_len} octets): {flag_data.hex()}")

# --- Étape 3 : Déchiffrer avec XOR 0x5B ---
key = 0x5B  # depuis le commentaire
flag = bytes(b ^ key for b in flag_data).decode('utf-8')
print(f"Flag : {flag}")
```

---

## 8. La structure complète du WAV

```
Offset 0:     RIFF [4] + size [4]
Offset 8:     'WAVE'
Offset 12:    'fmt ' [4] + 16 [4] + format PCM [2] + channels=1 [2] + rate=8000 [4]...
Offset 44:    'data' [4] + 16000 [4] + [16000 octets de samples audio 220Hz]
Offset 16060: 'LIST' [4] + 74 [4] + 'INFO' [4]
Offset 16072:   'ICMT' [4] + 28 [4] + "the string is tuned to 0x5B" [28 octets]
Offset 16092:   'flag' [4] + 41 [4] + [41 octets chiffrés XOR 0x5B]
```

---

## 9. Résumé des approches

| Approche                             | Résultat                             |
| ------------------------------------ | ------------------------------------- |
| `strings kora.wav`                 | Révèle commentaire + chunk `flag` |
| `exiftool kora.wav`                | Révèle commentaire "tuned to 0x5B"  |
| Steganographie LSB des samples audio | Données répétitives sans sens      |
| Analyse FFT (Morse/DTMF)             | Son pur à 220 Hz, pas de modulation  |
| Extraction chunk `flag` + XOR 0x5B | **Flag !**                      |

---

## 10. Glossaire débutant

| Terme               | Explication                                                            |
| ------------------- | ---------------------------------------------------------------------- |
| **WAV**       | Format audio non compressé basé sur RIFF                             |
| **RIFF**      | Resource Interchange File Format — structure de chunks                |
| **Chunk**     | Bloc de données dans un RIFF, identifié par 4 lettres                |
| **LIST/INFO** | Chunk standard pour les métadonnées dans un WAV                      |
| **ICMT**      | "Info Comment" — sous-chunk de métadonnée commentaire               |
| **XOR**       | Opération binaire réversible souvent utilisée en chiffrement simple |
| **0x5B**      | Valeur hexadécimale = 91 décimal = ASCII `[`                       |
| **LSB**       | Least Significant Bit = bit de poids faible                            |

---

## 11. Ressources

- [Format RIFF/WAV — spécification complète](https://www.mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html)
- [Audacity — visualiser l&#39;audio](https://www.audacityteam.org/)
- [CyberChef — XOR en ligne](https://gchq.github.io/CyberChef/#recipe=XOR(%7B'option':'Hex','string':'5B'%7D,'Standard',false))
- [Steganographie audio — techniques](https://ctf101.org/forensics/what-is-audio-steganography/)
- [XOR chiffrement — cryptopals.com](https://cryptopals.com/sets/1/challenges/2)
- [PicoCTF — challenges audio/forensics](https://picoctf.org/)
- [010 Editor / hexedit — éditeur hexadécimal](https://www.sweetscape.com/010editor/)

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
