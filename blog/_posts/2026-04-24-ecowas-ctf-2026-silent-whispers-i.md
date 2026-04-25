---
layout: post
title: "ECOWAS CTF 2026 — Silent Whispers I [Steganography/100pts]"
date: 2026-04-24 10:11:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [steganography, stegsnow, whitespace, tabs-spaces, huffman]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Steganography · **Difficulté :** ⭐ (Easy) · **Points :** 100  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Description du challenge

> *"We intercepted what looks like a normal message, but something feels.....off.
The content seems harmless, yet there may be more than meets the eye. Not all secrets are visible — some hide in plain sight.
Can you uncover what's hidden?"*

**Fichier fourni :** `information.txt`

---

La **[stéganographie](https://fr.wikipedia.org/wiki/St%C3%A9ganographie)** dissimule des données dans un fichier anodin (image, audio, texte) sans altération visible.

[**stegsnow**](http://www.darkside.com.au/snow/) encode des données dans les espaces/tabulations de fin de ligne — invisibles à l'œil nu.

---

## Étape 1 — Analyser le fichier

La première chose à faire avec tout fichier texte suspect dans un CTF : **vérifier l'hexdump** (représentation hexadécimale du contenu brut du fichier).

```bash
# Sur Linux / Kali
hexdump -C information.txt | head -20

# Ou avec Python sur n'importe quel OS
python3 -c "
f = open('information.txt', 'rb').read()
for i in range(0, min(160, len(f)), 16):
    hex_part = ' '.join(f'{b:02x}' for b in f[i:i+16])
    asc_part = ''.join(chr(b) if 32<=b<127 else '.' for b in f[i:i+16])
    print(f'{i:04x}: {hex_part:<48}  {asc_part}')
"
```

> **Résultat attendu :** On voit des octets `09` (tabulation) et `20` (espace) éparpillés en dehors des zones de texte normal — notamment en **fin de lignes**. C'est la signature caractéristique de stegsnow.

### Comment reconnaître stegsnow dans l'hexdump ?

```
Lignes normales : ...74 65 78 74 0a       → "text\n"
Lignes stego   : ...74 65 78 74 20 09 20 0a → "text \t \n"
                                 ^^  ^^
                         espaces/tabulations ajoutés AVANT le saut de ligne
```

---

## Étape 2 — Extraction avec stegsnow

**Outil requis :** `stegsnow` (disponible sur Linux/Kali)

```bash
# Installation sur Kali/Debian
sudo apt-get install stegsnow

# Extraction sans mot de passe
stegsnow -C information.txt
```

L'option `-C` active la **décompression** (compression Huffman intégrée à stegsnow).

> **Résultat :**
> ```
> EcowasCTF{wh1t3sp4c3_s3cr3ts_h1dd3n}
> ```

---

## Étape 3 — Comprendre ce qui vient de se passer

Voici ce que stegsnow a fait en coulisses :

```
[Information.txt]
│
│  Ligne 1: "Hey,\t     \t       \t  \t   \t  ..."  ← bits: 1,0,0,0,1...
│  Ligne 2: "Traffic...\t\t \t  \t   ..."            ← bits: 1,1,0,1,0...
│  ...
│
▼
[Extraction des bits à partir des espaces/tabulations]
  tab = 1, espace = 0
  Séquence de bits: 01000101 01100011 ...
│
▼
[Conversion bits → ASCII]
  01000101 = 0x45 = 'E'
  01100011 = 0x63 = 'c'
  ...
│
▼
[Flag]
  "EcowasCTF{wh1t3sp4c3_s3cr3ts_h1dd3n}"
```

---

## Script Python alternatif (sans stegsnow)

Si tu n'as pas `stegsnow` installé, tu peux le recréer en Python :

```python
def stegsnow_decode(filename):
    bits = []
    with open(filename, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            # On enlève le saut de ligne final
            line = line.rstrip('\n')
            # On lit les caractères whitespace à la FIN de la ligne
            trailing = line[len(line.rstrip(' \t')):]
            for char in trailing:
                if char == '\t':
                    bits.append(1)
                elif char == ' ':
                    bits.append(0)
    
    # Convertir les bits en bytes (groupes de 8)
    result = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte |= (bits[i + j] << (7 - j))
        result.append(byte)
    
    # Décoder le résultat
    try:
        return bytes(result).decode('utf-8', errors='replace')
    except:
        return bytes(result)

flag = stegsnow_decode('information.txt')
print(flag)
```

---

## Flag

```
EcowasCTF{wh1t3sp4c3_s3cr3ts_h1dd3n}
```

---

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
