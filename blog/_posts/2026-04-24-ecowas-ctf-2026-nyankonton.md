---
layout: post
title: "ECOWAS CTF 2026 — Nyankonton [Reverse/200pts]"
date: 2026-04-24 10:33:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [reverse, mach-o, arm64, xor, keystream, static-analysis, ghidra]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Reverse Engineering · **Difficulté :** ⭐⭐ (Medium) · **Points :** 200  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `nyancat.zip` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/33_nyankonton.zip) |

---

## Description du challenge

> *"The portal closes in 24 moves, you need to put your skills to work and get into the portal before it closes!"*

Un seul fichier à télécharger : `nyancat.zip` → contient le binaire `nyancat`.

---

## Étape 1 — Identification du binaire

La première chose à faire quand on reçoit un binaire inconnu : **identifier ce qu'il est**.

```bash
file nyancat
```

Résultat :
```
nyancat: Mach-O 64-bit ARM64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
```

Deux informations importantes :
- **Mach-O** : format des exécutables macOS (pas ELF comme sur Linux)
- **ARM64** : architecture 64 bits ARM (comme les Mac Apple Silicon M1/M2/M3)

On ne peut pas l'exécuter directement sur Linux ou Windows, mais on peut quand même l'**analyser statiquement**.

---

## Étape 2 — Tour d'horizon rapide : strings et symboles

Avant de plonger dans le désassemblage, on regarde les **chaînes lisibles** et les **symboles** exportés.

```bash
strings nyancat | head -50
```

On voit des choses comme des directions (`↑`, `↓`), des messages de jeu. Le binaire semble implémenter un jeu où l'on doit entrer 24 mouvements.

Les **symboles** sont encore plus révélateurs :

```bash
nm nyancat | grep -i flag
```

ou avec `objdump` / `Ghidra` → on trouve :

```
_NK_FLAG_CT    0x100003F68
```

`CT` ici signifie probablement **CipherText** — texte chiffré. C'est notre cible.

---

## Étape 3 — Analyser la logique du jeu (Ghidra / IDA)

On ouvre le binaire dans **Ghidra** (décompilateur gratuit de la NSA).

La fonction `main` implémente un jeu : l'utilisateur entre 24 mouvements, chacun est haché/traité, et le résultat final détermine si le flag est déchiffré correctement.

En pseudocode :

```c
uint64_t hash = 0;   // état initial
for (int i = 0; i < 24; i++) {
    char move = get_input();  // un des 4 mouvements
    hash = update_hash(hash, move);
}
// Si hash == 0x0C5B0BB2A46A6CFC → on peut déchiffrer le flag
decrypt_flag(hash);
```

La fonction de déchiffrement :

```c
void decrypt_flag(uint64_t v19) {
    uint8_t keystream[8];
    for (int k = 0; k < 48; k++) {
        if ((k & 7) == 0) {
            // tous les 8 bytes : on génère le prochain bloc de keystream
            store_le64(keystream, v19);
            v19 = 0x9E3779B97F4A7C15ULL * ror64(v19, 57);
        }
        flag[k] = keystream[k & 7] ^ NK_FLAG_CT[k];
    }
}
```

---

## Étape 4 — L'insight clé : on n'a pas besoin de jouer !

Une observation **critique** : la fonction de déchiffrement prend `v19` en paramètre, et commence **immédiatement** à générer le keystream à partir de cette valeur.

La valeur magique est `v19 = 0x0C5B0BB2A46A6CFC` — c'est la valeur du hash si les 24 mouvements sont corrects.

**Mais on n'a pas besoin de trouver les 24 mouvements.** La constante est codée en dur dans le binaire. Il suffit de :
1. Extraire les 48 bytes de `NK_FLAG_CT` depuis le fichier binaire
2. Simuler le keystream en partant de `0x0C5B0BB2A46A6CFC`
3. XOR les deux → flag

---

## Étape 5 — Extraction de NK_FLAG_CT

`NK_FLAG_CT` est dans la section `__const` à l'adresse virtuelle `0x100003F68`.

Dans le fichier, l'offset est : `0x100003F68 - 0x100000000 = 0x3F68`.

```python
with open('nyancat', 'rb') as f:
    data = f.read()

NK_FLAG_CT = data[0x3F68:0x3F68+48]
print(NK_FLAG_CT.hex())
```

---

## Étape 6 — Script de déchiffrement

```python
import struct

def ror64(val, shift):
    """Rotation droite 64 bits"""
    return ((val >> shift) | (val << (64 - shift))) & 0xFFFFFFFFFFFFFFFF

# La constante "gagnante" lue dans le binaire
v19 = 0x0C5B0BB2A46A6CFC

# Le flag chiffré (lu depuis l'offset 0x3F68 du binaire)
NK_FLAG_CT = bytes.fromhex("...")  # 48 bytes extraits du binaire

flag = bytearray(48)
for k in range(48):
    if (k & 7) == 0:
        # Générer le prochain bloc de 8 bytes de keystream
        keystream_block = struct.pack('<Q', v19)  # little-endian uint64
        # Avancer le générateur
        v19 = (0x9E3779B97F4A7C15 * ror64(v19, 57)) & 0xFFFFFFFFFFFFFFFF
    flag[k] = keystream_block[k & 7] ^ NK_FLAG_CT[k]

print(bytes(flag).decode())
```

---

## Résultat

```
EcowasCTF{ny4n_ny4n_w4rp_p0rt4l_f0und_@t_last!!}
```

---

## Résumé de la technique

| Étape | Action |
|-------|--------|
| 1 | Identifier le format (Mach-O ARM64) |
| 2 | Trouver le symbole `_NK_FLAG_CT` |
| 3 | Comprendre la logique de déchiffrement dans Ghidra |
| 4 | Réaliser que la constante est codée en dur |
| 5 | Extraire le ciphertext + simuler le keystream |
| 6 | XOR → flag |

**Concepts clés** : Analyse statique, lecture de symboles, keystream XOR, rotation de bits (ROR64).

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
