---
layout: post
title: "ECOWAS CTF 2026 — Yoruba VM [Reverse/500pts]"
date: 2026-04-24 11:16:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [reverse, elf, custom-vm, aes-sbox, xor, static-analysis, ghidra, inversion, yoruba]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Reverse Engineering · **Difficulté :** ⭐⭐⭐ (Hard) · **Points :** 500  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `yoruba_vm.zip` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/76_yoruba_vm.zip) |

---

**CTF :** ECOWAS CTF 2026  
**Date :** Avril 2026  
**Catégorie :** Reverse Engineering  
**Difficulté :** Hard  
**Points :** 500  
**Solves :** 106  
**Format du flag :** `EcowasCTF{...}`  
**Flag :** `EcowasCTF{y0rub4_vm_r3v_master!}`  
**Auteur :** ITACHI  

---

## Description du challenge

> Une machine virtuelle personnalisée nommée d'après le peuple Yoruba d'Afrique de l'Ouest.  
> Rétro-ingénierie pour trouver le flag.

**Fichier fourni :** `yoruba_vm` (binaire Linux ELF 64-bit)

---

## Vue d'ensemble

Le binaire implémente une **machine virtuelle (VM) personnalisée** qui lit votre entrée et la valide caractère par caractère via une **table de substitution AES (S-Box) combinée à un XOR**. Pour résoudre le challenge, on reverse la logique de vérification, on extrait les constantes (clés et cibles), puis on calcule mathématiquement l'entrée qui satisfait toutes les contraintes — sans jamais exécuter le programme.

**Technique principale :** Analyse statique + inversion de S-Box.

---

## Contexte : C'est quoi une « VM » dans un CTF ?

Dans les challenges de reverse, une « VM » ne désigne pas VirtualBox ou VMware. Cela signifie que le binaire **interprète ses propres opcodes personnalisés** — comme un mini-langage de programmation qui tourne à l'intérieur du vrai CPU.

Au lieu de reverser directement de l'assembleur complexe, on commence par reverser la **boucle de dispatch de la VM** (le `switch`/`if` qui gère chaque opcode), on comprend ce que fait chaque instruction, puis on trace le **programme VM** (le bytecode embarqué) pour reconstruire la logique globale.

> **Analogie :** Le binaire est un interpréteur Python, et à l'intérieur il y a un script `.py` que tu dois comprendre. Tu reverses d'abord l'interpréteur, puis tu lis le script.

---

## Étape 1 : Reconnaissance — Identifier le binaire

```bash
file yoruba_vm
# yoruba_vm: ELF 64-bit LSB executable, x86-64, dynamically linked

strings yoruba_vm | head -30
# Enter flag:
# Correct!
# Wrong!
```

**Observations clés :**
- C'est un ELF Linux standard x86-64
- Il demande un flag et affiche « Correct! » ou « Wrong! »
- Aucun flag en clair → la vérification se fait caractère par caractère

---

## Étape 2 : Désassemblage — Trouver la logique de validation

On ouvre le binaire dans Ghidra (ou tout désassembleur). On cherche les références croisées vers la chaîne `"Correct!"` pour localiser la fonction de validation.

Le pseudo-code pertinent :

```c
for (int i = 0; i < 32; i++) {
    byte result = sbox[ input[i] ^ keys[i] ];
    if (result != targets[i]) {
        puts("Wrong!");
        return;
    }
}
puts("Correct!");
```

Chaque caractère de l'entrée subit deux opérations :
1. **XOR** avec un octet de clé
2. **Substitution** dans une table S-Box de 256 octets

Le résultat doit correspondre à une valeur cible codée en dur.

---

## Contexte : C'est quoi une S-Box ?

Une **S-Box (Boîte de Substitution)** est une table de correspondance utilisée en cryptographie. Pour un index donné, elle retourne une valeur fixe. C'est exactement la même table que celle utilisée dans le chiffrement AES.

```python
sbox[0]   = 99   # 0x00 → 0x63
sbox[1]   = 124  # 0x01 → 0x7c
# ... 256 entrées au total
```

C'est une **bijection** : chaque entrée correspond exactement à une sortie, et vice-versa. C'est cette propriété qui rend le challenge soluble : on peut **l'inverser**.

---

## Étape 3 : Extraire les constantes

Depuis le binaire désassemblé, on extrait :

**S-Box AES standard (256 octets) :**
```python
sbox = [
    99, 124, 119, 123, 242, 107, 111, 197, 48,  1,  103, 43,  254, 215, 171, 118,
    202, 130, 201, 125, 250, 89,  71,  240, 173, 212, 162, 175, 156, 164, 114, 192,
    # ... (table complète dans le script ci-dessous)
]
```

**Clés (32 octets, masque XOR par caractère) :**
```python
keys = [
    0x5A, 0x5B, 0x58, 0x59, 0x5E, 0x5F, 0x5C, 0x5D,
    0x52, 0x53, 0x50, 0x51, 0x56, 0x57, 0x54, 0x55,
    0x4A, 0x4B, 0x48, 0x49, 0x4E, 0x4F, 0x4C, 0x4D,
    0x42, 0x43, 0x40, 0x41, 0x46, 0x47, 0x44, 0x45,
]
```

**Cibles (32 octets, sortie S-Box attendue) :**
```python
targets = [
    0xa0, 0x59, 0x41, 0x2a, 0x6f, 0x98, 0x15, 0x08,
    0x2b, 0x17, 0x8e, 0x84, 0x3a, 0xcc, 0x44, 0x13,
    0x98, 0xd4, 0x11, 0x84, 0x09, 0xf8, 0x71, 0x1b,
    0xbe, 0x8a, 0x9b, 0x69, 0x84, 0x84, 0x5a, 0x75,
]
```

---

## Étape 4 : Résoudre — Inverser les maths

La contrainte de vérification est :

$$\text{sbox}[\text{input}[i] \oplus \text{keys}[i]] = \text{targets}[i]$$

Pour retrouver `input[i]`, on inverse les deux opérations :

1. **Inverser la S-Box :** construire `inv_sbox` tel que `inv_sbox[sbox[x]] = x` pour tout x
2. **Annuler le XOR :** `input[i] = inv_sbox[targets[i]] XOR keys[i]`

Le XOR est sa propre inverse : si `a XOR k = b`, alors `b XOR k = a`.

```python
# Construire la S-Box inverse
inv_sbox = [0] * 256
for i, v in enumerate(sbox):
    inv_sbox[v] = i

# Récupérer chaque caractère du flag
flag = bytes([inv_sbox[t] ^ k for t, k in zip(targets, keys)])
print(flag.decode())
# EcowasCTF{y0rub4_vm_r3v_master!}
```

C'est toute la solution — pas de brute-force, pas de fuzzing, uniquement des maths.

---

## Script de résolution complet

```python
#!/usr/bin/env python3
"""
ECOWAS CTF 2026 — Yoruba VM (Rev 500pts)
Solution : inverser la S-Box + XOR pour retrouver le flag depuis les contraintes codées en dur.
"""

sbox = [
    99, 124, 119, 123, 242, 107, 111, 197, 48,  1,  103, 43,  254, 215, 171, 118,
    202, 130, 201, 125, 250, 89,  71,  240, 173, 212, 162, 175, 156, 164, 114, 192,
    183, 253, 147, 38,  54,  63,  247, 204, 52,  165, 229, 241, 113, 216, 49,  21,
    4,   199, 35,  195, 24,  150, 5,   154, 7,   18,  128, 226, 235, 39,  178, 117,
    9,   131, 44,  26,  27,  110, 90,  160, 82,  59,  214, 179, 41,  227, 47,  132,
    83,  209, 0,   237, 32,  252, 177, 91,  106, 203, 190, 57,  74,  76,  88,  207,
    208, 239, 170, 251, 67,  77,  51,  133, 69,  249, 2,   127, 80,  60,  159, 168,
    81,  163, 64,  143, 146, 157, 56,  245, 188, 182, 218, 33,  16,  255, 243, 210,
    205, 12,  19,  236, 95,  151, 68,  23,  196, 167, 126, 61,  100, 93,  25,  115,
    96,  129, 79,  220, 34,  42,  144, 136, 70,  238, 184, 20,  222, 94,  11,  219,
    224, 50,  58,  10,  73,  6,   36,  92,  194, 211, 172, 98,  145, 149, 228, 121,
    231, 200, 55,  109, 141, 213, 78,  169, 108, 86,  244, 234, 101, 122, 174, 8,
    186, 120, 37,  46,  28,  166, 180, 198, 232, 221, 116, 31,  75,  189, 139, 138,
    112, 62,  181, 102, 72,  3,   246, 14,  97,  53,  87,  185, 134, 193, 29,  158,
    225, 248, 152, 17,  105, 217, 142, 148, 155, 30,  135, 233, 206, 85,  40,  223,
    140, 161, 137, 13,  191, 230, 66,  104, 65,  153, 45,  15,  176, 84,  187, 22,
]

keys = [
    0x5A, 0x5B, 0x58, 0x59, 0x5E, 0x5F, 0x5C, 0x5D,
    0x52, 0x53, 0x50, 0x51, 0x56, 0x57, 0x54, 0x55,
    0x4A, 0x4B, 0x48, 0x49, 0x4E, 0x4F, 0x4C, 0x4D,
    0x42, 0x43, 0x40, 0x41, 0x46, 0x47, 0x44, 0x45,
]

targets = [
    0xa0, 0x59, 0x41, 0x2a, 0x6f, 0x98, 0x15, 0x08,
    0x2b, 0x17, 0x8e, 0x84, 0x3a, 0xcc, 0x44, 0x13,
    0x98, 0xd4, 0x11, 0x84, 0x09, 0xf8, 0x71, 0x1b,
    0xbe, 0x8a, 0x9b, 0x69, 0x84, 0x84, 0x5a, 0x75,
]

# Construire la S-Box inverse
inv_sbox = [0] * 256
for i, v in enumerate(sbox):
    inv_sbox[v] = i

# Retrouver le flag
flag = bytes([inv_sbox[t] ^ k for t, k in zip(targets, keys)])

# Vérification
for i, (inp, k, t) in enumerate(zip(flag, keys, targets)):
    assert sbox[inp ^ k] == t, f"Erreur à la position {i}"

print(f"Flag : {flag.decode()}")
```

**Sortie :**
```
Flag : EcowasCTF{y0rub4_vm_r3v_master!}
```

---

## Flag

```
EcowasCTF{y0rub4_vm_r3v_master!}
```

---

## Points clés à retenir

- **Reverse de VM personnalisée :** toujours trouver la boucle de dispatch en premier, puis tracer chaque opcode. Ici la VM se réduisait à une boucle de validation une fois la structure comprise.
- **S-Box + XOR est trivialement inversible :** les deux opérations sont réversibles en O(1) — ne jamais brute-forcer ce qui peut être résolu mathématiquement.
- **L'analyse statique est plus rapide que le dynamique :** on n'a jamais exécuté le binaire. Extraire les constantes et inverser les maths est plus sûr, plus rapide, et fonctionne même sans machine Linux.

---

## Ressources pour débutants

| Sujet | Ressource |
|---|---|
| Introduction au reverse engineering | [LiveOverflow RE playlist (YouTube)](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN) |
| Ghidra (décompilateur gratuit) | [ghidra-sre.org](https://ghidra-sre.org) |
| S-Box AES expliquée | [Wikipedia : Rijndael S-box](https://en.wikipedia.org/wiki/Rijndael_S-box) |
| XOR en CTF | [CryptoHack intro XOR](https://cryptohack.org/courses/intro/xorbasics/) |
| Techniques de reverse VM | [checkpoint.com blog VM obfuscation](https://research.checkpoint.com/2009/adventure-in-vm-obfuscation/) |
| Pratique reverse | [crackmes.one](https://crackmes.one) · [picoCTF RE](https://picoctf.org) |

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
