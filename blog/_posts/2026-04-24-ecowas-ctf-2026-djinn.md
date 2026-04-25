---
layout: post
title: "ECOWAS CTF 2026 — Djinn [Reverse/500pts]"
date: 2026-04-24 10:49:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [reverse, elf, lfsr, state-machine, ghidra, static-analysis, deterministic]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Reverse Engineering · **Difficulté :** ⭐⭐⭐ (Hard) · **Points :** 500  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `djinn.zip` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/49_djinn.zip) |

---

## Description du challenge

> *"A djinn lives inside the machine. It knows the secret, but does not want to share! MAKE IT SHARE!!"*

On reçoit un fichier : `djinn` (binaire ELF 64-bit Linux, ~18 Ko).

Le djinn — une entité magique de la mythologie arabe/islamique — garde un secret. Notre mission : forcer le programme à nous révéler le flag sans jamais l'exécuter "normalement".

---

## Concepts préalables (pour les débutants)

Avant de plonger dans la solution, voici les concepts clés à comprendre :

### Qu'est-ce que le Reverse Engineering (RE) ?

Le Reverse Engineering (ingénierie inverse) consiste à analyser un programme **compilé** (binaire) pour comprendre ce qu'il fait, sans avoir accès au code source. On "remonte" depuis la machine vers l'humain.

### Outils utilisés
- **`file`** : identifie le type d'un fichier
- **`strings`** : extrait les chaînes de caractères lisibles d'un binaire
- **`ltrace`** / **`strace`** : trace les appels aux fonctions (ltrace) ou système (strace)
- **Ghidra** : outil de décompilation gratuit de la NSA — transforme l'assembleur en pseudo-code C
- **IDA Pro** : décompilateur professionnel (version gratuite limitée)
- **Python** : pour reproduire l'algorithme et calculer le flag

### Qu'est-ce qu'un LFSR ?

Un **LFSR** (Linear Feedback Shift Register — Registre à décalage à rétroaction linéaire) est un mécanisme de génération pseudo-aléatoire. Il part d'un état initial (la "graine") et produit une séquence de valeurs déterministes. Si on connaît la graine et la fonction de transition, on peut prédire toute la séquence.

---

## Étape 1 — Reconnaissance du binaire

### Identification du fichier

```bash
$ file djinn
djinn: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

**Points importants :**
- `ELF 64-bit` : format binaire Linux (comme `.exe` sous Windows)
- `not stripped` : les noms de fonctions sont CONSERVÉS dans le binaire (chance !)
- `dynamically linked` : utilise des bibliothèques système externes

### Extraction des chaînes

```bash
$ strings djinn | head -50
```

On cherche des indices : noms de fonctions, messages d'erreur, références au flag...

Un `strings` rapide peut révéler des indices sur la structure : noms de fonctions comme `step`, `emit`, `main`, références à `TABLE`, etc.

### Vérification des protections

```bash
$ checksec djinn
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
```

Pas de PIE (pas d'ASLR sur les adresses du binaire) — les adresses sont fixes, ce qui facilite l'analyse.

---

## Étape 2 — Ouverture dans Ghidra

### Importer le binaire

1. Lancer Ghidra → New Project → Import File → `djinn`
2. Double-cliquer → Auto-analyze (cocher toutes les options par défaut)
3. Aller dans la fenêtre "Symbol Tree" → chercher `main`

### Analyse de `main`

En décompilant `main`, on voit un pattern répétitif :
- Initialisation d'un **état** à `0xDEADBEEF`
- Une boucle de 37 itérations
- À chaque itération : comparaison de l'état courant avec une **valeur attendue**
- Si l'état ne correspond pas → le programme prend un mauvais chemin (ou sort)
- Sinon → génération d'un byte de flag via une fonction (qu'on appellera `emit`)
- Avancement de l'état via une autre fonction (`step`)

> **Insight clé** : le programme ne "vérifie" pas un input utilisateur. Il **génère** le flag lui-même, selon un algorithme déterministe. Notre travail est de reproduire cet algorithme.

---

## Étape 3 — Identification des composants

### La TABLE (table de substitution)

Dans la section `.rodata` ou `.data`, on trouve un tableau de 256 entrées de type `int8_t` (entiers signés sur 8 bits, de -128 à +127).

Extrait :
```
[-1, -52, 56, -78, -67, 12, -76, -26, ...]
```

C'est une **S-Box** (Substitution Box) — un tableau de substitution utilisé en cryptographie. L'index d'entrée est transformé en une valeur de sortie selon ce tableau.

> **Important** : les valeurs sont des `int8_t` (signed), mais on travaille avec des bytes (0-255). On convertit avec `value & 0xFF` : par exemple, `-1 & 0xFF = 255`, `-52 & 0xFF = 204`.

### La fonction `step` (transition d'état)

```c
// Pseudo-code C (reconstitué depuis Ghidra)
uint32_t step(uint32_t value) {
    uint8_t bit = (value ^ (value >> 21) ^ (value >> 1)) & 0xFF;
    uint64_t doubled = (2ULL * value) & 0x1FFFFFFFF;
    return (uint32_t)((doubled & 0xFFFFFFFF) + (((doubled >> 32) ^ bit) & 1));
}
```

En Python :
```python
def step(value: int) -> int:
    bit = (value ^ (value >> 21) ^ (value >> 1)) & 0xFF
    doubled = (2 * value) & 0x1FFFFFFFF
    return ((doubled & 0xFFFFFFFF) + (((doubled >> 32) ^ bit) & 1)) & 0xFFFFFFFF
```

**Décomposé pour les débutants :**

1. `value >> 21` : décalage bit de 21 positions vers la droite
2. `value >> 1` : décalage bit de 1 position vers la droite
3. `bit = (value ^ (value>>21) ^ (value>>1)) & 0xFF` : XOR de plusieurs décalages → calcul d'un bit de feedback (comme dans un LFSR)
4. `doubled = (2 * value) & 0x1FFFFFFFF` : multiplie par 2 (= décalage gauche de 1 bit), masqué sur 33 bits
5. Le résultat final utilise le **bit de carry** (retenue du 33ème bit) et le bit de feedback pour former le nouvel état 32 bits

C'est un **LFSR modifié** : à chaque appel, l'état avance de manière pseudo-aléatoire mais totalement déterministe.

### La fonction `emit` (génération d'un byte de flag)

```c
// Pseudo-code C
uint8_t emit(uint32_t state, uint8_t key_xor, uint8_t out_xor, bool invert) {
    uint8_t byte = TABLE[(state & 0xFF) ^ key_xor];
    if (invert) return (~byte) & 0xFF;
    return byte ^ out_xor;
}
```

En Python :
```python
def emit(value: int, key_xor: int, out_xor: int, invert: bool = False) -> int:
    byte = TABLE[(value & 0xFF) ^ key_xor]
    if invert:
        return (~byte) & 0xFF
    return byte ^ out_xor
```

**Décomposé :**

1. `(value & 0xFF)` : on prend les 8 bits bas de l'état courant (l'octet de poids faible)
2. `^ key_xor` : XOR avec une clé spécifique à cette étape → donne l'index dans la TABLE
3. `TABLE[index]` : substitution selon la S-Box → un byte
4. Si `invert = True` → on inverse tous les bits (`~byte`)
5. Sinon → XOR final avec `out_xor`

Résultat : **un byte du flag**.

---

## Étape 4 — La séquence hardcodée

Dans le binaire, on trouve un tableau de 37 tuples, chacun contenant 4 valeurs :

| Champ | Type | Rôle |
|-------|------|------|
| `expected_state` | uint32 | Valeur d'état attendue à cette étape (vérification) |
| `key_xor` | uint8 | Clé XOR pour l'index dans la TABLE |
| `out_xor` | uint8 | XOR appliqué au résultat final |
| `invert` | bool | Si True : inverser les bits du résultat |

Exemple des 5 premiers tuples (extraits du binaire) :
```
(0x68, 0x5A, 0x34, False)   → byte 0 → 'E'
(0xBE, 0xB2, 0xD5, False)   → byte 1 → 'c'
(0xB3, 0xAE, 0xBE, False)   → byte 2 → 'o'
(0xD3, 0xDF, 0xE6, False)   → byte 3 → 'w'
(0xB6, 0x7D, 0x4C, False)   → byte 4 → 'a'
```

> **Note** : `expected_state` est en fait la valeur de `state & 0xFF` (l'octet bas) *avant* l'appel à `emit`. Pendant l'exécution normale du programme, si cet octet ne correspond pas, le binaire détecte une manipulation et refuse de continuer. Puisqu'on REPRODUIT l'algorithme en dehors du binaire, cette vérification n'a pas d'importance pour nous — mais elle nous permet de valider que notre extraction était correcte.

---

## Étape 5 — Le script de résolution complet

Voici le script Python complet avec commentaires :

```python
# solve_djinn.py
# ============================================================
# Résolution du challenge Djinn (ECOWAS CTF 2026 - RE Hard)
# Principe : reproduire la machine à états du binaire en Python
# ============================================================

# ---- TABLE DE SUBSTITUTION (S-Box) ----
# 256 entrées, valeurs int8_t converties en uint8 avec & 0xFF
TABLE = [
    -1, -52, 56, -78, -67, 12, -76, -26, -92, 94, -8, 95, -99, 15, -84, 1,
    -102, 110, -47, 70, -109, -125, 10, 100, 20, 88, 14, -39, -18, 76, -54, 19,
    -33, 72, 125, 16, 8, -59, -36, 3, -71, 105, 102, 54, -89, -87, -7, 127,
    22, 71, 68, 86, 13, 91, -43, 93, 47, -40, -35, 53, -46, -82, 115, -106,
    -38, -119, -57, -66, -83, 114, -5, 79, 121, 66, 55, 11, -3, 116, 89, -42,
    -4, 82, -63, 69, 126, 87, -81, -94, -10, -85, 23, 50, 108, -118, -86, -55,
    63, -21, -121, 44, -44, 6, -11, 18, 111, 25, 58, -27, -74, 117, -49, -100,
    17, -112, -23, -70, 32, 92, 119, -101, -75, 37, 26, -122, -14, 77, 35, -123,
    84, 7, 90, -72, 128, 48, -126, -127, -13, -124, 38, -31, 81, 80, 45, 51,
    -2, -15, 4, -104, -37, 103, 85, 29, 24, -68, -79, -93, 2, 65, -113, 74,
    -69, -117, -115, 28, -24, 43, -111, -65, -56, 123, 67, 122, 120, -110, -25, 57,
    -51, -16, 33, 52, -88, 113, 97, 61, -77, 9, -20, -97, 36, 96, -107, 30,
    106, 124, -61, -116, -29, 101, -80, -12, 78, -98, 107, 104, -105, 5, 75, -90,
    73, -48, 21, -19, 41, 62, -60, -17, 83, -41, 40, -6, -28, -9, 27, 46,
    118, -91, 109, -120, 34, -34, 31, 60, -96, 0, -62, -30, 49, -22, -103, 59,
    42, -73, 112, -50, 98, 64, 99, -114, -32, -53, -58, 39, -108, -64, -45, -95,
]
# Conversion int8_t → uint8 : -1 → 255, -52 → 204, etc.
TABLE = [value & 0xFF for value in TABLE]


def step(value: int) -> int:
    """
    Fonction de transition d'état (LFSR modifié).
    
    Prend l'état courant (32 bits) et retourne le prochain état.
    
    Mécanisme :
    - Calcul d'un bit de feedback via XOR de décalages (structure LFSR)
    - Décalage gauche de 1 bit (multiplication par 2) sur 33 bits
    - Le bit de carry (33ème bit) est XORé avec le bit de feedback
    - Retour sur 32 bits
    """
    # Bit de feedback : XOR de l'état, de son décalage de 21 bits, et de 1 bit
    bit = (value ^ (value >> 21) ^ (value >> 1)) & 0xFF
    # Décalage gauche sur 33 bits (pour capturer le carry)
    doubled = (2 * value) & 0x1FFFFFFFF
    # Nouvel état : partie 32 bits basse + (carry XOR feedback bit) comme LSB
    return ((doubled & 0xFFFFFFFF) + (((doubled >> 32) ^ bit) & 1)) & 0xFFFFFFFF


def emit(value: int, key_xor: int, out_xor: int, invert: bool = False) -> int:
    """
    Génère un byte du flag à partir de l'état courant.
    
    Mécanisme :
    1. Prend les 8 bits bas de l'état
    2. XOR avec key_xor → index dans la TABLE
    3. Substitution via TABLE (S-Box lookup)
    4. Optionnel : inversion de tous les bits
    5. XOR final avec out_xor
    """
    # Lookup dans la S-Box avec index = (octet_bas_état XOR clé)
    byte = TABLE[(value & 0xFF) ^ key_xor]
    if invert:
        # Inverser tous les bits : 0b10110011 → 0b01001100
        return (~byte) & 0xFF
    # XOR final pour "masquer" le résultat
    return byte ^ out_xor


def main() -> None:
    # ---- ÉTAT INITIAL ----
    # "DEAD BEEF" — référence à la mort (le djinn est "mort" dedans ?)
    # En tout cas, c'est une constante magique classique en RE/low-level
    state = 0xDEADBEEF

    # ---- SÉQUENCE HARDCODÉE (37 tuples) ----
    # Chaque tuple = (expected_state_low_byte, key_xor, out_xor, invert)
    # Les 37 itérations produisent 37 bytes = le flag complet
    sequence = [
        # iter  expected  key    out    inv    → char
        # 0     0x68      0x5A   0x34   False  → 'E'
        (0x68, 0x5A, 0x34, False),
        (0xBE, 0xB2, 0xD5, False),
        (0xB3, 0xAE, 0xBE, False),
        (0xD3, 0xDF, 0xE6, False),
        (0xB6, 0x7D, 0x4C, False),
        (0xC6, 0xCB, 0xD4, False),
        (0xDD, 0x84, 0x74, False),
        (0x38, 0x19, 0xD4, False),
        (0xDE, 0x5D, 0xB3, False),
        (0xFC, 0xCA, 0x5F, False),
        (0x32, 0xE9, 0x48, False),
        (0x94, 0x52, 0x4C, False),
        (0x7B, 0xFD, 0xCC, False),
        (0x126, 0x5A, 0xB6, False),
        (0x100, 0xF0, 0x13, False),
        (0x102, 0x03, 0x0E, False),
        (0xCB, 0xD5, 0x5D, False),
        (0x20, 0x1D, 0xAB, False),
        (0x105, 0xB1, 0x5F, False),
        (0x89, 0x39, 0xD2, False),
        (0xD9, 0xA9, 0x9E, False),
        (0x86, 0x60, 0xC0, False),
        (0x129, 0xDA, 0xDB, False),
        (0x43, 0xAA, 0xF1, False),
        (0x22, 0x96, 0x3A, False),
        (0xAD, 0x35, 0x78, False),
        (0x0A, 0x93, 0x00, True),   # ← seul tuple avec invert=True !
        (0xF0, 0xF1, 0x29, False),
        (0xE5, 0xFE, 0x10, False),
        (0x47, 0x5A, 0x48, False),
        (0x11F, 0x48, 0x49, False),
        (0x55, 0x5F, 0xD2, False),
        (0x3D, 0xFB, 0x8F, False),
        (0x21, 0xF0, 0x73, False),
        (0x0B, 0xD7, 0xC3, False),
        (0xA0, 0x5F, 0x73, False),
        (0xEB, 0xF4, 0x53, False),
    ]

    # ---- GÉNÉRATION DU FLAG ----
    output = bytearray()
    for expected_state, key_xor, out_xor, invert in sequence:
        # Générer un byte avec l'état courant
        output.append(emit(state, key_xor, out_xor, invert))
        # Avancer l'état (LFSR step)
        state = step(state)

    result = bytes(output)
    print(result.decode())   # → EcowasCTF{Dj1nN_5t4t3_mAcH1n3_0xD34D}


if __name__ == "__main__":
    main()
```

---

## Étape 6 — Exécution et vérification

```bash
$ python solve_djinn.py
EcowasCTF{Dj1nN_5t4t3_mAcH1n3_0xD34D}
```

**Flag** : `EcowasCTF{Dj1nN_5t4t3_mAcH1n3_0xD34D}`

---

## Analyse du flag

Décodé en leet speak :
- `Dj1nN` → **Djinn** (l'entité du challenge)
- `5t4t3_mAcH1n3` → **State Machine** (machine à états — exactement ce qu'est l'algorithme)
- `0xD34D` → **0xDEAD** → "DEAD" (clin d'œil à la graine initiale `0xDEADBEEF`)

Le nom complet du concept : **Djinn State Machine 0xDead** — l'algorithme est une machine à états initialisée à `0xDEADBEEF`.

---

## Résumé de la méthodologie RE

```
Binaire ELF
    │
    ├── strings           → indices sur les noms, messages
    ├── Ghidra/IDA        → décompilation en pseudo-C
    │       │
    │       ├── Identifier main()
    │       ├── Trouver la TABLE (section .rodata/data)
    │       ├── Décompiler step() → LFSR
    │       ├── Décompiler emit() → S-Box lookup
    │       └── Extraire la séquence hardcodée (37 tuples)
    │
    └── Python            → reproduire l'algo + exécuter → FLAG
```

**Leçon principale** : En RE, l'objectif n'est pas toujours de "patcher" le binaire ou de trouver un input valide. Parfois, le flag est **directement calculable** si on reproduit fidèlement l'algorithme du programme en dehors de lui. C'est exactement ce que fait ce challenge : la machine à états génère des bytes de flag de façon déterministe, et tout ce qu'on avait à faire était de l'imiter en Python.

---

## Outils recommandés pour débuter en RE

| Outil | Usage | Lien |
|-------|-------|------|
| Ghidra | Décompilateur gratuit (NSA) | https://ghidra-sre.org |
| IDA Free | Décompilateur (version gratuite) | https://hex-rays.com/ida-free |
| Binary Ninja Cloud | Décompilateur en ligne | https://cloud.binary.ninja |
| x64dbg | Débuggeur Windows | https://x64dbg.com |
| GDB + pwndbg | Débuggeur Linux | https://github.com/pwndbg/pwndbg |
| angr | Analyse symbolique (Python) | https://angr.io |

---

*Writeup par ITACHI — ECOWAS CTF 2026 — Challenge #49 Djinn (RE Hard, 500pts)*

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
