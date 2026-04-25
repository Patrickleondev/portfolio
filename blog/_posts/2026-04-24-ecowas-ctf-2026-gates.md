---
layout: post
title: "ECOWAS CTF 2026 — Gates [Reverse/100pts]"
date: 2026-04-24 10:44:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [reverse, mach-o, strings, decoy-flags, static-analysis, arm64]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Reverse Engineering · **Difficulté :** ⭐ (Easy) · **Points :** 100  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `gates.zip` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/44_gates.zip) |

---

## Description du challenge

> *(Pas de description textuelle — juste un binaire `gates` à télécharger)*

---

## 📖 Notions fondamentales

### Qu'est-ce que le Reverse Engineering (RE) ?

Le **Reverse Engineering** (rétro-ingénierie) consiste à analyser un programme compilé (binaire) pour comprendre son fonctionnement **sans avoir accès au code source**.

En CTF, le schéma typique est :
```
Binaire mystère
    ↓ On l'analyse (statiquement ou dynamiquement)
    ↓ On comprend comment il vérifie une entrée
    ↓ On trouve la condition de succès
    → FLAG
```

### Types d'analyse

| Type | Description | Avantages |
|------|-------------|-----------|
| **Statique** | Examiner le binaire sans l'exécuter | Sûr, pas besoin du bon OS |
| **Dynamique** | Exécuter et observer avec un debugger | Plus intuitif, voit les valeurs réelles |

### Qu'est-ce qu'un binaire Mach-O ?

Un **Mach-O** (Mach Object) est le format d'exécutable utilisé sur macOS (et iOS). C'est l'équivalent macOS de :
- ELF (`Executable and Linkable Format`) sur Linux
- PE (`Portable Executable` / `.exe`) sur Windows

On peut étudier un Mach-O statiquement sur n'importe quel OS, même sans Mac.

### Qu'est-ce que la commande `strings` ?

La commande `strings` extrait toutes les **chaînes de caractères lisibles** (ASCII) d'un fichier binaire. C'est l'une des premières choses à faire en RE — pour trouver des messages, des clés, des noms de fonctions.

```bash
strings mon_binaire | grep -i "flag\|pass\|secret\|key"
```

---

## Étape 1 — Identification du binaire

```python
data = open('gates', 'rb').read()
print(f"Taille: {len(data)} octets")
print(f"Magic: {data[:4].hex()}")  # cffaedfe
```

Les 4 premiers octets `cf fa ed fe` sont la signature **Mach-O 64-bit** (little-endian).

En hexadécimal :
```
cf fa ed fe  →  0xFEEDFACF en big-endian  →  "FEEDFACE" / Mach-O 64-bit LE
```

---

## Étape 2 — Extraction des chaînes (strings)

```python
import re

data = open('gates', 'rb').read()

# Extraire toutes les chaînes ASCII de longueur >= 4
strings_found = re.findall(rb'[\x20-\x7e]{4,}', data)

for s in strings_found:
    print(s.decode())
```

**Extrait de la sortie :**
```
__PAGEZERO
__TEXT
...
Enter the flag: 
That gate is a decoy. %d gates remain.
EcowasCTF{n0m4d_tr41l_w1nd3s}
EcowasCTF{fl4m1ng0_d4nc3s}
EcowasCTF{vultur3_c1rcl3s}
...
EcowasCTF{0nly_0n3_g4t3_0p3ns_th3_w4y}   ← SUSPECT !
...
EcowasCTF{fl4g_hunt3r_w1ns_n0t}
EcowasCTF{p4rr0t_r3p34ts_n0n3}
...
```

Il y a **exactement 100 chaînes** `EcowasCTF{...}` dans le binaire !

---

## Étape 3 — Comprendre la logique du challenge

Le message `"That gate is a decoy. %d gates remain."` est révélateur : il y a des **portes (gates)** qui sont des leurres (decoys), et **une seule** qui est la vraie.

En regardant la liste, un flag particulier se démarque :

```
EcowasCTF{0nly_0n3_g4t3_0p3ns_th3_w4y}
```

La traduction : **"Only one gate opens the way"** (Une seule porte ouvre le chemin).

C'est à la fois :
1. Un message méta sur le challenge lui-même
2. La réponse à sa propre question

Tous les autres flags sont des leurres. Le "vrai" flag se désigne lui-même dans son texte.

---

## Étape 4 — Vérification de la position dans le binaire

```python
data = open('gates', 'rb').read()
target = b'EcowasCTF{0nly_0n3_g4t3_0p3ns_th3_w4y}'
idx = data.find(target)
print(f"Trouvé à l'offset: 0x{idx:x} = {idx}")
# Sortie: Trouvé à l'offset: 0x39bd = 14781
```

Il est bien présent dans les données du binaire, dans la section `__cstring` (constantes de chaînes de caractères).

---

## Script complet de solve

```python
import re

data = open('gates', 'rb').read()

# Extraire tous les flags EcowasCTF
all_flags = [s.decode() for s in re.findall(rb'EcowasCTF\{[^\}]+\}', data)]
print(f"Nombre de flags trouvés: {len(all_flags)}")

# Chercher celui qui parle de "l'unique porte"
for flag in all_flags:
    if '0nly' in flag or 'only' in flag.lower() or '1' in flag and 'g4t3' in flag:
        print(f"Candidat: {flag}")

# Ou simplement chercher le flag auto-descriptif
real_flag = "EcowasCTF{0nly_0n3_g4t3_0p3ns_th3_w4y}"
print(f"\nFLAG: {real_flag}")
```

---

## Pourquoi ce challenge est pédagogique

Ce challenge enseigne plusieurs leçons importantes :

### 1. Toujours commencer par `strings`

Avant de plonger dans le désassemblage complexe, la commande `strings` révèle souvent l'essentiel immédiatement.

### 2. Les leurres (decoys) en RE

Dans la vraie vie et en CTF, les binaires utilisent des "fausses pistes" pour dérouter les reverse engineers. Techniques courantes :
- Plusieurs chemins de succès dont un seul est vrai
- Chaînes de caractères intentionnellement visibles mais fausses
- Anti-debug pour compliquer l'analyse dynamique

### 3. Lire les messages du programme

La chaîne `"That gate is a decoy. %d gates remain."` dit explicitement qu'il y a des leurres. Lire les **messages** du programme est souvent aussi informatif que lire son code.

---

## Chaîne d'exploitation

```
┌─ Binaire gates (Mach-O 64-bit ARM64)
│
├─ strings → 100 flags EcowasCTF{...} dont 99 leurres
│
└─ Analyse sémantique → "0nly_0n3_g4t3_0p3ns_th3_w4y"
                        ↑
                   S'auto-désigne comme le vrai flag
```

---

## Flag

```
EcowasCTF{0nly_0n3_g4t3_0p3ns_th3_w4y}
```

---

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
