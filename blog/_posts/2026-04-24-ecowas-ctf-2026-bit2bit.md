---
layout: post
title: "ECOWAS CTF 2026 — Bit2Bit [Crypto/Merkle Tree]"
date: 2026-04-24 10:00:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [crypto, merkle-tree, sha256, bit-extraction, binary-encoding]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Cryptographie · **Difficulté :** ⭐⭐⭐ (Hard) · **Points :** 400  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

> **Writeup par : 0xWhoAm1** — Équipe **DarkPulse**

---

## Description du challenge

![Challenge Bit2Bit](/assets/img/ecowas-2026/lion/bit2bit-challenge.png)

Le challenge fournit un fichier `output.txt` contenant **295 lignes**. Chaque ligne est un tuple de 5 hashes SHA-256 hexadécimaux représentant les nœuds d'un **arbre de Merkle binaire à 4 feuilles**.

Un message secret (le flag) a été encodé dans ces 295 arbres : chaque arbre encode **1 bit** du flag.

---

## Analyse du code source fourni

```python
def hash256(data):
    return sha256(data).digest()

def merge_nodes(a, b):
    return hash256(a + b)

def gen_test(is_true):
    a = hash256(os.urandom(8))
    b = hash256(os.urandom(8))
    c = hash256(os.urandom(8))
    d = hash256(os.urandom(8))
    bias = b"" if is_true else os.urandom(8)
    left  = merge_nodes(a, b + bias)   # ← bias injecté ici !
    right = merge_nodes(c, d)
    root  = merge_nodes(left, right)
    return a.hex(), b.hex(), c.hex(), d.hex(), root.hex()
```

**Structure de l'arbre de Merkle :**

```
          root
         /    \
      left    right
      /  \    /  \
     a   b   c   d
```

**Logique d'encodage des bits :**

| Bit | `bias` | `left` calculé | Conséquence |
|-----|--------|----------------|-------------|
| `1` (`is_true=True`) | `b""` (vide) | `hash(a ‖ b)` | Root cohérent avec `a, b, c, d` |
| `0` (`is_true=False`) | `os.urandom(8)` (8 bytes aléatoires ajoutés à `b`) | `hash(a ‖ b ‖ bias)` | Root incohérent avec les feuilles |

**Insight clé :** si le bit est `1`, le root peut être recalculé depuis les 4 feuilles. Si le bit est `0`, le root ne correspond **pas** au recalcul depuis les feuilles (car `b + bias ≠ b`).

---

## Méthode de résolution

Pour chaque ligne de `output.txt` contenant `[a, b, c, d, root]` :

1. Calculer `left_test = SHA256(a ‖ b)`
2. Calculer `right_test = SHA256(c ‖ d)`
3. Calculer `root_test = SHA256(left_test ‖ right_test)`
4. Comparer : `root_test == root` → bit = `1`, sinon bit = `0`
5. Assembler les 295 bits, convertir en bytes → flag

---

## Script de résolution

```python
from hashlib import sha256
import ast

def hash256(data):
    return sha256(data).digest()

def recover_flag(filepath):
    with open(filepath) as f:
        lines = f.readlines()

    bits = ""
    for line in lines:
        # Chaque ligne est un tuple Python: (a_hex, b_hex, c_hex, d_hex, root_hex)
        a, b, c, d, root = ast.literal_eval(line.strip())
        a     = bytes.fromhex(a)
        b     = bytes.fromhex(b)
        c     = bytes.fromhex(c)
        d     = bytes.fromhex(d)
        root  = bytes.fromhex(root)

        # Recalculer le root depuis les feuilles (sans bias)
        left_test  = hash256(a + b)
        right_test = hash256(c + d)
        root_test  = hash256(left_test + right_test)

        # Si les roots correspondent : bit 1 (arbre non corrompu)
        # Sinon : bit 0 (bias aléatoire avait altéré la feuille b)
        bits += "1" if root_test == root else "0"

    # Convertir la séquence de bits en texte
    n    = int(bits, 2)
    flag = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big").decode()
    return flag

if __name__ == "__main__":
    flag = recover_flag("output.txt")
    print(flag)
```

---

## Flag

```
EcowasCTF{b1t2b1t_ac9db9c3c1}
```

---

## Pourquoi ça fonctionne ?

La propriété exploitée est la **déterminisme de SHA-256** : étant donné les mêmes entrées, SHA-256 produit toujours la même sortie. Si le `bias` est vide, on peut vérifier la cohérence de l'arbre. Si le `bias` est non-nul (aléatoire), l'arbre est "cassé" et le root ne correspond plus.

> **Arbre de Merkle :** structure de données où chaque nœud parent est le hash de la concaténation de ses enfants. Utilisé dans Bitcoin (transactions), Git (commits), et les systèmes de vérification d'intégrité. Voir [Wikipedia — Merkle tree](https://fr.wikipedia.org/wiki/Arbre_de_Merkle).

La beauté du challenge : les 4 feuilles `a, b, c, d` sont **toujours données en clair** dans `output.txt`. La seule chose à vérifier est si le root fourni est cohérent avec une reconstruction propre (sans bias). C'est un test d'intégrité standard sur un arbre de Merkle.
