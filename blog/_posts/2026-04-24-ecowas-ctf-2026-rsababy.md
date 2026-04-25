---
layout: post
title: "ECOWAS CTF 2026 — Rsababy [Crypto/50pts]"
date: 2026-04-24 10:36:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [crypto, rsa, small-exponent, cube-root, e3, no-padding, gmpy2]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Crypto · **Difficulté :** ⭐ (Easy) · **Points :** 50  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Description du challenge

> *"This should be fun, as I know what I'm doing with m3."*

Les paramètres RSA sont directement donnés dans la description :
```
n = 0x77ce5ee900868d7f...  (2047 bits)
e = 3
c = 0x5190815ee3d8be07...  (811 bits)
```

L'indice **"m3"** est un jeu de mots : `m^3` (m puissance 3), ce qui révèle l'attaque à utiliser.

---

### Comment fonctionne RSA ?

RSA est un système de chiffrement asymétrique. Voici les bases :

**Génération des clés :**
1. Choisir deux grands nombres premiers `p` et `q`
2. Calculer `n = p × q` (la "clé publique")
3. Calculer `φ(n) = (p-1)(q-1)` (indicatrice d'Euler)
4. Choisir `e` tel que `gcd(e, φ(n)) = 1` (souvent `e = 65537`)
5. Calculer `d` tel que `e × d ≡ 1 (mod φ(n))` (la "clé privée")

**Chiffrement :** `c = m^e mod n`

**Déchiffrement :** `m = c^d mod n`

### Pourquoi e=3 est dangereux ?

Avec `e = 3`, le chiffrement devient `c = m^3 mod n`.

Si le message `m` est **petit** par rapport à `n`, alors :
```
m^3 < n   →   m^3 mod n = m^3   (le modulo ne s'active jamais !)
```

Dans ce cas, `c = m^3` exactement (sans modulo), et on peut simplement **extraire la racine cubique entière** de `c` pour trouver `m`.

```
c = 811 bits   <   n = 2047 bits
→ m^3 < n  (très probablement)
→ c = m^3 exactement
→ m = ∛c
```

---

## Étape 1 — Vérifier si m^3 < n

```python
n = 0x77ce5ee900868d7f...
c = 0x5190815ee3d8be07...

print(f"n: {n.bit_length()} bits")   # 2047 bits
print(f"c: {c.bit_length()} bits")   # 811 bits

# Si c < n, il est possible que c = m^3 exactement
print(f"c < n: {c < n}")  # True
```

Le ciphertext `c` fait 811 bits et `n` fait 2047 bits.

Si `m^3 = c` est exact (pas de modulo), alors `m` ferait `811 / 3 ≈ 270 bits`.

---

## Étape 2 — Calculer la racine cubique entière

```python
import gmpy2  # bibliothèque de précision arbitraire

m, exact = gmpy2.iroot(c, 3)  # iroot(n, k) = racine k-ième entière

print(f"Exact: {exact}")  # True si c est un cube parfait
if exact:
    flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
    print("FLAG:", flag_bytes.decode())
```

`gmpy2.iroot(c, 3)` retourne le couple `(m, exact)` où :
- `m` est la partie entière de `∛c`
- `exact` vaut `True` si `m^3 == c` exactement

### Pourquoi gmpy2 et pas `pow(c, 1/3)` en Python normal ?

Parce que les nombres RSA sont **énormes** (811 bits = 244 chiffres décimaux). La fonction `pow()` standard Python et le type `float` n'ont que 64 bits de précision, ce qui introduit des erreurs et donnerait une mauvaise réponse.

`gmpy2` utilise la bibliothèque GMP (GNU Multiple Precision) qui gère une précision arbitraire.

```bash
# Installation
pip install gmpy2
```

---

## Étape 3 — Exécution et résultat

```python
import gmpy2

n = 0x77ce5ee900868d7fce486622dd689ad52a9d5092bd292662f05f321190a72f0f...
c = 0x5190815ee3d8be07d0810aa5876b5e2052fd8b780410c599844144afb8e72f1f...
e = 3

m, exact = gmpy2.iroot(c, 3)
print(f"Racine cubique exacte: {exact}")  # True

flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
print("FLAG:", flag_bytes.decode())
```

**Sortie :**
```
n bits: 2047
c bits: 811
c < n: True
Cube root exact: True
FLAG: EcowasCTF{cub3_r00t_n0_p4dd1ng_ez}
```

---

## Pourquoi "no padding" dans le flag ?

Le flag `EcowasCTF{cub3_r00t_n0_p4dd1ng_ez}` contient "no padding", ce qui est la leçon principale de ce challenge.

En RSA standard, on utilise **PKCS#1 v1.5** ou **OAEP** comme schéma de bourrage (padding). Le bourrage ajoute des octets aléatoires **avant** le message, ce qui rend `m` toujours grand (proche de `n`) :

```
Avec padding :    m_padded = [00 02] + [octets_aléatoires] + [00] + [message]
                 → m_padded ~ n  → m_padded^3 > n  → modulo s'active
                 → attaque racine cubique ÉCHOUE

Sans padding :    m_raw = [message]
                 → m_raw petit si message court
                 → m_raw^3 < n possible
                 → attaque racine cubique RÉUSSIT
```

C'est une des erreurs classiques en crypto : utiliser RSA **sans padding** est dangereux.

---

## Script complet

```python
import gmpy2

# Paramètres du challenge
n = int("0x77ce5ee900868d7fce486622dd689ad52a9d5092bd292662f05f321190"
        "a72f0f721c36511f061462e4c83fa3cea9b01440baad9ab3e93ad85f59a4"
        "2b50232b76fe0f81afbf6bcdaddd43566269a5595b1345a6c75d7d483b3e"
        "659b243ad51bd26bd2fd9e5c75887501efd2cc803a47801ecb3897a0fd4c3"
        "c70566cf9ffc1482f6da7cf1a85e36f78727104b994de56e8147026d435af"
        "d7d9f8244f0e175c351bf85899f974fc01c5a97797f928f7bfee36277f8d5"
        "eea49b7c5517802d4274ecbe7d47797ff91571797452feab2465daf216d9d3"
        "73d23781e320a4ed6703549f049251f42de97b7f636ae4efae36b0ba9589a3"
        "eed2e11b9ea4592ba784792e675", 16)

c = int("0x5190815ee3d8be07d0810aa5876b5e2052fd8b780410c599844144afb8"
        "e72f1f93a76b0a6c966d318bb4e0c31260b0e40042777ca3fa7504f8e327"
        "42076f6954f12c9d536fb7463f2ccdf887521d121ce32448914f2e5b6757"
        "f9f0fe1d3346425b588c3ab65", 16)
e = 3

# Attaque : racine cubique entière
m, exact = gmpy2.iroot(c, 3)

if exact:
    flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
    print("FLAG:", flag_bytes.decode())
else:
    print("Pas exact — essayer d'autres approches")
```

---

## Flag

```
EcowasCTF{cub3_r00t_n0_p4dd1ng_ez}
```

---

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
