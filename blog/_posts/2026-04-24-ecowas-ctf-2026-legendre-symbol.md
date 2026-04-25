---
layout: post
title: "ECOWAS CTF 2026 — Legendre Symbol [Crypto/100pts]"
date: 2026-04-24 10:38:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [crypto, legendre-symbol, prg, quadratic-residues, number-theory, kpa, prime-recovery]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Crypto · **Difficulté :** ⭐⭐ (Medium) · **Points :** 100  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `output.txt` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/38_legendre_output.txt) |

---

---

---

## Description du challenge

> *Let's go back to 1797 or 1798*

**Fichier fourni :**
- `output.txt` — une liste de 336 grands entiers (~10¹⁵ chacun)

---

## 🔍 Première lecture

```python
[504093815235014, 946545434068944, 301534388298298, ...]
```

336 nombres. La description dit "retourne en 1797 ou 1798". C'est une date : **Adrien-Marie Legendre** a publié son *Essai sur la théorie des nombres* en **1797-1798**, où il introduit le **symbole de Legendre**.

---

## 📖 Le symbole de Legendre (rappel)

Le **symbole de Legendre** $\left(\frac{a}{p}\right)$ est défini pour un entier $a$ et un premier impair $p$ comme :

$$\left(\frac{a}{p}\right) = \begin{cases} 0 & \text{si } p \mid a \\ 1 & \text{si } a \text{ est un résidu quadratique mod } p \\ -1 & \text{si } a \text{ est un non-résidu quadratique mod } p \end{cases}$$

**Résidu quadratique** : $a$ est un résidu quadratique mod $p$ s'il existe $t$ tel que $t^2 \equiv a \pmod{p}$.

**Critère d'Euler** : on calcule le symbole de Legendre par :
$$\left(\frac{a}{p}\right) \equiv a^{(p-1)/2} \pmod{p}$$
Le résultat est $1$ (QR) ou $p-1 \equiv -1$ (QNR).

### Utilisation comme générateur pseudo-aléatoire de bits

Le symbole de Legendre peut servir de **bit** pseudo-aléatoire :
- Choisir un premier $p$ secret
- Pour encoder le bit $b$, choisir $x$ aléatoire qui soit **QR** si $b=1$, **QNR** si $b=0$
- Diffuser $x$ (pas $b$, pas $p$)

$\Rightarrow$ le message chiffré = liste de $x_i$ dont les résidus quadratiques encodent les bits du flag.

---

## 🧠 L'attaque : trouver p

`output.txt` ne contient **que les $x_i$**. Ni $p$, ni les bits. On doit trouver $p$.

### Contrainte fondamentale : $p > \max(\text{enc})$

Tous les $x_i$ sont des éléments de $\mathbb{Z}/p\mathbb{Z}$, donc $0 \leq x_i < p$.

$$\max(\text{enc}) = 1006204785090705 \implies p > 1006204785090705$$

### Attaque par texte clair connu (KPA)

Le format du flag est `EcowasCTF{...}`. On connaît les 80 premiers bits :

```python
known_bits = ''.join(format(ord(c), '08b') for c in 'EcowasCTF{')
# = "01000101011000110110111101110111..."
```

Pour chaque candidat premier $p' > \max(\text{enc})$ :
1. Calculer $\text{Legendre}(x_i, p') = \text{pow}(x_i, (p'-1)/2, p')$ pour $i = 0..79$
2. Vérifier que le résultat correspond aux bits de `'EcowasCTF{'`
3. Si oui → $p$ trouvé !

La probabilité qu'un faux candidat passe 80 bits = $1/2^{80}$ → **pratiquement nulle**.

### Efficacité du scan

L'espace entre $\max(\text{enc})$ et $p$ réel :
$$p - \max(\text{enc}) = 1\,416\,712\,324\,545 \approx 1.4 \times 10^{12}$$
$$\text{Primes dans cet intervalle} \approx \frac{1.4 \times 10^{12}}{\ln(10^{15})} \approx 41 \text{ milliards}$$

En Python pur → trop lent (100+ heures). En SageMath ou C → faisable (quelques minutes à heures avec optimisation).

**Optimisation clé** : tester d'abord un seul bit du préfixe. Seulement 50% des candidats passent chaque bit → après 8 bits, seul 1/256 des candidats reste.

### Erreurs de recherche commises

| Approche | Problème |
|----------|---------|
| Scan primes < 10^6 | Beaucoup trop petit : $p \approx 10^{15}$ |
| Scan primes near max(enc) | Bonne direction, mais scan Python trop lent sur 41B primes |
| GCD attacks | Circulaire : on a besoin de $p$ pour calculer les Legendre |

### La leçon

> **Première chose à vérifier : $p > \max(\text{enc})$. Toujours commencer le scan depuis là.**

---

## 🔧 Solution

```python
p = 1007621497415251  # trouvé par Known-Plaintext Attack depuis max(enc)+1

bits = ''
for x in enc:
    legendre = pow(x, (p - 1) // 2, p)
    bits += '1' if legendre == 1 else '0'

flag = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
print(flag)
```

### Vérification du décodage

```
336 nombres → 336 bits → 42 octets → 42 caractères ASCII
```

| Partie | Valeur |
|--------|--------|
| Bits | `01000101 01100011 01101111 01110111 ...` |
| ASCII | `E c o w a s C T F { ...` |

---

## ✅ Flag

```
EcowasCTF{p4tterns_1n_re5idu3s_85e5ae3583}
```

Le flag traduit lui-même l'attaque : *"patterns in residues"* (motifs dans les résidus quadratiques).

---

## 💡 Résumé de l'attaque KPA sur Legendre PRG

```
Données  : enc[] (sans p)
Connu    : format flag "EcowasCTF{" → 80 bits
Contrainte: p > max(enc)

1. Pour p_cand dans primes(max(enc)+1, ...):
2.   Si Legendre(enc[0..79], p_cand) == known_bits[0..79]:
3.     p = p_cand  ← trouvé !
4. Décoder: bit[i] = (pow(enc[i], (p-1)//2, p) == 1)
5. Flag = bits → ASCII
```

---

## 🛠️ Script de solve complet

```python
#!/usr/bin/env python3
"""
Legendre Symbol PRG - ECOWAS CTF 2026 - Challenge 38
p trouvé par KPA depuis max(enc)+1
"""
import ast

enc = ast.literal_eval(open('output.txt').read())
p = 1007621497415251

bits = ''.join('1' if pow(x, (p - 1) // 2, p) == 1 else '0' for x in enc)
flag = ''.join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8))
print(flag)
```

---

## 💡 Leçons apprises

1. **p > max(enc) toujours** : dans tout chiffrement basé sur $\mathbb{Z}/p\mathbb{Z}$, les éléments sont < $p$. La borne inférieure de la recherche est donc $\max(\text{données}) + 1$.

2. **KPA sur Legendre PRG** : si on connaît les premiers bits en clair (flag format !), on peut vérifier chaque candidat $p'$ en quelques opérations mod. Avec 80 bits connus, un faux positif aléatoire a probabilité $2^{-80}$ → pratiquement zéro faux positifs.

3. **Python insuffisant pour 41 milliards de primes** : utiliser SageMath (`next_prime()` backed by PARI/GP) ou C pour des scans > $10^{11}$ candidats.

4. **Indice "1797 ou 1798"** : pure référence historique à Legendre (pas d'information sur $p$). La date dit juste "utilise le symbole de Legendre".

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
