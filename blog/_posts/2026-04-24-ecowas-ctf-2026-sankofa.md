---
layout: post
title: "ECOWAS CTF 2026 — Sankofa [Crypto/300pts]"
date: 2026-04-24 10:47:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [crypto, ecdsa, lcg, nonce-reuse, secp256k1, lattice, aes-cbc, private-key-recovery, sqrt-mod]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Crypto · **Difficulté :** ⭐⭐⭐ (Hard) · **Points :** 300  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `sankofa_files.zip` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/47_sankofa_files.zip) |

---

## Description du challenge

> *Pas de description textuelle — juste les fichiers `oracle.py` et `output.json`.*

Le nom "Sankofa" est un symbole Adinkra signifiant **"Retourner chercher"** — une métaphore pour retrouver quelque chose depuis le passé. Ici, on va "retourner chercher" la clé privée depuis les signatures.

**Fichiers fournis :**
- `oracle.py` — le code source du serveur qui a généré les signatures
- `output.json` — les données publiques (signatures + clé publique + flag chiffré)

---

### Qu'est-ce que la cryptographie sur courbes elliptiques (ECC) ?

La **cryptographie sur courbes elliptiques** (ECC - Elliptic Curve Cryptography) est une branche de la cryptographie asymétrique. On travaille sur une **courbe elliptique** définie par l'équation :

$$y^2 = x^3 + ax + b \pmod{p}$$

Les courbes elliptiques permettent d'obtenir la même sécurité que RSA avec des clés bien plus petites.

#### Points sur une courbe elliptique

Un **point** sur la courbe est une paire `(x, y)` vérifiant l'équation. Il existe une opération d'**addition de points** qui produit un autre point sur la courbe.

Le **point générateur** `G` est un point de référence public.

#### ECDSA (Elliptic Curve Digital Signature Algorithm)

**ECDSA** est l'algorithme de signature basé sur ECC. C'est l'algorithme utilisé dans Bitcoin, TLS, et des centaines d'autres protocoles.

**Clés :**
- Clé privée `d` : un grand entier secret
- Clé publique `Q = d × G` : un point sur la courbe (calculé depuis `d`)

**Signature d'un message `m` :**
1. Générer un nombre aléatoire **éphémère** `k` (le nonce)
2. Calculer `R = k × G`, garder `r = R.x mod n`
3. Calculer `s = k⁻¹ × (H(m) + r × d) mod n`
4. La signature est la paire `(r, s)`

**Vérification :**
- Avec la clé publique `Q`, on peut vérifier que la signature `(r, s)` est valide sans connaître `d`

> **Règle d'or ECDSA :** Le nonce `k` doit être **aléatoire et unique** pour chaque signature. Si deux signatures utilisent le même `k`, la clé privée est immédiatement récupérable !

---

### Qu'est-ce qu'un générateur congruentiel linéaire (LCG) ?

Un **LCG** (Linear Congruential Generator) est un générateur de nombres pseudo-aléatoires très simple :

$$\text{state}_{i+1} = \alpha \times \text{state}_i + \beta \pmod{n}$$

Où `α`, `β`, et la graine initiale (`seed`) sont des paramètres secrets.

**Problème de sécurité :** Si l'attaquant connaît plusieurs sorties consécutives du LCG, il peut retrouver les paramètres `α` et `β` par une simple résolution d'équation linéaire.

---

## Lecture du code source (`oracle.py`)

```python
# Les nonces k sont générés par un LCG !
def sign(msg: bytes):
    global state
    state = (alpha * state + beta) % n   # ← LCG !
    k = state                            # ← k = sortie directe du LCG
    R = ec_mul(k, G)
    r = R[0] % n
    s = (pow(k,-1,n) * (H(msg) + r*d)) % n
    return r, s
```

**Vulnérabilité critique :** Les nonces `k` ne sont pas aléatoires — ils sont générés par un LCG avec des paramètres inconnus mais **déterministes** !

Si on a 4 signatures, on a 4 nonces `k₀, k₁, k₂, k₃` avec :
```
k₁ = α × k₀ + β  (mod n)
k₂ = α × k₁ + β  (mod n)
k₃ = α × k₂ + β  (mod n)
```

---

## La faille mathématique : récupérer k depuis (r, s)

Depuis une signature `(r, s)` pour un message `m`, on peut écrire :
```
s = k⁻¹ × (H(m) + r × d)  (mod n)
```

Donc :
```
k = s⁻¹ × (H(m) + r × d)  (mod n)
k = a + b × d               (mod n)
```

Où `a = H(m) × s⁻¹` et `b = r × s⁻¹` sont des valeurs **calculables** depuis les données publiques.

Chaque signature `i` donne : `kᵢ = aᵢ + bᵢ × d (mod n)`

---

## L'attaque sur le LCG

Le LCG donne :
```
k₁ = α × k₀ + β          (mod n)
k₂ = α × k₁ + β          (mod n)
```

En substituant `kᵢ = aᵢ + bᵢ × d` :
```
k₁ - k₀ = α × (k₀ - k₋₁)    →    k₁ = α × k₀ + β
(a₁ + b₁d) = α(a₀ + b₀d) + β
```

En prenant les différences entre équations consécutives :
```
dk₁ = k₂ - k₁ = α × (k₁ - k₀) = α × dk₀
```

Ce qui donne :
```
(a₂ - a₁) + (b₂ - b₁)d = α × [(a₁ - a₀) + (b₁ - b₀)d]
```

En notant `da_i = aᵢ₊₁ - aᵢ` et `db_i = bᵢ₊₁ - bᵢ` :
```
da₁ + db₁ × d = α × (da₀ + db₀ × d)
da₁ + db₁ × d = α × da₀ + α × db₀ × d
```

En réarrangeant :
```
da₁ - α × da₀ = (α × db₀ - db₁) × d
```

Et en utilisant une troisième équation :
```
da₂ - α × da₁ = (α × db₁ - db₂) × d
```

En éliminant `d` entre ces deux équations, on obtient une équation du second degré en `α`, qu'on résout avec la formule quadratique modulo `n` (en calculant une racine carrée modulaire).

---

## Le code de résolution

```python
from sympy.ntheory import sqrt_mod
import hashlib, json
from Crypto.Cipher import AES

# Paramètres de secp256k1 (courbe Bitcoin)
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def hash_message(message):
    return int.from_bytes(hashlib.sha256(message.encode()).digest(), "big") % N

def compute_ab(signature):
    """Depuis (r, s, msg), calculer a et b tels que k = a + b*d"""
    r = int(signature["r"], 16)
    s = int(signature["s"], 16)
    h = hash_message(signature["msg"])
    s_inv = pow(s, -1, N)
    a = h * s_inv % N   # contribution du hash
    b = r * s_inv % N   # contribution de la clé privée
    return a, b

def recover_private_key(signatures, public_key):
    # Calculer (a, b) pour chaque signature
    a0, b0 = compute_ab(signatures[0])
    a1, b1 = compute_ab(signatures[1])
    a2, b2 = compute_ab(signatures[2])
    a3, b3 = compute_ab(signatures[3])

    # Différences entre signatures consécutives
    da = (a1-a0)%N; db = (b1-b0)%N   # k1 - k0
    ea = (a2-a1)%N; eb = (b2-b1)%N   # k2 - k1
    fa = (a3-a2)%N; fb = (b3-b2)%N   # k3 - k2

    # Résoudre l'équation quadratique en alpha (mod N)
    # alpha² * (db²) - alpha * (2*da*db + ...) + da² = 0  (mod N)
    coeff_a = (eb*eb - fb*db) % N
    coeff_b = (2*ea*eb - fa*db - fb*da) % N
    coeff_c = (ea*ea - fa*da) % N
    discriminant = (coeff_b*coeff_b - 4*coeff_a*coeff_c) % N

    # sqrt_mod donne les racines carrées modulo N
    sqrt_values = sqrt_mod(discriminant, N, all_roots=True)
    inv_2a = pow((2*coeff_a) % N, -1, N)

    generator = (GX, GY)
    expected_q = (int(public_key["x"], 16), int(public_key["y"], 16))

    # Tester chaque candidat pour alpha
    for sqrt_value in sqrt_values:
        for candidate_alpha in [
            ((-coeff_b + sqrt_value) * inv_2a) % N,
            ((-coeff_b - sqrt_value) * inv_2a) % N,
        ]:
            # Calculer d depuis alpha et la première paire de signatures
            # k1 = alpha*k0 + beta → k1 - alpha*k0 = beta
            # En substituant k_i = a_i + b_i*d :
            # a1 + b1*d = alpha*(a0 + b0*d) + beta
            # → d*(b1 - alpha*b0) = alpha*a0 - a1 + beta
            # ... on cherche d tel que ec_mul(d, G) = Q_public
            # Ce qui se fait en testant les candidats depuis la formule quadratique
            numerator = (da - candidate_alpha * (a0 - a1)) % N
            # ... (code simplifié, voir solve_sankofa.py pour version complète)
            
            # La méthode complète: on a d candidats depuis les formules
            # On vérifie en comparant ec_mul(d, G) avec la clé publique attendue
            ...

def decrypt_flag(private_key, flag_ct):
    key = hashlib.sha256(private_key.to_bytes(32, "big")).digest()
    iv = bytes.fromhex(flag_ct["iv"])
    ciphertext = bytes.fromhex(flag_ct["ciphertext"])
    plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    return plaintext[:-plaintext[-1]]  # enlever le PKCS7 padding

# Chargement et solve
data = json.load(open("output.json"))
private_key = recover_private_key(data["signatures"], data["Q"])
flag = decrypt_flag(private_key, data["flag_ct"])
print(flag.decode())
# → "EcowasCTF{r3turn_4nd_f3tch_1t_l1near_LCG_kn0n_nonces}"
```

---

## Comprendre le déchiffrement du flag

Une fois la clé privée `d` récupérée :

1. **Dériver la clé AES** depuis `d` :
   ```python
   key = SHA256(d.to_bytes(32, 'big'))
   ```

2. **Déchiffrer le flag AES-CBC** :
   ```
   flag = AES_CBC_decrypt(key, iv, ciphertext)
   ```

3. **Enlever le padding PKCS#7** :
   ```python
   plaintext = plaintext[:-plaintext[-1]]  # dernier octet = longueur du padding
   ```

---

## Récapitulatif de l'attaque

```
oracle.py: nonces k générés par LCG
    k_i = alpha * k_{i-1} + beta  (mod n)

output.json: 4 signatures (r_i, s_i) + clé publique Q

Étape 1: Depuis (r_i, s_i) → calculer (a_i, b_i) tels que k_i = a_i + b_i*d
Étape 2: Utiliser les relations LCG pour écrire une équation en alpha et d
Étape 3: Résoudre l'équation quadratique mod n pour alpha (sqrt_mod)
Étape 4: Retrouver d en vérifiant ec_mul(d, G) = Q
Étape 5: Déchiffrer le flag avec SHA256(d) comme clé AES-256-CBC
```

---

## Connexion avec le nom "Sankofa"

Le symbole Adinkra **Sankofa** représente un oiseau qui regarde **en arrière** tout en avançant — "il n'est pas mauvais de retourner chercher ce qu'on a oublié".

Ici, on "retourne chercher" la clé privée `d` que l'attaquant aurait dû garder secrète, mais à travers la vulnérabilité du LCG dans la génération des nonces.

---

## Flag

```
EcowasCTF{r3turn_4nd_f3tch_1t_l1near_LCG_kn0n_nonces}
```

---

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
