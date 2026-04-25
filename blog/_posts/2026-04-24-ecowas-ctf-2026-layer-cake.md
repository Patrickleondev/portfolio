---
layout: post
title: "ECOWAS CTF 2026 — Layer Cake [Crypto/100pts]"
date: 2026-04-24 10:37:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [crypto, encoding, base64, hex, layered-encoding, cyberchef]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Crypto · **Difficulté :** ⭐ (Easy) · **Points :** 100  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Description du challenge

> Le "challenge" est la description elle-même :
>
> `==AZzQ2MxUjN2AzMlRTY3QGNzMTZ0MzM4UTO3UGN0UTN2AzM3cjMzgTN1MTY0IzM4UTO3UGN0UTN2AzM3cjMzUjN3QjM1EzMxUTY3YDNyMDN2YzNlRzN1ITN`

Il n'y a pas de fichier à télécharger — le flag est directement caché dans le texte de la description.

---

---

## Observation initiale

Le texte de la description commence par `==` — ce sont des caractères de **bourrage Base64** qui, normalement, se trouvent à la fin. Cela suggère que la chaîne est **inversée**.

```
Chaîne normale B64 : "RWNvd2FzQ1RGe...=="
Chaîne inversée    : "==...eGFzQ1RGe..."
```

---

## Démarche de résolution

### Étape 1 — Inverser la chaîne

```python
desc = "==AZzQ2MxUjN2AzMlRTY3QGNzMTZ0MzM4UTO3UGN0UTN2AzM3cjMzgTN1MTY0IzM4UTO3UGN0UTN2AzM3cjMzUjN3QjM1EzMxUTY3YDNyMDN2YzNlRzN1ITN"

# Inverser = lire de droite à gauche
reversed_str = desc[::-1]
print(reversed_str)
# → "NTI1NzRlNzY2NDMyNDY3YTUxMzE1MjQ..."
```

### Étape 2 — Décoder la chaîne inversée en Base64

```python
import base64

step1 = base64.b64decode(reversed_str).decode()
print(step1)
# → "52574e766432467a5131524765..."  ← une longue chaîne de chiffres hex !
```

Le résultat est une chaîne constituée uniquement de chiffres `0-9` et lettres `a-f` — c'est de l'hexadécimal.

### Étape 3 — Décoder l'hexadécimal

```python
step2 = bytes.fromhex(step1).decode()
print(step2)
# → "RWNvd2FzQ1RGe2w0eTNyX2J5X2w0eTNyX3N3MzN0fQ=="
```

On obtient une nouvelle chaîne Base64 (elle se termine par `==`).

### Étape 4 — Décoder le Base64 final

```python
flag = base64.b64decode(step2).decode()
print(flag)
# → "EcowasCTF{l4y3r_by_l4y3r_sw33t}"
```

---

## Résumé de la chaîne de décodage

```
Description originale : ==AZzQ2Mx...N1ITN
        ↓  Étape 1 : Inverser la chaîne
Chaîne inversée       : NTI1NzRl...
        ↓  Étape 2 : Décoder Base64
Hexadécimal           : 52574e76...
        ↓  Étape 3 : Décoder Hex → bytes
Base64 pur            : RWNvd2Fz...==
        ↓  Étape 4 : Décoder Base64
FLAG                  : EcowasCTF{l4y3r_by_l4y3r_sw33t}
```

Chaque couche est un "Layer" du "Cake" — d'où le titre !

---

## Script complet

```python
import base64

# Étape 0 : le texte de la description du challenge
desc = "==AZzQ2MxUjN2AzMlRTY3QGNzMTZ0MzM4UTO3UGN0UTN2AzM3cjMzgTN1MTY0" \
       "IzM4UTO3UGN0UTN2AzM3cjMzUjN3QjM1EzMxUTY3YDNyMDN2YzNlRzN1ITN"

print(f"Chaîne originale : {desc[:40]}...")

# Étape 1 : Inverser
reversed_str = desc[::-1]
print(f"Inversée         : {reversed_str[:40]}...")

# Étape 2 : Décoder Base64
step1 = base64.b64decode(reversed_str).decode()
print(f"Après Base64     : {step1[:40]}...")

# Étape 3 : Décoder Hex
step2 = bytes.fromhex(step1).decode()
print(f"Après Hex        : {step2[:40]}...")

# Étape 4 : Décoder Base64 final
flag = base64.b64decode(step2).decode()
print(f"\nFLAG : {flag}")
```

**Sortie :**
```
Chaîne originale : ==AZzQ2MxUjN2AzMlRTY3QGNzMTZ0MzM4UTO3UGN0U...
Inversée         : NTI1NzRlNzY2NDMyNDY3YTUxMzE1MjQ3NjUzMjc3Mz...
Après Base64     : 52574e766432467a513152476532773065544e795832...
Après Hex        : RWNvd2FzQ1RGe2w0eTNyX2J5X2w0eTNyX3N3MzN0fQ==
FLAG : EcowasCTF{l4y3r_by_l4y3r_sw33t}
```

---

## Comment reconnaître les encodages en CTF

| Indice visuel | Encodage probable |
|---------------|-------------------|
| `==` au début (inversé) | Base64 inversé |
| Commence par `==` ou `=` en fin | Base64 normal |
| Uniquement `0-9`, `a-f`, longueur paire | Hexadécimal |
| Que des lettres majuscules, parfois `2` et `7` | Base32 |
| `%XX` dans l'URL | URL encoding |
| `&#xxx;` dans HTML | HTML entities |

### L'approche CTF universelle pour les encodages

1. **Identifier** : regarder les caractères utilisés
2. **Décoder une couche** : Base64, Hex, ROT13...
3. **Répéter** jusqu'à obtenir quelque chose de lisible
4. **Vérifier** : est-ce que ça commence par `EcowasCTF{` ?

---

## Flag

```
EcowasCTF{l4y3r_by_l4y3r_sw33t}
```

---

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
