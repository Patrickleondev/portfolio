---
layout: post
title: "ECOWAS CTF 2026 — Baobab Whispers [Steg/ROT7+zsteg]"
date: 2026-04-24 09:30:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [steganography, zsteg, rot, lsb, image, cyberchef, dcode]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Stéganographie · **Difficulté :** ⭐⭐ (Medium) · **Points :** 150  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

> **Writeup par : 0xWhoAm1** — Équipe **DarkPulse**

---

## Description du challenge

> *"Le vieux baobab murmure à ceux qui le regardent pixel par pixel."*

Le hint nous oriente directement : **pixel par pixel** → stéganographie dans les pixels d'une image.

![Challenge Baobab Whispers](/assets/img/ecowas-2026/lion/baobab-challenge.png)

---

## Étape 1 — Extraction stéganographique avec zsteg

Le hint mentionne les pixels, ce qui oriente vers **zsteg** — un outil d'analyse stéganographique spécialisé dans les images PNG/BMP qui cherche des données cachées dans les bits de poids faible (LSB) des canaux de couleur.

```bash
zsteg baobab.png
```

![Résultat zsteg](/assets/img/ecowas-2026/lion/baobab-zsteg.png)

**Parmi les résultats**, une chaîne attire l'attention :

```
)LjvdhzJAM{i40i4i_do1zw3yz_zo1ma_if_z3c3u}>
```

Ce texte ressemble à un flag chiffré (la structure `{...}` est présente, les caractères sont décalés).

---

## Étape 2 — Identification du chiffrement

On soumet la chaîne à [dcode.fr — Cipher Identifier](https://www.dcode.fr/cipher-identifier) pour identifier automatiquement le chiffrement :

![dcode Cipher Identifier](/assets/img/ecowas-2026/lion/baobab-dcode.png)

L'outil suggère un **chiffrement ROT** (rotation alphabétique, variante de César).

---

## Étape 3 — Déchiffrement ROT avec CyberChef

On utilise la recette **ROT13 Brute Force** de [CyberChef](https://gchq.github.io/CyberChef/) pour tester tous les décalages de 1 à 25 :

![CyberChef ROT brute force — résultat](/assets/img/ecowas-2026/lion/baobab-cyberchef.png)

**ROT7** donne :

```
EcowasCTF{b40b4b_wh1sp3rs_sh1ft_by_s3v3n}
```

La rotation de 7 sur tous les caractères reconstitue le flag. Le chiffre **7** est le décalage utilisé, cohérent avec le thème ("shift by seven").

---

## Flag

```
EcowasCTF{b40b4b_wh1sp3rs_sh1ft_by_s3v3n}
```

---

## Résumé de la chaîne de résolution

```
Image PNG
  ↓ zsteg (LSB analysis)
Chaîne chiffrée: ")LjvdhzJAM{i40i4i_do1zw3yz_zo1ma_if_z3c3u}>"
  ↓ dcode Cipher Identifier → ROT
  ↓ CyberChef ROT Brute Force (décalage 7)
Flag: EcowasCTF{b40b4b_wh1sp3rs_sh1ft_by_s3v3n}
```

## Outils utilisés

| Outil | Rôle | Lien |
|-------|------|------|
| `zsteg` | Analyse LSB stéganographique dans les images PNG | [zsteg sur GitHub](https://github.com/zed-0xff/zsteg) |
| dcode Cipher Identifier | Identification automatique du type de chiffrement | [dcode.fr](https://www.dcode.fr/cipher-identifier) |
| CyberChef ROT Brute Force | Teste tous les décalages ROT 1-25 | [CyberChef](https://gchq.github.io/CyberChef/) |
