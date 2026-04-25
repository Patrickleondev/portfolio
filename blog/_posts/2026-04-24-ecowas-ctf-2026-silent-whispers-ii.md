---
layout: post
title: "ECOWAS CTF 2026 — Silent Whispers II [Steganography/200pts]"
date: 2026-04-24 10:12:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [steganography, stegsnow, base64, zip, zipcrpto, password-cracking, rockyou]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Steganography · **Difficulté :** ⭐⭐ (Medium) · **Points :** 200  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## 1. Énoncé du challenge
Le challenge nous présente un message intercepté qui semble normal à première vue. Cependant, l'indice suggère que quelque chose est "caché sous la surface" et qu'une simple extraction ne suffira pas.

**Fichier fourni :** `information_II.txt`

## 2. Analyse initiale
En ouvrant le fichier `information_II.txt`, on remarque la présence de nombreux espaces et tabulations à la fin des lignes de texte visibles. Ce comportement est typique de l'outil **stegsnow** (ou SNOW), qui dissimule des données dans les espaces blancs d'un fichier ASCII.

## 3. Étape 1 : Extraction Stegsnow
On tente une extraction avec `stegsnow` en utilisant le flag `-C` pour la compression :

```bash
stegsnow -C information_II.txt
```

**Résultat :** Au lieu d'un flag direct, l'outil nous renvoie un bloc de texte encodé en **Base64**.
> `UEsDBBQACQAIAIkGc1wipgyPIgAAABcAAAAIABwAZmxhZy50eHRVVAkAA8FIu2nBSLtpdXgLAAEE
6AMAAAToAwAAbys1ZQCkHajeMPRRt6JPLXcjBD7UvCtBkyOBMvdkdkVnt1BLBwgipgyPIgAAABcA
AABQSwECHgMUAAkACACJBnNcIqYMjyIAAAAXAAAACAAYAAAAAAABAAAAtIEAAAAAZmxhZy50eHRV
VAUAA8FIu2l1eAsAAQToAwAABOgDAABQSwUGAAAAAAEAAQBOAAAAdAAAAAAA`

## 4. Étape 2 : Décodage Base64
En observant le début de la chaîne décodée (`PK...`), on identifie la signature d'une archive **ZIP**. On décode donc la chaîne pour reconstruire le fichier :

```bash
echo "UEsDBBQACQAIAIkGc1wipgyPIgAAABcAAAAIABwAZmxhZy50eHRVVAkAA8FIu2nBSLtpdXgLAAEE
6AMAAAToAwAAbys1ZQCkHajeMPRRt6JPLXcjBD7UvCtBkyOBMvdkdkVnt1BLBwgipgyPIgAAABcA
AABQSwECHgMUAAkACACJBnNcIqYMjyIAAAAXAAAACAAYAAAAAAABAAAAtIEAAAAAZmxhZy50eHRV
VAUAA8FIu2l1eAsAAQToAwAABOgDAABQSwUGAAAAAAEAAQBOAAAAdAAAAAAA" | base64 -d > challenge.zip
```

## 5. Étape 3 : Cassage du mot de passe ZIP
Lors de la tentative d'extraction avec `unzip challenge.zip`, le système demande un mot de passe. Comme aucun mot de passe n'était présent dans les étapes précédentes, on utilise une attaque par dictionnaire avec **fcrackzip** et la liste `rockyou.txt` :

```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt challenge.zip
```

**Résultat :** `PASSWORD FOUND!!!!: pw == stealth123`

## 6. Étape 4 : Extraction finale et Flag
On utilise le mot de passe trouvé pour extraire le fichier `flag.txt` :

```bash
unzip challenge.zip
# Entrer le mot de passe : stealth123
cat flag.txt
```

**Contenu du fichier :**
`flag{l@y37s_0n_l@y3rs}`

**Flag :** `flag{l@y37s_0n_l@y3rs}`

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
