---
layout: post
title: "ECOWAS CTF 2026 — Runic2 [Crypto/Brainfuck]"
date: 2026-04-24 09:50:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [crypto, brainfuck, esoteric-language, dcode, cipher-identification]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Cryptographie · **Difficulté :** ⭐ (Easy) · **Points :** 100  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

> **Writeup par : 0xWhoAm1** — Équipe **DarkPulse**

---

## Description du challenge

![Challenge Runic2](/assets/img/ecowas-2026/lion/runic2-challenge.png)

Le challenge fournit un fichier contenant une chaîne de caractères composée exclusivement de `+`, `-`, `<`, `>`, `.`, `,`, `[` et `]`.

---

## Contenu du fichier

```text
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>++.++++++.-----------.++++++.++++++++++++++++++++.<-----------------.>----------------------.<----.+++++++.----.>-.<.---...>---.<++++.>+++++.<----.>-----.<++++++.-------.>+++.<+++.--..+.>.<++++++.>---.<--------.++++++.---.++.>+.<-.+.>+++++++++++++++++++++++++++.
```

---

## Étape 1 — Identification du « chiffrement »

À première vue, ce n'est pas un chiffrement classique (AES, Base64, ROT…). L'ensemble de symboles `+`, `-`, `<`, `>`, `.`, `,`, `[`, `]` est **caractéristique du langage Brainfuck**.

On peut le confirmer via [dcode.fr — Cipher Identifier](https://www.dcode.fr/cipher-identifier) en soumettant la chaîne.

> **Brainfuck** est un langage de programmation ésotérique créé en 1993 par Urban Müller. Il ne contient que 8 instructions, toutes représentées par des caractères ASCII simples. Voir [Wikipedia — Brainfuck](https://fr.wikipedia.org/wiki/Brainfuck).
>
> | Commande | Effet |
> |----------|-------|
> | `>` | Avancer le pointeur mémoire |
> | `<` | Reculer le pointeur mémoire |
> | `+` | Incrémenter la cellule courante |
> | `-` | Décrémenter la cellule courante |
> | `.` | Afficher le caractère ASCII de la cellule courante |
> | `,` | Lire un caractère en entrée |
> | `[` | Si la cellule est 0, sauter à `]` correspondant |
> | `]` | Si la cellule n'est pas 0, revenir à `[` correspondant |

---

## Étape 2 — Décodage

On utilise l'interpréteur Brainfuck de [dcode.fr](https://www.dcode.fr/brainfuck-language) :

1. Coller le code Brainfuck dans l'interpréteur
2. Cliquer sur **Execute** (aucun paramètre à configurer)
3. La sortie s'affiche directement

L'exécution du programme produit le flag en clair.

---

## Flag

```
flag{5e184d4111a5f1a70d3112d8a0635b45}
```

---

## Pourquoi ce n'est pas vraiment de la cryptographie ?

Brainfuck n'est **pas un chiffrement** — c'est un langage de programmation. L'exécution du programme produit du texte en sortie, il n'y a pas de clé secrète. La "sécurité" repose uniquement sur l'obscurité du format.

En CTF, ce type de challenge teste la **reconnaissance de formats ésotériques** plutôt que des connaissances cryptographiques. Le vrai travail est dans l'identification rapide du format.

**Réflexe à acquérir :** quand une chaîne contient uniquement des caractères parmi `+-<>.,[]`, c'est du **Brainfuck**. Si elle contient `Ook.`, `Ook?`, `Ook!`, c'est du **Ook!** (variante de Brainfuck). Si c'est du `*!@#$`, c'est probablement du **Malbolge**.
