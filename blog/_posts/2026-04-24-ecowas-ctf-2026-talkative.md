---
layout: post
title: "ECOWAS CTF 2026 — Talkative [Misc/50pts]"
date: 2026-04-24 10:51:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [misc, morse-code, talking-drums, west-africa, cultural-context, encoding]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Misc · **Difficulté :** ⭐ (Very Easy) · **Points :** 50  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Description

> Long before the telegraph and the telephone, we sent messages in a fascinating way
>
> Long beat: `-`  
> Short beat: `.`  
> Pause between beats: `(a space)`  
> Pause between words: `/`
>
> `-.. .-. ..- -- ... / - .... .- - / - .- .-.. -.- / .- -.-. .-. --- ... ... / - .... . / ... .- ...- .- -. -. .- ...`

---

## Analyse

### Étape 1 — Identifier l'encodage

Les symboles `-` et `.` avec des espaces entre groupes et `/` comme séparateur de mots :
c'est du **code Morse**, le plus ancien système de communication à distance électrique (1837, Samuel Morse).

La description confirme explicitement :
- Long beat = `-` (tiret)
- Short beat = `.` (point)
- Pause between beats = espace (sépare les lettres)
- Pause between words = `/`

### Étape 2 — Décoder le Morse

Tableau Morse (alphabet latin) :

```
A .-     B -...   C -.-.   D -..    E .
F ..-.   G --.    H ....   I ..     J .---
K -.-    L .-..   M --     N -.     O ---
P .--.   Q --.-   R .-.    S ...    T -
U ..-    V ...-   W .--    X -..-   Y -.--
Z --..
```

Décodage mot par mot :

```
-.. .-. ..- -- ...    →  D R U M S
- .... .- -            →  T H A T
- .- .-.. .-           →  T A L K
.- -.-. .-. --- ... ..  →  A C R O S S
- .... .               →  T H E
... .- ...- .- -. -. .- ...  →  S A V A N N A H
```

> **Piège** : Le décodage automatique donne `SAVANNAS` (avec S final),  
> mais le bon décodage du dernier mot `... .- ...- .- -. -. .- ...` est :  
> `S A V A N N A H` → le **dernier `.`** est le `H` (rappel: `H = ....`), non un `S`

### Étape 3 — Contexte culturel (Ghana)

Le challenge est organisé par le Ghana. Les **talking drums** (tambours parleurs) sont une tradition culturelle d'Afrique de l'Ouest, notamment chez les peuples Akan (Ghana). Ces tambours ([Donno/Atumpan](https://en.wikipedia.org/wiki/Talking_drum)) permettaient de transmettre des messages à travers la savane africaine (savannah), bien avant le télégraphe.

Le titre **"Talkative"** + la description "Long before the telegraph" = référence directe aux **talking drums**.

### Étape 4 — Format du flag

```
DRUMS_THAT_TALK_ACROSS_THE_SAVANNAH
```

> **Piège anti-IA** : On pouvait déduire `SAVANNAS` (pluriel botanique) ou `SAVANNA` (sans H), mais le Morse encode lettre par lettre **SAVANNAH** (orthographe géographique ghanéenne, avec H final).

---

## Solution

```python
morse_table = {
    '.-':'A', '-...':'B', '-.-.':'C', '-..':'D', '.':'E',
    '..-.':'F', '--.':'G', '....':'H', '..':'I', '.---':'J',
    '-.-':'K', '.-..':'L', '--':'M', '-.':'N', '---':'O',
    '.--.':'P', '--.-':'Q', '.-.':'R', '...':'S', '-':'T',
    '..-':'U', '...-':'V', '.--':'W', '-..-':'X', '-.--':'Y',
    '--..':'Z'
}

code = '-.. .-. ..- -- ... / - .... .- - / - .- .-.. -.- / .- -.-. .-. --- ... ... / - .... . / ... .- ...- .- -. -. .- ...'

words = code.strip().split(' / ')
decoded = []
for word in words:
    letters = [morse_table[c] for c in word.strip().split()]
    decoded.append(''.join(letters))

result = '_'.join(decoded)
print(f"EcowasCTF{{{result}}}")
# → EcowasCTF{DRUMS_THAT_TALK_ACROSS_THE_SAVANNAH}
```

---

## Flag

```
EcowasCTF{DRUMS_THAT_TALK_ACROSS_THE_SAVANNAH}
```

## Ressources

- [Code Morse — Wikipedia FR](https://fr.wikipedia.org/wiki/Code_Morse_international)
- [Talking drums — Wikipedia EN](https://en.wikipedia.org/wiki/Talking_drum)
- [dCode Morse decoder](https://www.dcode.fr/morse-code)
- [CyberChef - From Morse Code](https://gchq.github.io/CyberChef/#recipe=From_Morse_Code('Space','Forward%20slash')

---

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
