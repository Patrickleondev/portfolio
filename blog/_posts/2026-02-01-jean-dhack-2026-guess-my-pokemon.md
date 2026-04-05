---
layout: post
title: "Jean D'Hack 2026 — Guess My Pokémon [Crypto]"
date: 2026-02-01 13:00:00 +0100
categories: [CTF, Jean-DHack-2026]
tags: [crypto, php, uniqid, aes, prng, timing-attack, hard]
toc: true
---

> **CTF :** Jean D'Hack 2026 · **Catégorie :** Crypto · **Difficulté :** ⭐⭐⭐ Hard  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/jean-dhack-ctf/)**

---

## Description du challenge

Un service PHP choisit un Pokémon aléatoire et chiffre son nom avec AES.  
On reçoit l'indice chiffré (`encrypted_hint`) et on doit retrouver le Pokémon mystère.  
Un mécanisme **Proof-of-Work (PoW)** protège contre le brute-force direct sur le serveur.

---

## Analyse du code source PHP

Le fichier `api.php` révèle comment la clé AES est générée :

```php
// Génération de la clé AES
$_SESSION['aes_key'] = hash('sha256', uniqid(), true);

// Enregistrement du temps de départ
$_SESSION['game_start_time'] = (int)time();
```

### Le problème avec `uniqid()`

La fonction PHP `uniqid()` génère un identifiant basé sur le **temps système courant**.  
Son format hex sur 13 caractères se décompose :

```
[ 8 hex chars  ][ 5 hex chars ]
  ↑ secondes         ↑ microsecondes
```

Or, l'API expose `game_start_time` via l'endpoint `/api/uptime` → on connaît les **8 premiers caractères**.  
Il reste seulement **5 caractères hexadécimaux à brute-forcer** = $16^5 = 1\,048\,576$ possibilités.  
C'est faisable **localement en quelques secondes**.

---

## Stratégie d'exploitation

```
1. Appel API → récupérer encrypted_hint + game_start_time
2. Brute-force local des 5 chars de microsecondes
3. Pour chaque candidat → reconstruire uniqid → SHA256 → clé AES → déchiffrer
4. Si le résultat déchiffré ressemble à un nom de Pokémon → c'est la bonne clé
5. Récupérer le challenge PoW
6. Résoudre le PoW (hash SHA256 avec préfixe de 5 zéros)
7. Soumettre le nom + PoW → obtenir le flag
```

---

## Script de résolution

```python
import requests
import hashlib
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

BASE_URL = "http://<target>"

def solve():
    # Étape 1 : récupérer l'indice chiffré et le timestamp
    r = requests.get(f"{BASE_URL}/api/hint").json()
    encrypted_hex = r["encrypted_hint"]
    timestamp     = int(r["game_start_time"])

    encrypted = bytes.fromhex(encrypted_hex)

    # Étape 2 : brute-force local sur les microsecondes
    ts_hex = format(timestamp, "08x")
    found_pokemon = None

    for micro in range(0x00000, 0xFFFFF + 1):
        micro_hex = format(micro, "05x")
        candidate_uid = ts_hex + micro_hex           # format uniqid
        key = hashlib.sha256(candidate_uid.encode()).digest()

        try:
            cipher    = AES.new(key, AES.MODE_CBC, iv=encrypted[:16])
            plaintext = unpad(cipher.decrypt(encrypted[16:]), 16).decode()
            # Un nom de Pokémon commence par une majuscule
            if plaintext[0].isupper() and plaintext.isalpha():
                found_pokemon = plaintext
                print(f"[+] Pokémon trouvé : {found_pokemon}")
                break
        except Exception:
            continue

    if not found_pokemon:
        print("[-] Échec du brute-force")
        return

    # Étape 3 : résoudre le PoW
    pow_r    = requests.get(f"{BASE_URL}/api/pow").json()
    prefix   = pow_r["prefix"]
    nonce    = 0
    while True:
        candidate = f"{prefix}{nonce}"
        h = hashlib.sha256(candidate.encode()).hexdigest()
        if h.startswith("00000"):
            break
        nonce += 1
    print(f"[+] PoW résolu — nonce : {nonce}")

    # Étape 4 : soumettre la réponse
    payload = {"pokemon": found_pokemon, "nonce": nonce, "prefix": prefix}
    result  = requests.post(f"{BASE_URL}/api/guess", json=payload).json()
    print(f"[+] Réponse serveur : {result}")

solve()
```

### Résultat de l'exécution

```
[+] Pokémon trouvé : Moltres
[+] PoW résolu — nonce : 847293
[+] Réponse serveur : {"flag": "JDHACK{un1q1d_b4d}3cR3t5_Ar3_r3411y_b4d}"}
```

---

## Flag

```
JDHACK{un1q1d_b4d}3cR3t5_Ar3_r3411y_b4d}
```

---

## Ce que j'ai retenu

- **`uniqid()` n'est pas un générateur cryptographique.** Il est prévisible à partir du timestamp — jamais l'utiliser pour dériver des secrets (tokens, clés, seeds).
- La règle : pour tout usage sécurité, utiliser `random_bytes(32)` ou `openssl_random_pseudo_bytes(32)` en PHP.
- Le **PoW** était une protection anti-brute-force côté serveur — mais le fait d'exposer `game_start_time` rendait un brute-force **local** trivial, contournant complètement le PoW.
- Leçon d'architecture : ne jamais exposer des informations qui réduisent significativement l'espace de recherche d'un secret.
