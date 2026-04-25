# Guide — Créer un post CTF pour le blog

## Vue d'ensemble

Chaque writeup = un fichier `.md` dans `blog/_posts/`, nommé `YYYY-MM-DD-slug.md`.  
Ce guide couvre tout : structure, règles de contenu, pièges à éviter, et workflow de publication.

---

## 1. Nom du fichier

```
YYYY-MM-DD-<slug>.md
```

**Exemples :**
```
2026-04-24-ecowas-ctf-2026-legendre-symbol.md
2026-04-24-ecowas-ctf-2026-abnormal-chain.md
```

**Règles pour le slug :**
- Minuscules, tirets uniquement (pas d'espaces ni caractères spéciaux)
- Format : `<ctf-name>-<challenge-name>`
- Les accents et symboles → translittérés (`écowasCTF → ecowas-ctf`)

---

## 2. Frontmatter YAML

```yaml
---
layout: post
title: "ECOWAS CTF 2026 — Nom Challenge [Catégorie/Difficulté]"
date: 2026-04-24 10:00:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [crypto, rsa, lattice, coppersmith]
toc: true
---
```

**Champs obligatoires :** `layout`, `title`, `date`, `categories`, `tags`, `toc`

**Format du titre :** `"CTF Name — Challenge Name [Catégorie/Difficulté]"`  
**Format de la date :** ISO 8601 avec offset UTC `+0000`

**Tags recommandés par catégorie :**
| Catégorie | Tags typiques |
|-----------|---------------|
| Crypto | `crypto`, `rsa`, `ecc`, `aes`, `hash`, `legendre`, `lattice`, `lll`, `coppersmith` |
| Web | `web`, `xss`, `sqli`, `idor`, `ssrf`, `jwt`, `csrf` |
| Reverse | `reverse`, `elf`, `mach-o`, `arm64`, `x86-64`, `ghidra`, `gdb` |
| Forensics | `forensics`, `pcap`, `steganography`, `memory`, `disk` |
| Misc | `misc`, `encoding`, `base64`, `osint` |
| Pwn | `pwn`, `buffer-overflow`, `rop`, `heap`, `format-string` |

---

## 3. Structure complète d'un post

```markdown
---
[frontmatter YAML]
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Crypto · **Difficulté :** ⭐⭐ (Medium) · **Points :** 200  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement
> peuvent expirer après la fin de la compétition.

| Fichier | Télécharger |
|---------|-------------|
| `fichier.zip` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/XX_slug.zip) |

---

## Description du challenge

> *"Challenge description in English as given by the platform."*

**Fichiers fournis :** `challenge.zip` → `binary`, `output.txt`

---

## [Corps du writeup — voir section 4]

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
```

---

## 4. Corps du writeup — Règles de contenu

### ✅ Ce qu'on inclut

- **Analyse** : ce qu'on a observé en premier (magic bytes, format, charset, comportement)
- **Raisonnement** : pourquoi on a choisi telle approche, quels indices ont guidé
- **Code** : scripts complets, blocs de débogage, commandes
- **Résultat** : output attendu, flag

### ❌ Ce qu'on n'inclut PAS

- Explications de concepts basiques (Base64, hex, XOR, ROT13, strings command, JSON...)
  → Ce sont des pré-requis CTF implicites
- Sections "Qu'est-ce que X ?" pour X = outil/encodage courant
- Métadonnées des sources (ne pas inclure le frontmatter YAML des fichiers source)

### 🔗 Règle pour les concepts intermédiaires

Concepts intermédiaires (Vigenère, Rail Fence, steganographie...) :  
→ Une ligne d'explication + un lien Wikipedia, **pas** une section entière.

```markdown
Le **[chiffre de Vigenère](https://fr.wikipedia.org/wiki/Chiffre_de_Vigen%C3%A8re)**
applique un décalage différent à chaque lettre selon une clé répétée.
```

### ✅ Ce qu'on GARDE et développe

Concepts vraiment avancés (les lecteurs ne les connaissent pas forcément) :
- ECC / courbes elliptiques
- LLL / réduction de réseau
- Coppersmith / small_roots
- LFSR / registres à décalage
- HNP (Hidden Number Problem)
- Groupes de Galois, isogénies, etc.

---

## 5. Blocs de code — Règles

**TOUJOURS spécifier le langage :**

```
 ```python   ← Python
 ```bash     ← Shell/commandes terminal
 ```sage     ← SageMath
 ```json     ← JSON
 ```text     ← Output, flags, données brutes
 ```hex      ← Données hexadécimales
```

**Mauvais (texte rendu sans coloration) :**
````
```
import base64
flag = base64.b64decode(ct)
```
````

**Bon :**
````
```python
import base64
flag = base64.b64decode(ct)
```
````

---

## 6. Pièges Jekyll à éviter

### ⚠️ Liquid templates — `{{` et `{%`

Jekyll interprète `{{variable}}` et `{% tag %}` comme du Liquid.  
Dans les f-strings Python, `f"EcowasCTF{{{flag}}}"` contient `{{` → **casse le rendu**.

**Fix :** Entourer le bloc avec `{% raw %}` / `{% endraw %}` :

```
{% raw %}
```python
flag = f"EcowasCTF{{{result}}}"
```
{% endraw %}
```

Ou échapper : remplacer `{{` par `{{ "{{" }}` (lourd) — préférer `{% raw %}`.

### ⚠️ BOM UTF-8

Certains fichiers ont un BOM (`\ufeff`) en tête qui casse le parsing YAML.  
→ Toujours sauvegarder en **UTF-8 sans BOM** (`utf-8`, pas `utf-8-sig`).

### ⚠️ Frontmatter des sources

Si le fichier source `.md` commence par `---\n...\n---\n`, c'est son propre frontmatter.  
**Ne JAMAIS copier ce bloc dans le post blog** — il s'afficherait en texte brut.

---

## 7. Images

Chemin correct (Chirpy ajoute le baseurl automatiquement) :
```markdown
![Description](/assets/img/ecowas-2026/35_adinkra_screenshot.png)
```

Chemin **incorrect** (double baseurl) :
```markdown
![Description](/portfolio/blog/assets/img/...)  ← NE PAS FAIRE
```

Dossier des assets : `blog/assets/img/ecowas-2026/`  
Nommage : `<num_challenge>_<slug>_<description>.png`

---

## 8. Difficulté et étoiles

| Difficulté | Notation | Points typiques |
|------------|----------|-----------------|
| Easy | ⭐ (Easy) | 50–100 |
| Medium | ⭐⭐ (Medium) | 100–300 |
| Hard | ⭐⭐⭐ (Hard) | 300–500 |

---

## 9. Descriptions de challenges

**Les descriptions originales des challenges sont en anglais — les citer telles quelles :**

```markdown
## Description du challenge

> *"The Nile leaks only a little each season, but a little is enough."*
```

Ne pas traduire la description originale. Le reste du post est en français.

---

## 10. Workflow complet de publication

### Étape 1 — Préparer le fichier source

1. Écrire le writeup dans `D:\CTF_2025\ECOWAS_CTF_2026\writeups\writeup_NN_slug.md`
2. Structure recommandée du fichier source :
   ```
   # Titre
   
   ## Description du challenge
   ## Analyse
   ## Solution
   ## Script complet
   ## Flag
   ```
3. **Ne pas** ajouter de frontmatter YAML au fichier source

### Étape 2 — Créer le post blog

```powershell
# Copier le template
$slug = "ecowas-ctf-2026-mon-challenge"
$date = "2026-04-24"
$post = "D:\New folder\portfolio\blog\_posts\$date-$slug.md"
```

Structure minimale à créer :

```markdown
---
layout: post
title: "ECOWAS CTF 2026 — Mon Challenge [Catégorie/Difficulté]"
date: 2026-04-24 10:00:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [tag1, tag2]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Misc · **Difficulté :** ⭐ (Easy) · **Points :** 100  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

| Fichier | Télécharger |
|---------|-------------|
| `challenge.zip` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/NN_slug.zip) |

---

## Description du challenge

> *"Original English description."*

---

## Analyse

[corps du writeup]

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
```

### Étape 3 — Mettre à jour l'index

Fichier : `blog/_posts/2026-04-24-ecowas-ctf-2026.md`

Ajouter une ligne dans le tableau de la catégorie correspondante :
```markdown
| Mon Challenge | [Misc/Easy] | ⭐ | [Writeup](/portfolio/blog/posts/ecowas-ctf-2026-mon-challenge/) |
```

### Étape 4 — Vérifications avant commit

```python
# Checklist rapide
import re
content = open('mon-post.md', 'r', encoding='utf-8').read()

# 1. Frontmatter présent ?
assert content.startswith('---\n'), "Frontmatter manquant"

# 2. Pas de Liquid {{ dans du code Python non protégé ?
liquid = re.findall(r'\{\{|\{%', content)
if liquid:
    print(f"ATTENTION: {len(liquid)} occurrence(s) de {{ ou {%")

# 3. Blocs code bien fermés (nombre pair de ```) ?
backticks = len(re.findall(r'```', content))
assert backticks % 2 == 0, f"Blocs code non fermés! ({backticks} backticks)"

# 4. Tous les blocs code ont un langage ?
no_lang = re.findall(r'```\n', content)
if no_lang:
    print(f"ATTENTION: {len(no_lang)} blocs code sans langage spécifié")

print("OK — post prêt à publier")
```

### Étape 5 — Git

```powershell
cd "D:\New folder\portfolio"
git add blog/_posts/2026-04-24-ecowas-ctf-2026-mon-challenge.md
git add blog/_posts/2026-04-24-ecowas-ctf-2026.md  # si index mis à jour
git commit -m "Add writeup: Mon Challenge [Catégorie/Difficulté]"
git push origin main
```

GitHub Actions déploie automatiquement → live en ~2 minutes sur GitHub Pages.

---

## 11. Script de fusion automatique (pour sources déjà écrites)

Pour les writeups déjà dans `D:\CTF_2025\ECOWAS_CTF_2026\writeups\`, utiliser `merge_writeups.py` :

```python
# merge_writeups.py — D:\CTF_2025\merge_writeups.py
# Usage: python merge_writeups.py
# Fusionne les fichiers source détaillés avec les posts blog existants
```

**Règles du script :**
- Lit le frontmatter + header blockquote + Fichiers section depuis le post blog
- Lit le corps depuis le fichier source (en sautant son frontmatter YAML s'il en a un)
- Reconstruit le post complet
- Ne touche pas aux posts sans source dans le MAPPING

---

## 12. Checklist rapide

```
[ ] Nom du fichier : YYYY-MM-DD-ecowas-ctf-2026-slug.md
[ ] Frontmatter YAML complet (layout, title, date, categories, tags, toc)
[ ] En-tête blockquote avec CTF/Catégorie/Difficulté/Points + lien retour
[ ] Description du challenge en ANGLAIS (citation originale)
[ ] Blocs code avec spécificateur de langage (python/bash/sage/text/json)
[ ] Pas de Liquid {{ dans le code (ou protégé avec {% raw %})
[ ] Pas de sections "Qu'est-ce que" pour des concepts basiques
[ ] Lien retour en bas de page
[ ] Index mis à jour (blog/_posts/2026-04-24-ecowas-ctf-2026.md)
[ ] git add + git commit + git push
```
