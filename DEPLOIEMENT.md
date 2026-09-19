# Comment mettre une modification en ligne

Le site est publié sur <https://patrickleondev.github.io/portfolio/>.

## Situation actuelle : le déploiement automatique ne marche pas

Normalement, un `git push` sur `main` déclenche le workflow `.github/workflows/deploy.yml`,
qui construit le site et le publie. Depuis le 19 septembre 2026, GitHub refuse de lancer ce
workflow : **« The job was not started because your account is locked due to a billing issue »**.

Tant que ce blocage dure, il faut publier à la main. Pour revenir au fonctionnement normal :
régler la facturation sur <https://github.com/settings/billing>, puis relancer le dernier
workflow depuis l'onglet **Actions** du dépôt.

## Le flux, étape par étape

Exemple : tu corriges un intitulé de certificat dans `expertise.html`.

### 1. Modifier le fichier source

Les pages sont à la racine du dépôt : `index.html`, `about.html`, `expertise.html`,
`projects.html`, `contact.html`, plus leurs versions anglaises en `-en.html`.
Le style est dans `style.css`, le JavaScript dans `main.js`.

**Attention :** chaque page existe en deux langues. Une correction de texte doit être faite
dans les deux fichiers (`expertise.html` **et** `expertise-en.html`), sinon les deux versions
du site se contredisent.

### 2. Vérifier en local avant de publier

```bash
cd D:/All/portfolio
npm run dev          # ouvre http://localhost:5173/portfolio/
```

Regarde la page modifiée dans le navigateur. Ctrl+C pour arrêter.

### 3. Construire le site

```bash
npm run build        # génère le dossier dist/
```

Vite copie les pages, compresse le CSS et le JS, et renomme les images avec une empreinte.

**Règle à retenir :** un fichier qui n'est lié que par un `<a href="...">` (un PDF, par exemple)
n'est **pas** copié par Vite depuis `assets/`. Il doit être placé dans `public/assets/docs/`.
Les images affichées avec `<img src="...">` sont copiées normalement.

### 4. Enregistrer la modification dans Git

```bash
git add expertise.html expertise-en.html
git commit -m "fix: intitule correct du certificat TryHackMe"
git push origin main
```

Le dépôt `main` garde l'historique du code source. À ce stade, **le site en ligne n'a pas
encore changé**.

### 5. Publier (tant que GitHub Actions est bloqué)

Le site est servi depuis la branche `gh-pages`. On y copie le contenu de `dist/`, en gardant
le dossier `blog/`, qui est construit par Jekyll et ne se régénère pas en local.

```bash
# une seule fois : récupérer la branche gh-pages dans un dossier à part
git clone --single-branch --branch gh-pages https://github.com/Patrickleondev/portfolio.git ../portfolio-ghpages

cd ../portfolio-ghpages
git pull origin gh-pages
# tout effacer sauf .git, blog et .nojekyll
find . -maxdepth 1 -mindepth 1 ! -name .git ! -name blog ! -name .nojekyll -exec rm -rf {} +
cp -R ../portfolio/dist/. .
git add -A
git status --short | grep blog/     # doit ne rien afficher : le blog ne doit pas bouger
git commit -m "Deploiement manuel"
git push origin gh-pages
```

### 6. Vérifier que c'est bien en ligne

Le push sur `gh-pages` déclenche la publication « pages build and deployment », qui, elle,
fonctionne malgré le blocage. Elle prend une à deux minutes.

```bash
curl -s https://patrickleondev.github.io/portfolio/expertise.html | grep "TryHackMe - "
```

Dans le navigateur, **Ctrl + F5** pour recharger sans le cache.
Pour un changement de favicon, Ctrl + F5 ne suffit pas : les navigateurs gardent les icônes
dans une base à part. Il faut ouvrir le site en navigation privée, ou changer le `?v=` des
liens d'icône dans les pages.

## Résumé

| Étape | Effet |
|---|---|
| `npm run dev` | tu vois la modification chez toi |
| `npm run build` | le dossier `dist/` contient le site prêt à publier |
| `git push origin main` | le code source est sauvegardé sur GitHub |
| push sur `gh-pages` | **le site public change** |
