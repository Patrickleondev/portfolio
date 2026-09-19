const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const isEnglish = document.documentElement.lang === 'en';

// Fond Matrix : décoratif, masqué aux lecteurs d'écran, en pause quand l'onglet est caché
// et figé si le visiteur a demandé moins d'animations.
const matrixBg = document.getElementById('matrix-bg');
if (matrixBg) {
    matrixBg.setAttribute('aria-hidden', 'true');
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    matrixBg.appendChild(canvas);

    const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@#$%^&*()";
    const fontSize = 16;
    let drops = [];

    function resize() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        drops = Array(Math.ceil(canvas.width / fontSize)).fill(1);
    }

    function draw() {
        ctx.fillStyle = "rgba(13, 2, 8, 0.05)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = "#00ff41";
        ctx.font = fontSize + "px monospace";

        for (let i = 0; i < drops.length; i++) {
            const text = letters[Math.floor(Math.random() * letters.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }

    resize();
    window.addEventListener('resize', resize);

    if (reduceMotion) {
        for (let i = 0; i < 60; i++) draw();
    } else {
        let timer = setInterval(draw, 33);
        document.addEventListener('visibilitychange', () => {
            clearInterval(timer);
            if (!document.hidden) timer = setInterval(draw, 33);
        });
    }
}

// Effet machine à écrire.
// - Le haut de page s'écrit élément par élément, dans l'ordre.
// - Les titres de section plus bas s'écrivent quand ils arrivent à l'écran.
// - La place est réservée avant d'effacer : la page ne saute pas.
// - Les lecteurs d'écran lisent le texte complet (copie masquée visuellement),
//   et rien ne s'anime si le visiteur a demandé moins d'animations.
// Chaque groupe s'écrit d'un coup ; les groupes s'enchaînent l'un après l'autre.
const introGroups = [
    ['.glitch'],
    ['.hero-school', '.role', '.bio-short'],
    ['#about-title'],
    ['.about-text p'],
    ['#expertise-title']
];

function prepareTyping(element) {
    if (element.dataset.typed) return null;
    element.dataset.typed = '1';
    element.style.visibility = '';
    element.style.minHeight = element.offsetHeight + 'px';

    const full = element.textContent.replace(/\s+/g, ' ').trim();
    const visual = document.createElement('span');
    visual.setAttribute('aria-hidden', 'true');
    while (element.firstChild) visual.appendChild(element.firstChild);
    const readable = document.createElement('span');
    readable.className = 'sr-only';
    readable.textContent = full;
    element.append(readable, visual);

    // On garde les balises internes (ex. le « // » en vert) et on vide seulement le texte.
    const walker = document.createTreeWalker(visual, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) {
        const node = walker.currentNode;
        const text = node.textContent.replace(/\s+/g, ' ');
        if (text.trim() === '' && nodes.length === 0) { node.textContent = ''; continue; }
        nodes.push({ node, text });
        node.textContent = '';
    }
    return { element, nodes };
}

function typeInto(job, speed) {
    return new Promise(resolve => {
        const cursor = document.createElement('span');
        cursor.className = 'type-cursor';
        cursor.setAttribute('aria-hidden', 'true');
        let n = 0, i = 0;

        const step = () => {
            if (n >= job.nodes.length) {
                cursor.remove();
                job.element.style.minHeight = '';
                return resolve();
            }
            const { node, text } = job.nodes[n];
            if (i === 0) node.parentNode.insertBefore(cursor, node.nextSibling);
            node.textContent = text.slice(0, i + 1);
            i++;
            if (i >= text.length) { n++; i = 0; }
            setTimeout(step, speed);
        };
        step();
    });
}

const speedFor = el => (el.textContent.length > 60 ? 12 : 40);

if (!reduceMotion) {
    const groups = introGroups
        .map(selectors => selectors
            .flatMap(selector => [...document.querySelectorAll(selector)])
            .map(prepareTyping)
            .filter(Boolean))
        .filter(jobs => jobs.length);

    (async () => {
        for (const jobs of groups) {
            await Promise.all(jobs.map(job => typeInto(job, speedFor(job.element))));
            await new Promise(r => setTimeout(r, 120));
        }
    })();

    const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (!entry.isIntersecting) return;
            observer.unobserve(entry.target);
            const job = prepareTyping(entry.target);
            if (job) typeInto(job, 35);
        });
    }, { threshold: 0.6 });

    document.querySelectorAll('.section-title, .subsection-title, .cert-block > h3').forEach(el => {
        if (el.dataset.typed) return;
        el.style.visibility = 'hidden';
        observer.observe(el);
    });
}

// Menu mobile repliable. Sans JavaScript, le menu reste simplement déplié.
const nav = document.querySelector('.glass-nav');
if (nav) {
    const list = nav.querySelector('ul');
    list.id = 'site-menu';
    nav.querySelectorAll('a.active').forEach(a => a.setAttribute('aria-current', 'page'));

    const toggle = document.createElement('button');
    toggle.className = 'menu-toggle';
    toggle.type = 'button';
    toggle.setAttribute('aria-controls', 'site-menu');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.innerHTML = '<i class="fas fa-bars" aria-hidden="true"></i><span class="sr-only">' +
        (isEnglish ? 'Menu' : 'Menu') + '</span>';
    nav.insertBefore(toggle, list);
    document.documentElement.classList.add('js');

    toggle.addEventListener('click', () => {
        const open = nav.classList.toggle('open');
        toggle.setAttribute('aria-expanded', String(open));
    });
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && nav.classList.contains('open')) {
            nav.classList.remove('open');
            toggle.setAttribute('aria-expanded', 'false');
            toggle.focus();
        }
    });
}

// Visionneuse de certificats : ouvrable à la souris et au clavier, fermée par Échap,
// le focus revient sur l'image d'origine.
const certImages = document.querySelectorAll('.clickable-cert img');
certImages.forEach(img => {
    img.tabIndex = 0;
    img.setAttribute('role', 'button');
    img.setAttribute('aria-label', (isEnglish ? 'Enlarge: ' : 'Agrandir : ') + img.alt);

    const open = () => {
        const modal = document.createElement('div');
        modal.className = 'lightbox';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-label', img.alt);

        const closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'lightbox-close';
        closeBtn.innerHTML = '<i class="fas fa-xmark" aria-hidden="true"></i><span class="sr-only">' +
            (isEnglish ? 'Close' : 'Fermer') + '</span>';

        const zoomed = document.createElement('img');
        zoomed.src = img.src;
        zoomed.alt = img.alt;

        modal.append(closeBtn, zoomed);
        document.body.appendChild(modal);
        document.body.style.overflow = 'hidden';
        closeBtn.focus();

        const close = () => {
            modal.remove();
            document.body.style.overflow = '';
            document.removeEventListener('keydown', onKey);
            img.focus();
        };
        const onKey = e => {
            if (e.key === 'Escape') close();
            if (e.key === 'Tab') { e.preventDefault(); closeBtn.focus(); }
        };
        modal.addEventListener('click', e => { if (e.target !== zoomed) close(); });
        document.addEventListener('keydown', onKey);
    };

    img.addEventListener('click', open);
    img.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); }
    });
});
