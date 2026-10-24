const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const isEnglish = document.documentElement.lang === 'en';
const isLight = () => document.documentElement.dataset.theme === 'light';

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
        ctx.fillStyle = isLight() ? "rgba(244, 247, 244, 0.08)" : "rgba(13, 2, 8, 0.05)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = isLight() ? "#0b8a3a" : "#00ff41";
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

// Thème clair / sombre. Le clair est celui par défaut ; le choix ne dure que le temps
// de la visite. Le <head> de chaque page l'applique avant l'affichage.
if (nav) {
    const item = document.createElement('li');
    item.className = 'theme-item';
    const themeBtn = document.createElement('button');
    themeBtn.type = 'button';
    themeBtn.className = 'theme-toggle';
    item.appendChild(themeBtn);
    nav.querySelector('.lang-switch').before(item);

    const render = () => {
        const light = isLight();
        const label = light
            ? (isEnglish ? 'Switch to dark mode' : 'Passer en fond sombre')
            : (isEnglish ? 'Switch to light mode' : 'Passer en fond clair');
        themeBtn.innerHTML = '<i class="fas ' + (light ? 'fa-moon' : 'fa-sun') + '" aria-hidden="true"></i>';
        themeBtn.setAttribute('aria-label', label);
        themeBtn.title = label;
        document.querySelector('meta[name="theme-color"]').content = light ? '#f4f7f4' : '#0d0208';
    };

    themeBtn.addEventListener('click', () => {
        const light = !isLight();
        if (light) document.documentElement.dataset.theme = 'light';
        else delete document.documentElement.dataset.theme;
        try { sessionStorage.setItem('theme', light ? 'light' : 'dark'); } catch (e) { /* stockage indisponible */ }
        render();
    });
    render();
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

// Son "cyber" au survol des liens, boutons et cartes. Les navigateurs n'autorisent
// le son qu'après une première interaction (clic ou touche) : avant, il reste muet.
let audioCtx = null;

function playClickSound() {
    try {
        audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
        if (audioCtx.state === 'suspended') audioCtx.resume();

        const oscillator = audioCtx.createOscillator();
        const gainNode = audioCtx.createGain();
        oscillator.type = 'sawtooth';
        oscillator.frequency.setValueAtTime(120, audioCtx.currentTime);
        oscillator.frequency.linearRampToValueAtTime(800, audioCtx.currentTime + 0.05);
        gainNode.gain.setValueAtTime(0.04, audioCtx.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.05);
        oscillator.connect(gainNode);
        gainNode.connect(audioCtx.destination);
        oscillator.start();
        oscillator.stop(audioCtx.currentTime + 0.05);
    } catch (e) { /* audio indisponible : on reste silencieux */ }
}

document.querySelectorAll('a, button, .btn, .service-card, .project-card').forEach(el => {
    el.addEventListener('pointerenter', e => {
        if (e.pointerType === 'mouse') playClickSound();
    });
});

// Notification par mail à chaque visite (une par session), via EmailJS.
const EMAILJS = {
    publicKey: 'iDAAJccPUyJWnHZ_f',
    serviceId: 'service_hm39lyc',
    templateId: 'template_7f7jy9k'
};
// Robots qui affichent un aperçu du lien, pas les navigateurs intégrés aux applications
// (l'application LinkedIn ouvre le site dans un vrai navigateur, à ne pas ignorer).
const BOT_PATTERN = /bot\b|bot\/|crawl|spider|slurp|headless|lighthouse|facebookexternalhit|linkedinbot|^whatsapp\/|telegrambot|skypeuripreview/i;

async function sendVisitNotification() {
    try {
        if (sessionStorage.getItem('visit-notified')) return;
    } catch (e) { /* stockage indisponible : on envoie quand même */ }

    // La localisation est un bonus : si un bloqueur de publicité bloque ipapi.co,
    // le mail part quand même, sans ville ni pays.
    let ipData = {};
    try {
        ipData = await fetch('https://ipapi.co/json/').then(res => res.json());
    } catch (e) { /* localisation indisponible */ }

    let entreprise = ipData.org || 'N/A';
    if (/orange|free|sfr|bouygues/i.test(entreprise)) {
        entreprise = 'Particulier / réseau privé';
    }

    try {
        const response = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                service_id: EMAILJS.serviceId,
                template_id: EMAILJS.templateId,
                user_id: EMAILJS.publicKey,
                template_params: {
                    ip: ipData.ip || 'N/A',
                    country: ipData.country_name || 'N/A',
                    city: ipData.city || 'N/A',
                    isp: ipData.org || 'N/A',
                    entreprise: entreprise,
                    browser: navigator.userAgent.substring(0, 120),
                    page: window.location.href,
                    date: new Date().toLocaleString('fr-FR', { timeZone: 'Europe/Paris' })
                }
            })
        });
        if (!response.ok) throw new Error(response.status + ' ' + await response.text());
        // marquée seulement une fois le mail réellement parti
        try { sessionStorage.setItem('visit-notified', '1'); } catch (e) { /* rien */ }
        console.log('Notification de visite envoyée');
    } catch (error) {
        console.log('Notification de visite non envoyée', error);
    }
}

if (location.hostname.endsWith('github.io') && !navigator.webdriver && !BOT_PATTERN.test(navigator.userAgent)) {
    sendVisitNotification();
}
