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

// Effet machine à écrire, limité aux titres courts. Le texte complet reste lisible
// par les lecteurs d'écran (aria-label) et s'affiche directement sans animation.
const typedSelectors = ['.greeting', '.glitch', '#about-title', '#services-title',
    '#realizations-title', '#expertise-title', '#tech-title'];

function typeWriter(element, text, i = 0) {
    if (i < text.length) {
        element.textContent += text.charAt(i);
        setTimeout(() => typeWriter(element, text, i + 1), 45);
    } else {
        element.classList.remove('typing');
    }
}

if (!reduceMotion) {
    typedSelectors.forEach((selector, index) => {
        const element = document.querySelector(selector);
        if (!element) return;
        const text = element.getAttribute('data-text') || element.textContent.trim();
        element.setAttribute('aria-label', text);
        element.textContent = '';
        element.classList.add('typing');
        setTimeout(() => typeWriter(element, text), index === 0 ? 0 : 300);
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
