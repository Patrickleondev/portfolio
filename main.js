// Matrix Background Effect
const canvas = document.createElement('canvas');
const ctx = canvas.getContext('2d');
const matrixBg = document.getElementById('matrix-bg');
matrixBg.appendChild(canvas);

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@#$%^&*()";
const fontSize = 16;
const columns = canvas.width / fontSize;
const drops = [];

for (let i = 0; i < columns; i++) {
    drops[i] = 1;
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

setInterval(draw, 33);

window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});

// Typewriter Effect
const typeWriterElements = [
    { selector: '.greeting', delay: 0 },
    { selector: '.glitch', delay: 1000 },
    { selector: '.role', delay: 2000 },
    { selector: '.bio-short', delay: 3500 },
    { selector: '#about-title', delay: 500 },
    { selector: '#about-hook', delay: 1500 }
];

function typeWriter(element, text, i = 0, speed = 75) {
    if (i < text.length) {
        element.innerHTML += text.charAt(i);
        i++;
        setTimeout(() => typeWriter(element, text, i, speed), speed);
    } else {
        element.style.borderRight = "none"; // Remove cursor after typing
    }
}

window.addEventListener('load', () => {
    typeWriterElements.forEach(({ selector, delay }) => {
        const element = document.querySelector(selector);
        if (element) {
            const text = element.getAttribute('data-text') || element.innerText;
            element.innerText = ''; // Clear initial text
            element.style.opacity = '1';
            element.style.visibility = 'visible';

            setTimeout(() => {
                element.style.borderRight = "2px solid var(--accent-color)"; // Add cursor
                typeWriter(element, text);
            }, delay);
        }
    });
});
// Audio Context for Hover Effect (Hacker Style)
const audioCtx = new (window.AudioContext || window.webkitAudioContext)();

function playHoverSound() {
    if (audioCtx.state === 'suspended') {
        audioCtx.resume();
    }
    const oscillator = audioCtx.createOscillator();
    const gainNode = audioCtx.createGain();

    oscillator.type = 'sine';
    oscillator.frequency.setValueAtTime(220, audioCtx.currentTime); // Low frequency
    oscillator.frequency.exponentialRampToValueAtTime(800, audioCtx.currentTime + 0.1); // Zip up

    gainNode.gain.setValueAtTime(0.05, audioCtx.currentTime); // Low volume
    gainNode.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.1);

    oscillator.connect(gainNode);
    gainNode.connect(audioCtx.destination);

    oscillator.start();
    oscillator.stop(audioCtx.currentTime + 0.1);
}

// Add hover listeners to interactive cards
document.querySelectorAll('.service-card, .project-card, .btn, a').forEach(el => {
    el.addEventListener('mouseenter', () => {
        playHoverSound();
        if (navigator.vibrate) navigator.vibrate(5); // Micro vibration
    });
});
