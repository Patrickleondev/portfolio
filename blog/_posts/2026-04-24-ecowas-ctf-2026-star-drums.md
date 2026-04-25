---
layout: post
title: "ECOWAS CTF 2026 — Star Drums [Steganography/Medium]"
date: 2026-04-24 10:45:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [steganography, morse, audio, base64, rot13, wav, medium]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Steganography · **Difficulté :** ⭐⭐ Medium · **Points :** 200  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `star_drums.wav` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/60_star_drums.wav) |

---

# #60 – Star Drums (Steganography, 200 pts)

## Challenge Description

> Drums across the Sahel carry messages in their rhythm. Can you decode the beats?

## Files / Artifacts

- `drums.wav` — 8 kHz mono WAV file (~57 seconds) containing rhythmic drum beats

## Overview

A three-layer encoding chain hidden in audio:
1. The flag was **base64-encoded**
2. Each **letter** in the base64 string was **ROT-13'd** (digits and `=` unchanged)
3. The result was forced to **uppercase**
4. Encoded as **Morse code** and synthesised into audio beats

Reverse: decode Morse from WAV energy → undo case loss via greedy base64 decode → decode base64 → flag.

## Solution

### Step 1: Decode Morse Code from Audio

Analyse audio energy in 10 ms frames (80 samples at 8 kHz) to classify signal as on/off. Measure run lengths to classify symbols as dit (1 unit), dah (3 units), inter-symbol gap, word gap.

```python
import wave, numpy as np

with wave.open('drums.wav') as wf:
    rate = wf.getframerate()          # 8000 Hz
    raw  = wf.readframes(wf.getnframes())

data       = np.frombuffer(raw, dtype=np.int16).astype(float)
frame_size = 80   # 10 ms at 8 kHz
energy     = np.array([np.sum(data[i*80:(i+1)*80]**2) for i in range(len(data)//80)])
active     = energy / np.max(energy) > 0.05

# Measure run lengths → classify as dit / dah / gaps
# Standard Morse timing: dit=1 unit, dah=3 units, symbol-gap=1, letter-gap=3, word-gap=7
```

**Decoded Morse output** (all uppercase, looks like base64):
```
EJAIQ2SMD1ETR3Z0NQAFK2ELAT1MK20JPAZMK2V2AS9LZUDKZ30=
```

**Key observation:** The string ends in `=` and contains only alphanumerics — characteristic of base64.

### Step 2: Understand the Encoding Chain

Direct base64 decode fails (produces non-printable binary). Reasoning through the encoding:

| Step | Operation | Example (for character `E` in flag) |
|------|-----------|--------------------------------------|
| 1 | Raw flag char | `E` |
| 2 | Base64 encode flag | e.g., `R` in base64 stream |
| 3 | ROT-13 letter | `R` → `E` |
| 4 | Uppercase | `E` (already uppercase) |
| 5 | Morse → audio | `· −` |

The **problem**: step 4 collapses case. Each uppercase letter `X` in the Morse output could have come from *either* the uppercase or lowercase ROT-13 inverse. For example, Morse `E` was either base64 `R` (if original was uppercase `E`) or base64 `e` (if original was lowercase `e`) after ROT-13 inversion.

### Step 3: Greedy Case Recovery

For each character in the Morse string, generate both possible base64 candidates. Process groups of 4 base64 characters at a time (each group decodes to 3 bytes), greedily selecting the combination that yields the most printable ASCII output.

```python
import base64
from itertools import product

morse_decoded = 'EJAIQ2SMD1ETR3Z0NQAFK2ELAT1MK20JPAZMK2V2AS9LZUDKZ30='

def rot13_inv(c):
    """Map uppercase Morse char → two possible base64 candidates."""
    if c.isdigit() or c == '=':
        return [c]
    idx   = ord(c) - ord('A')
    upper = chr(ord('A') + (idx + 13) % 26)   # ROT-13 inverse, uppercase
    return [upper, upper.lower()]              # both case variants

def printable_score(data):
    return sum(1 for b in data if 32 <= b < 127) if data else -1

possible     = [rot13_inv(c) for c in morse_decoded]
result_chars = []
n            = len(possible)

for i in range(0, n, 4):
    group      = possible[i:i+4]
    best_score = -1
    best_combo = [opts[0] for opts in group]
    for combo in product(*group):
        test_b64 = ''.join(result_chars) + ''.join(combo)
        pad = (4 - len(test_b64) % 4) % 4
        try:
            dec = base64.b64decode(test_b64 + '=' * pad)
            sc  = printable_score(dec[-3:])
            if sc > best_score:
                best_score, best_combo = sc, list(combo)
        except Exception:
            pass
    result_chars.extend(best_combo)

b64_str = ''.join(result_chars)
flag    = base64.b64decode(b64_str).decode()
print(f"[+] Flag: {flag}")
# EcowasCTF{s4h3l_dr4ms_m0rs3_b64_r0t13}
```

**Recovered base64:** `RWNvd2FzQ1RGe3M0aDNsX2RyNG1zX20wcnMzX2I2NF9yMHQxM30=`

### Verification

```python
import base64, codecs
base64.b64decode('RWNvd2FzQ1RGe3M0aDNsX2RyNG1zX20wcnMzX2I2NF9yMHQxM30=').decode()
# 'EcowasCTF{s4h3l_dr4ms_m0rs3_b64_r0t13}'
```

## Full Solve Script

```python
#!/usr/bin/env python3
"""
#60 Star Drums — full solve (Morse audio → base64+ROT-13 → flag)
Requires: numpy, a Morse decoder (decode_morse.py), then this script.
"""
import base64
from itertools import product

# Step 1 output: Morse-decoded string (obtained from audio energy analysis)
morse_decoded = 'EJAIQ2SMD1ETR3Z0NQAFK2ELAT1MK20JPAZMK2V2AS9LZUDKZ30='

def rot13_inv(c):
    """Map each uppercase Morse-decoded char to possible original base64 chars."""
    if c.isdigit() or c == '=':
        return [c]
    idx   = ord(c) - ord('A')
    upper = chr(ord('A') + (idx + 13) % 26)
    return [upper, upper.lower()]

def printable_score(data):
    if not data:
        return -1
    return sum(1 for b in data if 32 <= b < 127)

possible     = [rot13_inv(c) for c in morse_decoded]
result_chars = []

for i in range(0, len(possible), 4):
    group      = possible[i:i+4]
    best_score = -1
    best_combo = [opts[0] for opts in group]
    for combo in product(*group):
        test_b64 = ''.join(result_chars) + ''.join(combo)
        pad = (4 - len(test_b64) % 4) % 4
        try:
            dec = base64.b64decode(test_b64 + '=' * pad)
            sc  = printable_score(dec[-3:])
            if sc > best_score:
                best_score, best_combo = sc, list(combo)
        except Exception:
            pass
    result_chars.extend(best_combo)

b64_str = ''.join(result_chars)
flag    = base64.b64decode(b64_str).decode()
print(f"[+] Flag: {flag}")
# EcowasCTF{s4h3l_dr4ms_m0rs3_b64_r0t13}
```

## Flag

```
EcowasCTF{s4h3l_dr4ms_m0rs3_b64_r0t13}
```

## Lessons Learned

- WAV Morse audio → always check if the decoded string looks like base64 (ends in `=`, only alphanum + `/+`).
- **ROT-13 + uppercase kills case** → greedy group-of-4 base64 decode recovers it cleanly without full brute-force.
- Challenge title "Star Drums" + "Sahel" hint strongly at the multi-layer encoding name embedded in the flag itself (`m0rs3_b64_r0t13`).
- The encoding chain order matters: encode first, then obfuscate; decode in reverse — Morse → ROT-13 inv → base64 dec.

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
