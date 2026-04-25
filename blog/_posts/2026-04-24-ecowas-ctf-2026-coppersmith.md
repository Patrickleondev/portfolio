---
layout: post
title: "ECOWAS CTF 2026 — Coppersmith [Crypto/500pts]"
date: 2026-04-24 10:57:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [crypto, rsa, coppersmith, small-roots, lattice, sagemath, factorization, partial-key]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Crypto · **Difficulté :** ⭐⭐⭐ (Hard) · **Points :** 500  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

title: Coppersmith
ctf: ECOWAS CTF 2025
date: 2026-04-14
category: misc
difficulty: hard
points: 500
flag_format: EcowasCTF{...}
flag: EcowasCTF{c0pp3rsm1th_f1nds_th3_nil3_s0urce}
author: team
---

# #57 – Coppersmith (Misc, 500 pts)

## Challenge Description

> The Nile leaks only a little each season, but a little is enough. You are given 520 of the lowest bits of p. Recover the rest.

## Files / Artifacts

- `params.txt` — RSA parameters:
  - `N` (1024-bit modulus)
  - `e = 65537`
  - `c` (ciphertext)
  - `p_low` (the low ~319 bits of factor p)

## Overview

**RSA key recovery via Coppersmith's method** (low-bits of p known). We know the least significant bits of one of N's prime factors. Coppersmith's `small_roots` algorithm finds the unknown high bits of `p` via lattice reduction, recovering `p` completely, factoring `N`, and decrypting the flag.

## The Math

Let $N = p \cdot q$ with $|p| = |q| \approx 512$ bits. We know:

$$p = p_{\text{high}} \cdot 2^k + p_{\text{low}}$$

where $p_{\text{low}}$ is the known low part ($k \approx 319$ bits known), and $p_{\text{high}} < 2^{512 - k} \approx 2^{193}$ is unknown.

Define the polynomial:

$$f(x) = x \cdot 2^k + p_{\text{low}}$$

Then $f(p_{\text{high}}) = p$, so $\gcd(f(p_{\text{high}}), N) = p$.

Coppersmith's theorem guarantees we can find a small root $p_{\text{high}}$ of a related polynomial modulo $N$ when:

$$|p_{\text{high}}| < N^{\beta^2 / \deg(f)}$$

With $\beta = 0.499$ (i.e., $p > N^{0.499}$), degree 1, and $|p_{\text{high}}| \approx N^{0.188}$, the bound is satisfied.

Convert to monic form by multiplying both sides by $(2^k)^{-1} \bmod N$:

$$f_{\text{monic}}(x) = x + p_{\text{low}} \cdot (2^k)^{-1} \bmod N$$

Root: $x_0 = p_{\text{high}}$ where $f_{\text{monic}}(p_{\text{high}}) \equiv 0 \pmod{N}$.

## Solution

### Step 1: Set Up the Polynomial

```python
# In SageMath
N     = 74600889653023...  # (full value in params.txt)
e     = 65537
c     = 75404784285460...  # (full value in params.txt)
p_low = 45441561978689...  # (full value in params.txt)

nbits_N   = int(N).bit_length()       # 1024
nbits_p   = nbits_N // 2              # 512
nbits_low = int(p_low).bit_length()   # ~319
k = nbits_low                          # known bit count
```

### Step 2: Run Coppersmith's small_roots

```sage
P.<x> = Zmod(N)[]
inv2k    = ZZ(pow(int(2)^k, -1, int(N)))
f_monic  = P(x + ZZ(p_low) * inv2k)

X_bound  = 2^(nbits_p - k + 4)       # ~2^197, with slack
roots    = f_monic.small_roots(X=X_bound, beta=0.499, epsilon=1/40)
```

### Step 3: Recover p, Factor N, Decrypt

```sage
if roots:
    p_high = int(roots[0])
    p      = p_high * int(2^k) + int(p_low)
    assert N % p == 0, "p does not divide N!"
    q      = N // p
    phi    = (p - 1) * (q - 1)
    d      = pow(e, -1, phi)
    m      = pow(c, d, N)
    m_bytes = int(m).to_bytes((int(m).bit_length() + 7) // 8, 'big')
    print(m_bytes.decode(errors='replace'))
```

## Full Solve Script

```sage
#!/usr/bin/env sage
# #57 Coppersmith — RSA with low bits of p known → recover p via small_roots

proof.arithmetic(False)

N = 74600889653023659496323524800203844283998596227333292301031442457415034623646301211632868394578744188584588173976056895281836412051522943414262583130205572712962539765806894162288542023844818056144716954515665693117374757424006534930550604084525257604307933974466490220155852248857791349963756379468368424681
e = 65537
c = 7540478428546052896026450923123205320446884760712280030506771017665028362203351590295148946581458513381674355031030111156745224804119718411808346486136345610469894546186492928929742243551592712937158781566590978208703093367973587593330992466146325727723310095530136386718998330874738270449799957393839154914
p_low = 454415619786896494701626302280808392653952174258062178500272049314321860915799365077432422046043

nbits_N   = int(N).bit_length()        # 1024
nbits_p   = nbits_N // 2               # 512
nbits_low = int(p_low).bit_length()    # ~319
k         = nbits_low

print(f"N bits:     {nbits_N}")
print(f"p bits:     {nbits_p}")
print(f"p_low bits: {nbits_low}")
print(f"Unknown:    {nbits_p - nbits_low} bits")

# Build monic polynomial f(x) = x + p_low * (2^k)^-1  (root = p_high)
P.<x>    = Zmod(N)[]
inv2k    = ZZ(pow(int(2)^int(k), -1, int(N)))
f_monic  = P(x + ZZ(p_low) * inv2k)

X_bound = 2^(nbits_p - k + 4)
print(f"X_bound bits: {int(X_bound).bit_length()}")

print("Running small_roots (monic)...")
roots = f_monic.small_roots(X=X_bound, beta=0.499, epsilon=1/40)

if not roots:
    print("Retrying with epsilon=1/30...")
    roots = f_monic.small_roots(X=X_bound, beta=0.499, epsilon=1/30)

if roots:
    p_high  = int(roots[0])
    p       = p_high * int(2^k) + int(p_low)
    assert N % p == 0, "ERROR: p does not divide N!"
    q       = N // p
    print(f"[+] Factored N successfully.")
    phi     = (p - 1) * (q - 1)
    d       = pow(e, -1, phi)
    m       = pow(c, d, N)
    m_bytes = int(m).to_bytes((int(m).bit_length() + 7) // 8, 'big')

    # Strip PKCS#1 v1.5 padding if present
    if m_bytes[:1] == b'\x02' or m_bytes[:2] == b'\x00\x02':
        data = m_bytes if m_bytes[:1] == b'\x02' else m_bytes[1:]
        idx  = data.index(b'\x00')
        m_bytes = data[idx + 1:]

    print(f"[+] Flag: {m_bytes.decode(errors='replace')}")
    # EcowasCTF{c0pp3rsm1th_f1nds_th3_nil3_s0urce}
else:
    print("FAILED: No roots found.")
```

## Flag

```
EcowasCTF{c0pp3rsm1th_f1nds_th3_nil3_s0urce}
```

## Lessons Learned

- **Know the low bits of p?** → Immediate Coppersmith: polynomial `f(x) = x * 2^k + p_low`, root = `p_high`.
- Use monic form: multiply `f(x)` by `(2^k)^{-1} mod N` to make it monic before calling `small_roots`.
- Parameters: `beta=0.499` (p is close to sqrt(N)), `epsilon=1/40` works; if no root, widen `X_bound` or increase `epsilon`.
- PKCS#1 v1.5 padding strips: scan for first `\x00` byte after the padding byte, take the rest as plaintext.
- Challenge flavour: "only a little leaks" → partial key info → Coppersmith.

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
