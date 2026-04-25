---
layout: post
title: "ECOWAS CTF 2026 — Ngoma [Reverse/300pts]"
date: 2026-04-24 10:34:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [reverse, elf, upx, custom-vm, aes, bytecode, static-analysis, ghidra, unpacking]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Reverse Engineering · **Difficulté :** ⭐⭐ (Medium-Hard) · **Points :** 300  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `ngoma.zip` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/34_ngoma.zip) |

---

## Description du challenge

> *"A small drum, at times it hits but not like cerberus or maybe medusa or maybe joyboy?"*

Un seul fichier : `ngoma.zip` → contient `ngoma`.

Les indices dans la description :

- **Ngoma** = petit tambour en swahili/lingala → thème africain
- **"cerberus or maybe medusa or maybe joyboy"** → fausse piste vers des algo connus, ou indices sur la structure interne. On verra.

---

## Préambule : qu'est-ce qu'on cherche à faire ?

En Reverse Engineering CTF, le schéma typique est toujours le même :

```
On a un binaire "boîte noire"
↓
Il prend une entrée (le flag potentiel)
↓
Il effectue des transformations
↓
Il compare le résultat à une valeur attendue
↓
Notre mission : comprendre les transformations et les INVERSER
```

---

## Étape 1 — Identification du binaire

```bash
file ngoma
```

```
ngoma: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
       statically linked, no section to take,
       UPX compressed, BuildID[sha1]=...
```

Plusieurs informations importantes :

**ELF 64-bit x86-64** : c'est un exécutable Linux standard, architecture Intel/AMD 64 bits. Bon, on est sur notre terrain.

**statically linked** : toutes les bibliothèques sont intégrées dans le binaire (pas de dépendances dynamiques). Ça tend à rendre le binaire plus grand.

**UPX compressed** : **voilà le premier obstacle**.

---

## Concept #1 — UPX : qu'est-ce que c'est et pourquoi ça bloque ?

**UPX** (Ultimate Packer for eXecutables) est un compresseur de binaires. Il fonctionne comme ça :

```
[Binaire original] → UPX → [Stub de décompression] + [Données compressées]

À l'exécution :
1. Le stub se charge en mémoire
2. Il décompresse les données compressées
3. Il saute vers le vrai code
```

Le problème pour nous : si on essaie d'analyser le fichier directement dans Ghidra ou avec capstone, on analyse **le stub de décompression**, pas le vrai code. C'est comme essayer de lire un ZIP compressé comme si c'était du texte brut.

**La solution : dépacker le binaire.**

```bash
upx -d ngoma -o ngoma_upx
```

```
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.22       Markus Oberhumer, Laszlo Molnar & John Reiser    Oct 12th 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     14472 <-      7832   54.32%   linux/amd64   ngoma_upx

Unpacked 1 file.
```

Le binaire dépaqué fait 14472 bytes (7832 × 2 environ). Maintenant on peut l'analyser.

---

## Étape 2 — Premiers indices : strings et comportement

```bash
strings ngoma_upx
```

On cherche les **chaînes de caractères** lisibles dans le binaire. Résultat pertinent :

```
need exactly 32 bytes
the drum answers: correct.
silence.
the drum breaks.
nope.
```

**Que nous dit cela ?**

- `need exactly 32 bytes` → l'entrée doit faire exactement 32 bytes (= notre flag fait 32 caractères)
- `the drum answers: correct.` → chemin succès
- `silence.` → mauvaise entrée
- `the drum breaks.` → probablement le chemin anti-debug
- `nope.` → autre chemin d'échec

---

## Étape 3 — Détection d'anti-debug

```bash
strings ngoma_upx | grep -E "ptrace|prctl|getppid|waitpid"
```

On trouve ces symboles dans la table des imports. Le binaire implémente des techniques **anti-débogage** :

| Technique                           | Ce qu'elle fait                                                                       |
| ----------------------------------- | ------------------------------------------------------------------------------------- |
| `ptrace(PTRACE_TRACEME, 0, 0, 0)` | Si un débogueur est déjà attaché, échoue et on détecte                          |
| `getppid()`                       | Regarde si le parent est un débogueur (ex: gdb)                                      |
| `fork()` + `waitpid()`          | Lance un processus fils, le surveille ; si quelqu'un surveille aussi, ça se détecte |
| `prctl(PR_SET_DUMPABLE, 0)`       | Empêche les core dumps                                                               |

Si l'anti-debug se déclenche → `the drum breaks.` et exit.

**Conséquence pour nous** : on va faire du **reverse statique** (analyser sans exécuter). Pas besoin de contourner l'anti-debug si on n'exécute pas le binaire.

---

## Étape 4 — Analyse de la structure ELF

On regarde les sections du binaire :

```python
import struct

with open('ngoma_upx', 'rb') as f:
    data = f.read()

# Parser l'en-tête ELF pour les sections
# (on peut aussi faire: readelf -S ngoma_upx)
```

Résultat pertinent :

```
Section  Addr    Offset  Size
.text    0x1160  0x1160  0x4f9   ← le code (1273 bytes)
.rodata  0x2000  0x2000  0xad8   ← données lecture seule (2776 bytes!)
.bss     0x4020  0x3010  0x840   ← données non initialisées
```

La section `.rodata` est **inhabituellement grande** (2776 bytes pour un binaire de 14KB). Elle contient très probablement :

- Des clés de chiffrement
- Des tables de substitution (S-box)
- Le ciphertext attendu

---

## Étape 5 — Désassemblage du code principal

On utilise **Capstone** (bibliothèque de désassemblage en Python) pour lire la section `.text` :

```python
import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

code = data[0x1160:0x1160 + 0x4f9]
for ins in md.disasm(code, 0x1160):
    print(f'{ins.address:#010x}: {ins.mnemonic:<10} {ins.op_str}')
```

### Mon premier échec : confusion avec le stub UPX

 **Erreur commise initialement** : on avait essayé de désassembler le binaire original `ngoma` (pas `ngoma_upx`). Le résultat était le **code du stub UPX**, pas le vrai code. On voyait des instructions comme `pusha`, `popa`, des boucles de décompression — rien de lisible.

**Leçon : toujours dépacker avant d'analyser.**

---

## Étape 6 — Lecture du désassemblage (le vrai code)

Après avoir désassemblé `ngoma_upx`, voici les premières instructions :

```asm
0x00001164: push r13
0x00001166: xor  ecx, ecx
0x0000116a: xor  r8d, r8d
0x0000117a: mov  edi, 4
0x0000117f: sub  rsp, 0x38
0x00001183: call 0x1110     ← ptrace(4, 0, 0, 0)
0x00001188: xor  ecx, ecx
0x00001192: call 0x1120     ← fork()
0x00001197: cmp  rax, -1
0x0000119b: je   0x1551     ← si fork échoue → "the drum breaks."
```

On voit l'anti-debug se mettre en place. On continue :

```asm
0x000011a1: call 0x1150     ← getppid()
0x000011a6: test eax, eax
0x000011a8: je   0x1342     ← si pas de parent → chemin spécial

0x000011c3: cmp  ebx, 1    ← argc == 1 ?
0x000011c6: jle  0x1398    ← si argc <= 1 → lire depuis stdin

0x000011cc: mov  rbx, qword ptr [rbp + 8]  ← argv[1]
0x000011d3: call 0x1100    ← strlen(argv[1])
0x000011d8: cmp  rax, 0x20 ← longueur == 32 ?
0x000011dc: jne  0x13b8    ← sinon → "need exactly 32 bytes"
```

Donc le programme accepte le flag en argument ou en stdin, vérifie que c'est exactement **32 bytes**.

---

## Étape 7 — La grande révélation : une Machine Virtuelle !

En continuant la lecture du désassemblage, on arrive à quelque chose d'inhabituel :

```asm
0x00001201: lea  rbx, [rip + 0x2e38]   ← rbx = 0x4040 (zone mémoire)
0x00001208: lea  rbp, [rip + 0x3631]   ← rbp = 0x4840 (registres VM)
0x0000120f: lea  rsi, [rip + 0xe8a]    ← rsi = 0x20a0 (données)
0x00001216: mov  ecx, 0x100
0x0000121e: rep movsq                  ← copie 0x100 * 8 = 2048 bytes

0x00001221: mov  ecx, 8
0x00001226: mov  rdi, rbp
0x00001230: rep stosd                  ← initialise les registres VM à 0
```

Le programme **copie 2048 bytes depuis `.rodata` vers une zone mémoire**, puis **initialise 16 mots de 4 bytes à zéro** (les registres de la VM).

Ensuite, la boucle principale :

```asm
0x00001239: xor  edi, edi             ← compteur de PC = 0
0x0000123b: lea  r9, [rip + 0x165e]  ← r9 = bytecode (à 0x28a0)
0x00001242: lea  r12, [rip + 0xe17]  ← r12 = jump table (à 0x2060)

; Décoder l'instruction courante
0x00001250: lea  edx, [rdi + 1]
0x00001258: imul eax, r8d            ← eax = (pc+1) * 91
0x0000125c: movzx r13d, byte ptr [r9 + rdx]
0x00001264: xor  eax, 0xffffffa3     ← ^ 0xa3
; ... sélectionner l'opcode via la jump table
0x000012ac: movsxd rax, dword ptr [r12 + rdx*4]
0x000012b3: notrack jmp rax          ← dispatcher VM
```

**C'est une Machine Virtuelle** ! Le programme implémente son propre processeur virtuel.

---

## Concept #2 — La Machine Virtuelle (VM) dans les CTF

### Pourquoi utiliser une VM ?

Dans les CTF de reverse engineering avancé, les auteurs cachent parfois la logique dans une VM custom. L'idée :

```
[Bytecode chiffré/obfusqué] → [Interpréteur VM dans l'ELF] → [Résultat]
```

Avantages pour l'auteur :

1. Le désassembleur classique ne peut pas analyser directement le bytecode
2. L'analyser demande de comprendre d'abord l'interpréteur
3. On peut implémenter des opcodes non-standard difficiles à reconnaître

### Architecture de cette VM

Après analyse de l'interpréteur :

| Composant             | Description                                        |
| --------------------- | -------------------------------------------------- |
| **Registres**   | 16 registres 16 bits, nommés r0..r15              |
| **Mémoire**    | 2048 bytes adressables (adresses 0x000..0x7FF)     |
| **Programme**   | Bytecode stocké dans `.rodata` à offset 0x28a0 |
| **Instruction** | 4 bytes par instruction                            |

---

## Étape 8 — Comprendre l'encodage des instructions

Chaque instruction est **encodée/obfusquée**. En lisant l'interpréteur :

```asm
; Pour l'octet à la position i dans le bytecode :
; decode(i, byte) = byte ^ ((i * 91) & 0xFF) ^ 0xa3

0x00001258: imul eax, r8d    ← r8d = 0x5b = 91
0x00001264: xor  eax, 0xffffffa3  ← ^ 0xa3
```

Formule complète :

```python
def decode_byte(position, raw_byte):
    return (raw_byte ^ ((position * 91) & 0xFF) ^ 0xa3) & 0xFF
```

Chaque instruction décodée donne :

- `b0 & 0xF` → opcode (0..15)
- `b1 & 0xF` → registre destination
- `b2 & 0xF` → registre source 1 (ou octet fort d'une valeur immédiate)
- `b3 & 0xF` → registre source 2 (ou octet faible d'une valeur immédiate)

---

## Étape 9 — La table de dispatch (jump table)

L'interpréteur sélectionne le bon handler via une **jump table** à l'adresse 0x2060 :

```python
jt = struct.unpack('<16i', data[0x2060:0x2060+64])
# Chaque entrée : offset relatif depuis 0x2060 → adresse du handler
```

Mapping opcode → handler → sens :

| Opcode | Adresse handler | Nom                                                              |
| ------ | --------------- | ---------------------------------------------------------------- |
| 0      | 0x1528          | **CHECK** — compare r[dst] avec r[src], succès ou échec |
| 1      | 0x132f          | **STORE_IMM_BYTE** — r[dst] = valeur immédiate (8 bits)  |
| 2      | 0x1511          | **LOAD_IMM** — r[dst] = valeur immédiate 16 bits         |
| 3      | 0x14f1          | **LOAD_MEM** — r[dst] = mem[r[src] & 0x7FF]               |
| 4      | 0x14d2          | **STORE_MEM** — mem[r[dst] & 0x7FF] = r[src]              |
| 5      | 0x14bb          | **MOV** — r[dst] = r[src]                                 |
| 6      | 0x1493          | **ADD** — r[dst] = r[src1] + r[src2]                      |
| 7      | 0x1469          | **SUB** — r[dst] = r[src1] - r[src2]                      |
| 8      | 0x144a          | **XOR** — r[dst] = r[src1] ^ r[src2]                      |
| 9      | 0x141c          | **AND** — r[dst] = r[src1] & r[src2]                      |
| 10     | 0x1400          | **SHL** — r[dst] = r[src1] << r[src2]                     |
| 11     | 0x13e4          | **SAR** — r[dst] = r[src1] >> r[src2] (arithmétique)     |
| 12     | 0x12f4          | **GFMUL** — multiplication dans GF(256)                   |
| 13     | 0x12c3          | **JMP** — saut inconditionnel                             |
| 14     | 0x13ce          | **JNZ** — saut si r[dst] ≠ 0                             |
| 15     | 0x12b6          | **JEZ** — saut si r[dst] == 0                             |

**GFMUL** est l'opcode le plus rare et le plus révélateur. La multiplication dans GF(256) est utilisée dans... **AES**.

---

## Étape 10 — Désassemblage du bytecode VM

On écrit un désassembleur pour le bytecode :

```python
bytecode_off = 0x28a0  # r9 dans l'interpréteur
code = data[bytecode_off:bytecode_off + 568]

for i in range(0, 568, 4):
    b0 = decode_byte(i,   code[i])
    b1 = decode_byte(i+1, code[i+1])
    b2 = decode_byte(i+2, code[i+2])
    b3 = decode_byte(i+3, code[i+3])
    op = b0 & 0xF
    # ... afficher l'instruction
```

### Le bytecode désassemblé (annoté)

Voici le bytecode complet, annoté au fur et à mesure de notre compréhension :

```asm
; === INITIALISATION ===
   0: STORE_IMM_BYTE r12, 1     ; r12 = 1  (constante "incrément = 1")
   4: STORE_IMM_BYTE r13, 2     ; r13 = 2  (constante pour GF mul)
   8: STORE_IMM_BYTE r14, 3     ; r14 = 3  (constante pour GF mul)
  12: STORE_IMM_BYTE r15, 16    ; r15 = 16 (taille d'un bloc = 16 bytes)
  16: STORE_IMM_BYTE r0, 0      ; r0 = 0   (compteur de bloc, 0 ou 1)
  20: STORE_IMM_BYTE r1, 0      ; r1 = 0   (index byte courant dans le bloc)

; === BOUCLE A : AddRoundKey initial (XOR avec clé 0) ===
; mem[0x00..0x0F] = input_block XOR key0
; L'input est à mem[0x80..] (offset 0x80 + r0*16 + r1)
; La clé 0 est à mem[0x20..0x2F]
  24: MOV  r2, r0
  28: SHL  r2, r2, r4           ; r2 = r0 << r4 (r4 non initialisé = 0 → r2 = r0)
  32: ADD  r2, r2, r1           ; r2 = r0*16 + r1
  36: LOAD_IMM r3, 0x0080       ; r3 = 0x80
  40: ADD  r2, r2, r3           ; r2 = 0x80 + r0*16 + r1 (adresse dans l'input)
  44: LOAD_MEM r4, [r2]         ; r4 = mem[0x80 + r0*16 + r1] = input[r1]
  48: STORE_MEM [r1], r4        ; mem[r1] = input[r1]  (copier input dans mem[0..15])
  52: ADD  r1, r1, r12          ; r1++
  56: SUB  r5, r1, r15          ; r5 = r1 - 16
  60: JNZ  r5, 0x0018           ; si r1 != 16, continuer la boucle

; Au sortir : mem[0x00..0x0F] = input[0..15]

  64: STORE_IMM_BYTE r1, 0
  68: LOAD_IMM r2, 0x0020       ; Les clés commencent à mem[0x20]
  72: ADD  r2, r2, r1           ; r2 = 0x20 + r1
  76: LOAD_MEM r3, [r2]         ; r3 = key0[r1]
  80: LOAD_MEM r4, [r1]         ; r4 = state[r1]
  84: XOR  r4, r4, r3           ; r4 = state[r1] ^ key0[r1]
  88: STORE_MEM [r1], r4        ; state[r1] = r4
  92: ADD  r1, r1, r12
  96: SUB  r5, r1, r15
 100: JNZ  r5, 0x0044           ; boucler 16 fois
; → Résultat : state = input XOR key0  (c'est AddRoundKey !)

; === BOUCLE principale : 4 rounds ===
; r6 = compteur de round (1..4)
 104: STORE_IMM_BYTE r6, 1

; SOUS-ÉTAPE 1 : SubBytes (substitution via S-box)
; La S-box est à mem[0x100..0x1FF]
 108: STORE_IMM_BYTE r1, 0
 112: LOAD_MEM r3, [r1]         ; r3 = state[r1]
 116: LOAD_IMM r2, 0x0100       ; r2 = 0x100 (base S-box)
 120: ADD  r2, r2, r3           ; r2 = 0x100 + state[r1]
 124: LOAD_MEM r4, [r2]         ; r4 = sbox[state[r1]]
 128: STORE_MEM [r1], r4        ; state[r1] = sbox[state[r1]]
 132: ADD  r1, r1, r12
 136: SUB  r5, r1, r15
 140: JNZ  r5, 0x0070           ; 16 fois

; SOUS-ÉTAPE 2 : ShiftRows (permutation)
; La table de permutation est à mem[0x70..0x7F]
; 144-172 : copier state dans mem[0x10..0x1F]
; 176-216 : state[i] = temp[perm[i]]

; SOUS-ÉTAPE 3 : MixColumns
; 4 colonnes × 4 bytes, opérations GF(256)
 252: STORE_IMM_BYTE r7, 0      ; r7 = colonne courante (0..3)

; Pour chaque colonne (a, b, c, d) :
 300: GFMUL r2, r8, r13         ; 2*a
 304: GFMUL r3, r9, r14         ; 3*b
 308: XOR   r2, r2, r3          ; 2a ^ 3b
 312: XOR   r2, r2, r10         ; ^ c
 316: XOR   r2, r2, r11         ; ^ d  → nouveau[0] = 2a^3b^c^d ← MixColumns AES!
; (et pareil pour les 3 autres bytes)

; SOUS-ÉTAPE 4 : AddRoundKey(r6)
; La clé du round r6 est à mem[0x20 + r6*16]
 424: STORE_IMM_BYTE r1, 0
 428: MOV  r2, r6
 432: SHL  r2, r2, r4           ; r2 = r6 * 16 (shift par r4=4)
 436: ADD  r2, r2, r1           ; r2 = r6*16 + r1
 440: LOAD_IMM r3, 0x0020
 444: ADD  r2, r2, r3           ; r2 = 0x20 + r6*16 + r1
 448: LOAD_MEM r3, [r2]         ; r3 = key[r6][r1]
 452: LOAD_MEM r4, [r1]         ; r4 = state[r1]
 456: XOR  r4, r4, r3
 460: STORE_MEM [r1], r4        ; state[r1] ^= key[r6][r1]
; ... (16 fois)
 476: ADD  r6, r6, r12          ; round++
 480: STORE_IMM_BYTE r5, 5
 484: SUB  r2, r6, r5           ; r2 = r6 - 5
 488: JNZ  r2, 0x006c           ; si round != 5, recommencer

; === VÉRIFICATION FINALE ===
; Comparer state avec le ciphertext attendu à mem[0x200..]
 492: STORE_IMM_BYTE r1, 0
 496: MOV  r2, r0
 500: SHL  r2, r2, r4           ; r2 = r0*16
 504: ADD  r2, r2, r1
 508: LOAD_IMM r3, 0x0200       ; ciphertext attendu
 512: ADD  r2, r2, r3
 516: LOAD_MEM r3, [r2]         ; expected[r0*16 + r1]
 520: LOAD_MEM r4, [r1]         ; state[r1]
 524: XOR  r5, r3, r4
 528: JNZ  r5, 0x0234           ; si différent → "nope." / "silence."
; ... (16 fois)
 544: ADD  r0, r0, r12          ; bloc suivant (r0++)
 548: STORE_IMM_BYTE r5, 2
 552: SUB  r2, r0, r5
 556: JNZ  r2, 0x0014           ; si r0 != 2, traiter le 2ème bloc
 560: CHECK                     → "the drum answers: correct."
```

---

## Étape 11 — Confirmation : c'est de l'AES !

En assemblant les pièces :

1. **AddRoundKey** : XOR état avec une clé →  AES
2. **SubBytes** : substitution via table S-box → AES
3. **ShiftRows** : permutation circulaire des lignes → AES
4. **MixColumns** : multiplication dans GF(256) avec coefficients 2 et 3 →  AES

```
state = AddRoundKey(input, k[0])
for round in 1..4:
    state = SubBytes(state)
    state = ShiftRows(state)
    state = MixColumns(state)
    state = AddRoundKey(state, k[round])
compare(state, expected_ciphertext)
```

C'est de l'**AES à 4 rounds** (au lieu de 10/12/14 normalement) avec **clés hardcodées**.

### Vérification de la S-box

Pour en être sûr, on compare avec la S-box officielle AES :

```python
sbox = list(vm_mem(0x100, 256))
aes_sbox_known = [0x63, 0x7c, 0x77, 0x7b, ...]  # valeurs connues
print(sbox[0] == 0x63)   # True
print(sbox[1] == 0x7c)   # True
print(sbox[0x10] == 0xca) # True → c'est EXACTEMENT la S-box AES
```

### Le hint "cerberus / medusa / joyboy" expliqué maintenant

- **Cerberus** → 3 têtes → AES-192 ? ou référence aux 3 coefficients ?
- **Medusa** → transforme en pierre → S-box (substitution irréversible ?)
- **Joyboy** → One Piece → "joy" dans le sens de XOR "liberté" ?

C'étaient des fausses pistes pour faire croire à un algo custom. L'algo est du vrai AES.

---

## Étape 12 — Extraction des paramètres

Tout est stocké dans `.rodata`, copié dans la mémoire VM à l'offset 0x20a0 du fichier :

```python
vm_base = 0x20a0  # offset dans le fichier ngoma_upx

def vm_mem(addr, n=1):
    off = vm_base + addr
    if n == 1: return data[off]
    return data[off:off+n]

# 5 clés de 16 bytes (round keys k0..k4)
keys = [list(vm_mem(0x20 + r*16, 16)) for r in range(5)]
# k0: e55d3bd1769164549d03c1265a3c2e08
# k1: e4e1299437d1b44797458e7801d27427
# k2: 256c90b1607ed61392bad7e557da1533
# k3: e61de9df00c9cb530810444fb50a692c
# k4: d53f4f117b9f3b5b41f5e95dec875940

# S-box (256 bytes, standard AES)
sbox = list(vm_mem(0x100, 256))

# Table ShiftRows (permutation de 16 entiers)
sr_perm = list(vm_mem(0x70, 16))
# = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
# EXACTEMENT la permutation standard AES !

# Ciphertext attendu (32 bytes = 2 blocs)
ct0 = list(vm_mem(0x200, 16))  # 1cb2b01623ed909e0ac72d81ad1e5e08
ct1 = list(vm_mem(0x210, 16))  # fe3b90e145f7fe90dad86f4a47421d2e
```

---

## Concept #3 — AES : comment ça marche et comment l'inverser

### Pourquoi peut-on déchiffrer ?

Chaque opération AES est **réversible** :

| Opération                      | Inverse                                          |
| ------------------------------- | ------------------------------------------------ |
| `SubBytes` (sbox[x])          | `InvSubBytes` (inverse de la S-box)            |
| `ShiftRows` (perm[i])         | `InvShiftRows` (permutation inverse)           |
| `MixColumns` (GF mul par 2/3) | `InvMixColumns` (GF mul par 9/11/13/14)        |
| `AddRoundKey` (XOR k)         | `AddRoundKey` (XOR encore avec k = annulation) |

### Le déchiffrement

On applique les inverses **à l'envers** :

```
Déchiffrement:
  état = ciphertext
  Pour i = 4, 3, 2, 1:
    état = état XOR k[i]           ← InvAddRoundKey (= AddRoundKey)
    état = InvMixColumns(état)     ← inverse MixColumns
    état = InvShiftRows(état)      ← inverse ShiftRows
    état = InvSubBytes(état)       ← inverse S-box
  état = état XOR k[0]             ← InvAddRoundKey initial
  retourner état = plaintext
```

---

## Étape 13 — Implémentation Python du déchiffrement

```python
def gfmul(a, b):
    """Multiplication dans GF(2^8) avec polynôme AES x^8+x^4+x^3+x+1 (0x11b)"""
    result = 0
    for _ in range(8):
        if b & 1:           # si le bit bas de b est 1
            result ^= a     # XOR avec a
        hi = a & 0x80       # sauvegarder le bit haut de a
        a = (a << 1) & 0xFF # décaler a d'un bit vers le haut
        if hi:              # si le bit haut était 1
            a ^= 0x1b       # réduire modulo le polynôme (0x11b → 0x1b en 8 bits)
        b >>= 1             # décaler b d'un bit
    return result

# Pour déchiffrer MixColumns, les coefficients inverses sont 9, 11 (0xb), 13 (0xd), 14 (0xe)
def inv_mix_columns(state):
    out = []
    for col in range(4):
        a = state[col*4 : col*4+4]  # les 4 bytes de la colonne
        # Formule InvMixColumns d'AES
        b0 = gfmul(a[0], 0xe) ^ gfmul(a[1], 0xb) ^ gfmul(a[2], 0xd) ^ gfmul(a[3], 0x9)
        b1 = gfmul(a[0], 0x9) ^ gfmul(a[1], 0xe) ^ gfmul(a[2], 0xb) ^ gfmul(a[3], 0xd)
        b2 = gfmul(a[0], 0xd) ^ gfmul(a[1], 0x9) ^ gfmul(a[2], 0xe) ^ gfmul(a[3], 0xb)
        b3 = gfmul(a[0], 0xb) ^ gfmul(a[1], 0xd) ^ gfmul(a[2], 0x9) ^ gfmul(a[3], 0xe)
        out += [b0, b1, b2, b3]
    return out

def inv_shift_rows(state):
    """Inverse la permutation: si forward met state[perm[i]] en position i,
    l'inverse remet state[i] en position perm[i]"""
    result = [0] * 16
    for i in range(16):
        result[sr_perm[i]] = state[i]
    return result

def inv_sub_bytes(state):
    """Remplace chaque byte par son inverse dans la S-box"""
    return [inv_sbox[b] for b in state]

def decrypt_block(ct, keys):
    state = list(ct)
    for r in range(4, 0, -1):           # rounds 4, 3, 2, 1
        state = add_round_key(state, keys[r])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
    state = add_round_key(state, keys[0])  # défaire le XOR initial
    return state
```

---

## Étape 14 — Exécution et vérification

```python
ct0 = list(vm_mem(0x200, 16))
ct1 = list(vm_mem(0x210, 16))

pt0 = decrypt_block(ct0, keys)
pt1 = decrypt_block(ct1, keys)

flag = bytes(pt0 + pt1)
print(flag)  # b'EcowasCTF{vm_ng0m4_spn_r1ng_0bf}'

# Vérification : re-chiffrer et comparer
enc0 = encrypt_block(pt0, keys)
print(enc0 == ct0)  # True ← parfait !
```

---

## Résultat

```
EcowasCTF{vm_ng0m4_spn_r1ng_0bf}
```

### Décryptage du flag

- `vm` → Virtual Machine (la structure qu'on a analysée)
- `ng0m4` → Ngoma (le nom du challenge)
- `spn` → Substitution-Permutation Network (l'architecture d'AES)
- `r1ng` → Ring / GF ring (les corps de Galois utilisés dans AES)
- `0bf` → obfuscation ?

---

## Récapitulatif de notre parcours

### Timeline et erreurs commises

```
[Début]
  ↓
1. file ngoma → UPX détecté
   → Essai d'analyser le binaire compressé avec capstone
    ÉCHEC : on lisait le stub UPX, pas le vrai code
  ↓
2. upx -d ngoma -o ngoma_upx
   → Lecture des strings : "need exactly 32 bytes"
   → Détection anti-debug (ptrace/fork)
  ↓
3. Lecture des sections ELF
   → .rodata inhabituel (2776 bytes pour si peu de code)
  ↓
4. Désassemblage .text avec capstone
   → Interpréteur VM identifié
   → Jump table à 0x2060
  ↓
5. Décodage de la formule d'obfuscation des instructions
   → decode(pos, byte) = byte ^ ((pos * 91) & 0xFF) ^ 0xa3
  ↓
6. Écriture d'un désassembleur pour le bytecode
   → GFMUL opcode → indice AES
   → Structure SubBytes/ShiftRows/MixColumns confirmée
  ↓
7. Extraction des paramètres depuis .rodata
   → S-box = AES standard confirmée
   → 5 round keys
   → Ciphertext attendu
  ↓
8. Implémentation du déchiffrement AES inverse
    Premier essai : mauvais ordre des inverses (on avait mis InvShiftRows avant InvMixColumns)
    Correction : InvAddRoundKey → InvMixColumns → InvShiftRows → InvSubBytes
  ↓
9. Vérification : re-encrypt == ciphertext → 
  ↓
FLAG : EcowasCTF{vm_ng0m4_spn_r1ng_0bf}
```

---

## Architecture finale de la solution

```
ngoma (UPX packed, 7832 bytes)
    ↓ upx -d
ngoma_upx (ELF x86-64, 14472 bytes)
    ↓ capstone disassembly de .text
Interpréteur VM
    ├── Registres: r0..r15 (16-bit)
    ├── Mémoire: 2048 bytes (depuis .rodata à 0x20a0)
    │   ├── 0x00..0x0F  : état courant (16 bytes)
    │   ├── 0x10..0x1F  : tampon temporaire (ShiftRows)
    │   ├── 0x20..0x6F  : 5 round keys × 16 bytes
    │   ├── 0x70..0x7F  : table ShiftRows (permutation)
    │   ├── 0x80..0xFF  : input utilisateur (2 blocs × 16 bytes)
    │   ├── 0x100..0x1FF: S-box AES (256 bytes)
    │   └── 0x200..0x21F: ciphertext attendu (2 blocs × 16 bytes)
    └── Bytecode: .rodata à 0x28a0 (568 bytes, encodé)
        ↓ 142 instructions décodées
4-round AES
    ├── AddRoundKey(k0)
    ├── [SubBytes → ShiftRows → MixColumns → AddRoundKey(k1)] × 4
    └── Compare avec ciphertext
```

---

## Script complet de résolution

```python
#!/usr/bin/env python3
"""Solver challenge 34 Ngoma - ECOWAS CTF 2026"""
import struct

with open("ngoma_upx", "rb") as f:
    data = f.read()

vm_base = 0x20a0

def vm_mem(addr, n=1):
    off = vm_base + addr
    return data[off] if n == 1 else data[off:off+n]

# === Charger les paramètres depuis .rodata ===
keys    = [list(vm_mem(0x20 + r*16, 16)) for r in range(5)]
sbox    = list(vm_mem(0x100, 256))
sr_perm = list(vm_mem(0x70, 16))
ct0     = list(vm_mem(0x200, 16))
ct1     = list(vm_mem(0x210, 16))

# Inverse de la S-box
inv_sbox = [0]*256
for i, v in enumerate(sbox):
    inv_sbox[v] = i

# === Opérations AES ===

def gfmul(a, b):
    """Multiplication GF(2^8), polynôme 0x11b"""
    result = 0
    for _ in range(8):
        if b & 1: result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1b
        b >>= 1
    return result

def add_round_key(state, key):
    return [state[i] ^ key[i] for i in range(16)]

def inv_sub_bytes(state):
    return [inv_sbox[b] for b in state]

def inv_shift_rows(state):
    result = [0]*16
    for i in range(16):
        result[sr_perm[i]] = state[i]
    return result

def inv_mix_columns(state):
    out = []
    for col in range(4):
        a = state[col*4:col*4+4]
        b0 = gfmul(a[0],14)^gfmul(a[1],11)^gfmul(a[2],13)^gfmul(a[3], 9)
        b1 = gfmul(a[0], 9)^gfmul(a[1],14)^gfmul(a[2],11)^gfmul(a[3],13)
        b2 = gfmul(a[0],13)^gfmul(a[1], 9)^gfmul(a[2],14)^gfmul(a[3],11)
        b3 = gfmul(a[0],11)^gfmul(a[1],13)^gfmul(a[2], 9)^gfmul(a[3],14)
        out += [b0,b1,b2,b3]
    return out

def decrypt_block(ct, keys):
    state = list(ct)
    for r in range(4, 0, -1):
        state = add_round_key(state, keys[r])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
    return add_round_key(state, keys[0])

# === Déchiffrer les 2 blocs ===
flag = bytes(decrypt_block(ct0, keys) + decrypt_block(ct1, keys))
print(flag.decode())
# → EcowasCTF{vm_ng0m4_spn_r1ng_0bf}
```

---

## Ce qu'on a appris

| Concept                              | Application dans ce challenge                                |
| ------------------------------------ | ------------------------------------------------------------ |
| **UPX unpacking**              | Dépacker avant d'analyser `upx -d`                        |
| **Anti-debug**                 | Reconnaître ptrace/fork, ignorer en analyse statique        |
| **VM (Machine Virtuelle)**     | Identifier l'interpréteur, comprendre les registres/opcodes |
| **Obfuscation d'instructions** | Formule de décodage `byte ^ (pos*91) ^ 0xa3`              |
| **Jump table**                 | Dispatcher VM = tableau d'adresses de handlers               |
| **AES**                        | Reconnaître SubBytes/ShiftRows/MixColumns/AddRoundKey       |
| **GF(256)**                    | Multiplication dans le corps fini de Galois (MixColumns)     |
| **Reverse AES**                | Inverser chaque étape dans l'ordre inverse                  |

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
