---
layout: post
title: "ECOWAS CTF 2026 — GrIOT [Forensics/100pts]"
date: 2026-04-24 10:43:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [forensics, iot, firmware, xor, gzip, tar, base64, ecfw, embedded-systems]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Forensics · **Difficulté :** ⭐⭐ (Medium) · **Points :** 100  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `griot-gw-v1.3.bin` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/43_griot-gw-v1.3.bin) |

---

---

## Étape 1 — Analyse de l'en-tête binaire

La première chose à faire avec un fichier binaire inconnu : **analyser son en-tête**.

```python
import struct

data = open('griot-gw-v1.3.bin', 'rb').read()

# Lire les premiers champs de l'en-tête
magic          = data[0:4]                          # "ECFW"
version        = struct.unpack_from('<H', data, 4)[0]
device_id      = data[8:22].rstrip(b'\x00').decode()
payload_offset = struct.unpack_from('<I', data, 32)[0]  # offset dans le fichier
payload_size   = struct.unpack_from('<I', data, 36)[0]  # taille
xor_key_byte   = struct.unpack_from('<I', data, 28)[0]  # clé XOR

print(f"Magic:          {magic}")            # b'ECFW'
print(f"Device ID:      {device_id}")        # 'GRIOT-IOT-7200'
print(f"Payload offset: 0x{payload_offset:x}")  # 0x1040 = 4160
print(f"Payload size:   0x{payload_size:x}")    # 0xBAD = 2989
print(f"XOR key:        0x{xor_key_byte:x}")    # 0xa7
```

**Sortie :**

```
Magic:          b'ECFW'
Device ID:      GRIOT-IOT-7200
Payload offset: 0x1040
Payload size:   0xbad
XOR key:        0xa7
```

> **Observation clé :** Le champ à l'offset 0x1c contient `0xa7` — c'est la clé XOR.

---

## Étape 2 — Extraction et déchiffrement XOR du payload

```python
# Extraire le payload depuis le bon offset
payload = data[0x1040 : 0x1040 + 0xbad]
print(f"Payload premiers octets: {payload[:8].hex()}")
# b8 2c af a7 fa 04 74 ce ...  → octets "chiffrés"

# Appliquer XOR avec la clé 0xa7
xor_key = 0xa7
decrypted = bytes(b ^ xor_key for b in payload)
print(f"Après XOR 0xa7: {decrypted[:8].hex()}")
# 1f 8b ... → signature GZIP !
```

Les deux premiers octets après XOR sont `1f 8b` — c'est la **signature magique GZIP** !

### Comment trouver la clé XOR ?

Méthode 1 — Lire l'en-tête (comme ci-dessus, le champ 0x1c = `0xa7`).

Méthode 2 — Brute force : si on sait que le payload est GZIP, le premier octet déchiffré doit être `0x1f`, donc `key = paylaod[0] XOR 0x1f` :

```python
key = payload[0] ^ 0x1f  # b8 XOR 1f = a7 ✓
```

---

## Étape 3 — Décompression GZIP → Système de fichiers TAR

```python
import zlib

# zlib.MAX_WBITS | 16 → mode GZIP (pas juste zlib raw)
rootfs = zlib.decompress(decrypted, zlib.MAX_WBITS | 16)

print(f"Taille décompressée: {len(rootfs)} octets")
# → 102400 octets (100 KB)
```

On a obtenu 100 KB de filesystem décompressé.

---

## Étape 4 — Lire le système de fichiers TAR

```python
import io, tarfile

# Créer un objet fichier en mémoire à partir des données décompressées
tar = tarfile.open(fileobj=io.BytesIO(rootfs))

# Lister tous les fichiers
for member in tar.getmembers():
    print(f"[{'DIR ' if member.isdir() else 'FILE'}] {member.name} ({member.size} B)")
```

**Sortie (extrait) :**

```
[DIR ] etc
[DIR ] etc/config
[FILE] etc/passwd (175 B)
[FILE] etc/shadow (179 B)
[FILE] etc/hostname (14 B)
[FILE] etc/config/network.conf (281 B)
[FILE] etc/config/iot_cloud.conf (441 B)     ← SUSPECT !
[FILE] etc/config/mqtt.conf (192 B)
[FILE] usr/bin/griot-daemon (82144 B)
[FILE] opt/app/.credentials (195 B)          ← TRÈS SUSPECT !
[FILE] var/log/syslog (494 B)
```

Les fichiers `iot_cloud.conf` et `.credentials` méritent une attention particulière.

---

## Étape 5 — Extraction et lecture des fichiers suspects

```python
# Lire opt/app/.credentials
f = tar.extractfile('opt/app/.credentials')
print(f.read().decode())
```

**Contenu de `.credentials` :**

```
# Legacy credentials — DO NOT USE IN PRODUCTION
# These were for the development MQTT broker
MQTT_USER=dev_griot
MQTT_PASS=D3v_P@ss_2024!
# Note: production auth uses token from iot_cloud.conf
```

```python
# Lire etc/config/iot_cloud.conf
f = tar.extractfile('etc/config/iot_cloud.conf')
print(f.read().decode())
```

**Contenu de `iot_cloud.conf` :**

```
# Griot Cloud Connector — production config
[cloud]
endpoint = https://api.griot-iot.ecowas.int/v2
region   = wa-west-1
protocol = mqtts

[auth]
method     = token
api_token  = RWNvd2FzQ1RGe2Yxcm13NHIzX3hvcl9mc19kdW1wX2dyMTB0fQ==
device_id  = GRT-7200-00AF-B1C3
```

Le champ `api_token` est du **Base64** !

---

## Étape 6 — Décoder le token Base64

```python
import base64

api_token = "RWNvd2FzQ1RGe2Yxcm13NHIzX3hvcl9mc19kdW1wX2dyMTB0fQ=="
flag = base64.b64decode(api_token).decode()
print(flag)
# → "EcowasCTF{f1rmw4r3_xor_fs_dump_gr10t}"
```

---

## Script complet

```python
import struct, zlib, io, tarfile, base64

# Étape 1 : lire le binaire
data = open('griot-gw-v1.3.bin', 'rb').read()

# Étape 2 : parser l'en-tête
payload_offset = struct.unpack_from('<I', data, 32)[0]  # 0x1040
payload_size   = struct.unpack_from('<I', data, 36)[0]  # 0xbad
xor_key        = struct.unpack_from('<I', data, 28)[0] & 0xff  # 0xa7

# Étape 3 : extraire et déchiffrer le payload
payload   = data[payload_offset : payload_offset + payload_size]
decrypted = bytes(b ^ xor_key for b in payload)

# Étape 4 : décompresser GZIP
rootfs = zlib.decompress(decrypted, zlib.MAX_WBITS | 16)

# Étape 5 : ouvrir l'archive TAR
tar = tarfile.open(fileobj=io.BytesIO(rootfs))

# Étape 6 : lire iot_cloud.conf et décoder le token
f = tar.extractfile('etc/config/iot_cloud.conf')
content = f.read().decode()
for line in content.splitlines():
    if 'api_token' in line:
        token = line.split('=')[1].strip()
        flag = base64.b64decode(token).decode()
        print("FLAG:", flag)
```

**Sortie :**

```
FLAG: EcowasCTF{f1rmw4r3_xor_fs_dump_gr10t}
```

---

## Récapitulatif de la chaîne d'exploitation

```
griot-gw-v1.3.bin
  ↓  Parse l'en-tête ECFW  →  offset=0x1040, size=0xbad, xor_key=0xa7
  ↓  Extraire le payload binaire
  ↓  XOR avec 0xa7 octet par octet
  ↓  Décompresser GZIP
  ↓  Lire l'archive TAR (système de fichiers Linux)
  ↓  Ouvrir etc/config/iot_cloud.conf
  ↓  Décoder le champ api_token en Base64
→ EcowasCTF{f1rmw4r3_xor_fs_dump_gr10t}
```

---

## Flag

```
EcowasCTF{f1rmw4r3_xor_fs_dump_gr10t}
```

---

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
