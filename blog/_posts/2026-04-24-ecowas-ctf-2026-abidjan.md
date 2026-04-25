---
layout: post
title: "ECOWAS CTF 2026 — Abidjan [Network Forensics/100pts]"
date: 2026-04-24 10:24:00 +0000
categories: [CTF, ECOWAS-CTF-2026]
tags: [network-forensics, pcap, arp, arp-poisoning, wireshark, tshark, mac-address]
toc: true
---

> **CTF :** ECOWAS CTF 2026 · **Catégorie :** Network Forensics · **Difficulté :** ⭐ (Easy) · **Points :** 100  
> **[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**

---

## Fichiers du challenge

> ⚠️ **Note :** Les fichiers sont hébergés sur la plateforme ECOWAS CTF. Les liens de téléchargement peuvent expirer après la fin de la compétition. Si un lien ne fonctionne plus ou consultez les archives de la plateforme.

| Fichier | Télécharger |
|---------|-------------|
| `Abidjan.pcap` | [⬇ Télécharger](/portfolio/blog/assets/files/ecowas-2026/24_abidjan.pcap) |

---

## Description

Analyse d'un fichier PCAP `Abidjan.pcap` (9 KB, 105 paquets) capturant du trafic réseau suspect.

---

## Analyse du PCAP

### ARP Poisoning — vecteur principal

En analysant les paquets ARP avec scapy :

```python
from scapy.all import rdpcap, ARP

pkts = rdpcap("Abidjan.pcap")
for pkt in pkts:
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
        print(pkt[ARP].hwsrc, "->", pkt[ARP].psrc)
```

Résultat :
- `00:11:22:33:44:55` : **12 ARP replies non sollicités** se réclamant être `192.168.1.1`
- `de:ad:be:ef:00:01` : 1 seule réponse ARP (légitimate gateway)

→ **L'attaquant est `00:11:22:33:44:55`** : 12 empoisonnements ARP = attaque en-masse.

### Autres artefacts trouvés dans le PCAP

| Type | Détail |
|------|--------|
| DNS tunneling | Requêtes base64 vers `exfil.tunnel-ns.xyz` → `password=Sup3rS3cr3t`, `user=admin@ACLEVP` |
| SQL Injection | `shop.acmecorp.local/products.php` → dump `admin:5f4dcc3b5aa765d61d8327deb882cf99` |
| C2 Beaconing | Vers `cdn-update.evil-c2.ru` avec UUID `a1b2c3d4e5f6` |
| SMB Scan | `192.168.1.105` scannant `.10, .15, .20, .25` sur le port 445 |
| Tor | Trafic via nœud de sortie `185.220.101.47:443` |

---

## Flag Format

Le format du flag est `EcowasCTF{x.x.x.x.x.x}` mais avec des **deux-points** (pas des points) :

Tentatives échouées :
- `EcowasCTF{00.11.22.33.44.55}` ❌
- `EcowasCTF{de.ad.be.ef.00.01}` ❌
- `EcowasCTF{de:ad:be:ef:00:01}` ❌

**Bonne réponse** :
- `EcowasCTF{00:11:22:33:44:55}` ✅ — l'adresse MAC de l'attaquant avec colons

---

## Script de solve

```python
from scapy.all import rdpcap, ARP
from collections import Counter

pkts = rdpcap("Abidjan.pcap")
arp_senders = Counter()
for pkt in pkts:
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # is-at
        arp_senders[pkt[ARP].hwsrc] += 1

# L'attaquant = MAC avec le plus grand nombre de ARP replies
attacker = max(arp_senders, key=arp_senders.get)
flag = f"EcowasCTF{{{attacker}}}"
print(flag)  # EcowasCTF{00:11:22:33:44:55}
```

---

## Flag

```
EcowasCTF{00:11:22:33:44:55}
```

---

## Leçon

L'ARP poisoning se reconnaît à l'envoi massif de ARP replies non sollicités (gratuitous ARP) depuis un MAC usurpant la gateway. Le format flag utilise bien les deux-points standard Unix pour les adresses MAC.

---

**[← Retour à l'index du CTF](/portfolio/blog/posts/ecowas-ctf-2026/)**
