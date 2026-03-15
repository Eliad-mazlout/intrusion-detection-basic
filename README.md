# 🚨 intrusion-detection-basic

Script Python de détection d'intrusion en temps réel pour serveur **Linux Debian**.  
Surveille les connexions SSH, les ports, les utilisateurs et les processus suspects.

---

## 📋 Ce que le script surveille

| Surveillance | Détail | Niveau alerte |
|---|---|---|
| 🔐 Brute-force SSH | X tentatives échouées depuis une même IP | ALERTE |
| 🌐 Ports ouverts | Nouveau port détecté entre deux cycles | ALERTE |
| 👤 Utilisateurs | Création ou suppression de compte | CRITIQUE |
| 🖥️ Connexions actives | Sessions `who` en cours | INFO |
| 🕵️ Processus suspects | nmap, hydra, netcat, sqlmap... | CRITIQUE |

---

## 🚀 Installation

```bash
git clone https://github.com/TON_USERNAME/intrusion-detection-basic.git
cd intrusion-detection-basic
sudo python3 ids.py
```

Aucune dépendance externe — uniquement la bibliothèque standard Python.

---

## ⚙️ Configuration

Modifie `config.json` pour adapter le comportement :

```json
{
    "seuil_tentatives_ssh": 5,
    "fenetre_secondes": 60,
    "ports_surveilles": [22, 80, 443, 3306, 21, 23, 3389],
    "whitelist_ip": ["127.0.0.1", "::1"],
    "intervalle_scan": 5
}
```

---

## 📊 Exemple de sortie

```
[2025-04-15 14:03:01] [INFO] IDS démarré
[2025-04-15 14:03:01] [INFO] --- Cycle #1 ---
[2025-04-15 14:03:01] [ALERTE] Brute-force SSH détecté — IP: 185.224.128.55 — 9 tentatives
[2025-04-15 14:03:06] [ALERTE] Nouveau port ouvert détecté : 3306
[2025-04-15 14:03:06] [CRITIQUE] Nouvel utilisateur créé : backdoor
[2025-04-15 14:03:11] [CRITIQUE] Processus suspect : nmap -sV 192.168.1.0/24
```

---

## 📁 Structure du projet

```
intrusion-detection-basic/
├── ids.py                          ← script principal
├── config.json                     ← configuration
├── README.md
├── logs/                           ← générés au lancement
│   ├── ids.log                     ← tous les événements
│   └── alertes.log                 ← alertes uniquement
├── exemple-alertes/
│   └── alertes.log                 ← exemple de sortie réelle
└── explication/
    ├── comment-ca-marche.md        ← fonctionnement détaillé
    └── glossaire.md                ← définitions des termes
```

---

## 🧪 Testé sur

- Debian 11 / 12
- Ubuntu 22.04 LTS
- Python 3.9+

---

## 💡 Contexte

Projet personnel développé en parallèle du **Bac Pro CIEL** et de mon stage **Technicien Systèmes & Sécurité chez GAN Assurances** (2025), où j'ai réalisé des audits de sécurité manuels sur des serveurs Linux Debian.

---

## 📬 Contact

**Eliad Mazlout** — Étudiant Bac Pro CIEL  
📧 eliad.mazlout782@gmail.com  
🔗 [LinkedIn](https://www.linkedin.com/in/eliad-mazlout-2830a33a3/)

---

## 📄 Licence

MIT
