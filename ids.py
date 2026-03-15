import subprocess
import time
import datetime
import os
import sys
import json
import re
from collections import defaultdict

LOG_FILE = "logs/ids.log"
ALERT_FILE = "logs/alertes.log"
CONFIG_FILE = "config.json"

default_config = {
    "seuil_tentatives_ssh": 5,
    "fenetre_secondes": 60,
    "ports_surveilles": [22, 80, 443, 3306, 21, 23, 3389],
    "whitelist_ip": ["127.0.0.1", "::1"],
    "intervalle_scan": 5
}


def charger_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    with open(CONFIG_FILE, "w") as f:
        json.dump(default_config, f, indent=4)
    return default_config


def logger(niveau, message):
    maintenant = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ligne = f"[{maintenant}] [{niveau}] {message}"
    print(ligne)
    with open(LOG_FILE, "a") as f:
        f.write(ligne + "\n")
    if niveau in ("ALERTE", "CRITIQUE"):
        with open(ALERT_FILE, "a") as f:
            f.write(ligne + "\n")


def lire_auth_log():
    chemins = ["/var/log/auth.log", "/var/log/secure"]
    for chemin in chemins:
        if os.path.exists(chemin):
            return chemin
    return None


def extraire_tentatives_ssh(chemin_log):
    tentatives = defaultdict(list)
    try:
        with open(chemin_log, "r", errors="ignore") as f:
            lignes = f.readlines()[-2000:]
        for ligne in lignes:
            if "Failed password" in ligne or "Invalid user" in ligne:
                match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', ligne)
                match_time = re.search(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', ligne)
                if match and match_time:
                    ip = match.group(1)
                    tentatives[ip].append(ligne.strip())
    except PermissionError:
        logger("ERREUR", "Permission refusée pour lire auth.log — relancer en sudo")
    return tentatives


def analyser_connexions_ssh(tentatives, config):
    seuil = config["seuil_tentatives_ssh"]
    whitelist = config["whitelist_ip"]
    for ip, lignes in tentatives.items():
        if ip in whitelist:
            continue
        if len(lignes) >= seuil:
            logger("ALERTE", f"Brute-force SSH détecté — IP: {ip} — {len(lignes)} tentatives")


def scanner_ports_ouverts():
    try:
        if sys.platform == "win32":
            result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=10)
        else:
            result = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True, timeout=10)
        return result.stdout
    except Exception:
        return ""


def analyser_ports(sortie_ss, config):
    ports_surveilles = config["ports_surveilles"]
    ports_detectes = []
    for ligne in sortie_ss.splitlines():
        for port in ports_surveilles:
            if f":{port} " in ligne or f":{port}\t" in ligne:
                if ligne not in ports_detectes:
                    ports_detectes.append((port, ligne.strip()))
    return ports_detectes


def verifier_nouveaux_utilisateurs(utilisateurs_connus):
    try:
        if sys.platform == "win32":
            result = subprocess.run(["net", "user"], capture_output=True, text=True)
            lignes = result.stdout.strip().splitlines()
            utilisateurs_actuels = set()
            for ligne in lignes[4:-2]:
                for nom in ligne.split():
                    if nom:
                        utilisateurs_actuels.add(nom)
        else:
            result = subprocess.run(
                ["awk", "-F:", '$3 >= 1000 && $3 < 65534 {print $1}', "/etc/passwd"],
                capture_output=True, text=True
            )
            utilisateurs_actuels = set(result.stdout.strip().splitlines())
        nouveaux = utilisateurs_actuels - utilisateurs_connus
        supprimes = utilisateurs_connus - utilisateurs_actuels
        return utilisateurs_actuels, nouveaux, supprimes
    except Exception:
        return utilisateurs_connus, set(), set()


def verifier_connexions_actives():
    try:
        if sys.platform == "win32":
            result = subprocess.run(["query", "session"], capture_output=True, text=True)
        else:
            result = subprocess.run(["who"], capture_output=True, text=True)
        return result.stdout.strip().splitlines()
    except Exception:
        return []


def verifier_processus_suspects():
    suspects = []
    try:
        if sys.platform == "win32":
            result = subprocess.run(["tasklist"], capture_output=True, text=True)
        else:
            result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        mots_cles = ["nmap", "nikto", "metasploit", "netcat", "nc -l", "hydra", "sqlmap"]
        for ligne in result.stdout.splitlines():
            for mot in mots_cles:
                if mot in ligne.lower() and "grep" not in ligne:
                    suspects.append(ligne.strip())
    except Exception:
        pass
    return suspects


def afficher_banniere():
    print("""
  ██╗██████╗ ███████╗
  ██║██╔══██╗██╔════╝
  ██║██║  ██║███████╗
  ██║██║  ██║╚════██║
  ██║██████╔╝███████║
  ╚═╝╚═════╝ ╚══════╝
  intrusion-detection-basic v1.0
  Eliad Mazlout — Bac Pro CIEL
    """)


def boucle_principale():
    if not os.path.exists("logs"):
        os.makedirs("logs")

    config = charger_config()
    afficher_banniere()
    logger("INFO", "IDS démarré")
    logger("INFO", f"Seuil SSH : {config['seuil_tentatives_ssh']} tentatives / {config['fenetre_secondes']}s")
    logger("INFO", f"Ports surveillés : {config['ports_surveilles']}")

    chemin_auth = lire_auth_log()
    if not chemin_auth:
        logger("WARN", "auth.log introuvable — surveillance SSH désactivée")

    utilisateurs_connus, _, _ = verifier_nouveaux_utilisateurs(set())
    ports_precedents = set()
    cycle = 0

    while True:
        cycle += 1
        logger("INFO", f"--- Cycle #{cycle} ---")

        if chemin_auth:
            tentatives = extraire_tentatives_ssh(chemin_auth)
            analyser_connexions_ssh(tentatives, config)
            total = sum(len(v) for v in tentatives.values())
            logger("INFO", f"SSH — {len(tentatives)} IP suspectes, {total} tentatives totales")

        sortie_ss = scanner_ports_ouverts()
        ports = analyser_ports(sortie_ss, config)
        ports_actuels = set(p[0] for p in ports)

        nouveaux_ports = ports_actuels - ports_precedents
        for port in nouveaux_ports:
            logger("ALERTE", f"Nouveau port ouvert détecté : {port}")

        ports_fermes = ports_precedents - ports_actuels
        for port in ports_fermes:
            logger("INFO", f"Port fermé : {port}")

        ports_precedents = ports_actuels
        logger("INFO", f"Ports ouverts surveillés actifs : {sorted(ports_actuels)}")

        utilisateurs_connus, nouveaux, supprimes = verifier_nouveaux_utilisateurs(utilisateurs_connus)
        for u in nouveaux:
            logger("CRITIQUE", f"Nouvel utilisateur créé : {u}")
        for u in supprimes:
            logger("ALERTE", f"Utilisateur supprimé : {u}")

        connexions = verifier_connexions_actives()
        logger("INFO", f"Connexions actives : {len(connexions)}")
        for c in connexions:
            logger("INFO", f"  → {c}")

        suspects = verifier_processus_suspects()
        for s in suspects:
            logger("CRITIQUE", f"Processus suspect : {s}")

        time.sleep(config["intervalle_scan"])


if __name__ == "__main__":
    if sys.platform != "win32":
        if os.geteuid() != 0:
            print("[ERREUR] Lance le script en root : sudo python3 ids.py")
            sys.exit(1)
    else:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[ERREUR] Lance le script en administrateur sur Windows")
            sys.exit(1)
    try:
        boucle_principale()
    except KeyboardInterrupt:
        print("\n[INFO] IDS arrêté.")
