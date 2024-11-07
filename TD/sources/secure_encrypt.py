from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    # Généreration d' un vecteur d'initialisation (IV)
    iv = os.urandom(16)
    # Création du chiffrement AES avec le mode CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Ajout d'un padding pour s'assurer que les données sont un multiple de la taille de bloc
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Chiffrement des données
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Retourner l'IV et les données chiffrées
    return iv + encrypted_data
