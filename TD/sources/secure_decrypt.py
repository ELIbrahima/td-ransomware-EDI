from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def aes_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    # Extraire l'IV
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]

    # Créer le déchiffrer AES avec le mode CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Déchiffrer les données
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Enlever le padding
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data
