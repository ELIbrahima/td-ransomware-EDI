from itertools import cycle

def retrieve_key(encrypted_data: bytes, plaintext_data: bytes) -> bytes:
    # Récupère la clé en XOR les données chiffrées avec le texte clair
    key = bytes([e ^ p for e, p in zip(encrypted_data, plaintext_data)])
    # Retourne la clé
    return key

# Chargement des fichiers
with open("fichier_chiffre.txt", "rb") as enc_file, open("fichier_clair.txt", "rb") as plain_file:
    encrypted_data = enc_file.read()
    plaintext_data = plain_file.read()

# Récupère la clé en appelant retrieve_key()
retrieved_key = retrieve_key(encrypted_data, plaintext_data)
print("Clé récupérée :", retrieved_key)
