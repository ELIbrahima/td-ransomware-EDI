# Chiffrement 
# Q1
L'algorithme utilisé ici est le XOR (eXclusive OR), un chiffrement symétrique assez basique. Il n'est pas considéré comme sécurisé pour plusieurs raisons :

-Dépendance à la clé : Si la clé est connue ou peut être devinée, les données sont facilement déchiffrables. La sécurité dépend entièrement de la clé, ce qui le rend vulnérable aux attaques par force brute.

-Répétition de la clé : Dans ce code, la clé est répétée pour correspondre à la longueur des données. Cela crée des motifs reconnaissables dans les données chiffrées, rendant le chiffrement sensible aux attaques basées sur les statistiques.

-Faible diffusion : Un changement dans les données d’origine affecte seulement le caractère correspondant dans le message chiffré, ce qui facilite la détection de motifs dans les données chiffrées.

En somme, XOR est trop simple pour protéger des informations sensibles, car il est vulnérable aux attaques et aux analyses de motifs.


# Generations des secrets 
# Q2
Hacher le sel et la clé directement rendrait l’algorithme plus vulnérable, car les fonctions de hachage sont rapides et peuvent être exploitées par des attaques par force brute.

Le HMAC est utilisé pour vérifier l’intégrité des données, mais ce n'est pas conçu pour dériver des clés sécurisées. En utilisant PBKDF2 avec un sel et plusieurs itérations, on renforce la sécurité : cela rend les attaques par force brute plus difficiles et empêche l’utilisation de tables arc-en-ciel pour deviner la clé.


# Setup 
# Q3 
Il est important de vérifier qu'un fichier token.bin n'est pas déjà présent pour éviter de remplacer un token existant, ce qui pourrait rendre la récupération des données impossible. Cela permet aussi d'éviter de générer et d'envoyer des éléments cryptographiques supplémentaires au CNC, économisant ainsi des ressources et limitant le risque de confusion côté serveur.


# Verifier et Utiliser la Clé
# Q4 
On vérifie la clé en effectuant une dérivation avec le sel initial. Si le résultat correspond au token stocké, cela confirme que la clé est correcte et permettra de déchiffrer les données

# Bonus 

# Voler les fichiers 
# B1
Dans la fonction leak_files, j'envoie les fichiers de la victime au serveur CNC en les encodant en Base64 pour pouvoir les transmettre via JSON. J'inclus aussi le token et le chemin original pour garder une trace précise de chaque fichier. L'objectif est de montrer à la victime que ses données sensibles ont été copiées, afin de l'inciter davantage à payer la rançon en évitant toute divulgation publique.

