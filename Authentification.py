import re
import hashlib
import bcrypt

# Fonction pour vérifier si l'email est valide
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

# Fonction pour vérifier si le mot de passe est valide
def is_valid_password(password):
    if (len(password) == 8 and
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password) and
        any(not c.isalnum() for c in password)):
        return True
    return False

# Fonction pour vérifier les identifiants dans le fichier d'enregistrement
def authenticate(email, password):
    with open("Enregistrement.txt", "r") as file:
        for line in file:
            if f"Email: {email}, Pwd: {password}" in line:
                return True
    return False

# Authentification
while True:
    email = input("Entrez votre email (ou tapez 'q' pour quitter) : ")
    if email == 'q':
        break
    while not is_valid_email(email):
        print("L'email n'est pas valide. Veuillez le ressaisir.")
        email = input("Entrez votre email : ")
    password = input("Entrez votre mot de passe : ")
    if authenticate(email, password):
        print("Authentification réussie !")
        # Menu une fois authentifié
        while True:
            print("Menu :")
            print("A- Donnez un mot à hacher (en mode invisible)")
            print("a- Hacher le mot par sha256")
            print("b- Hacher le mot en générant un salt (bcrypt)")
            print("c- Attaquer par dictionnaire le mot inséré")
            print("d- Revenir au menu principal")
            choice = input("Entrez votre choix : ")
            if choice == 'A':
                word = input("Entrez le mot à hacher : ")
                # Implémentez ici les options pour le hachage par sha256 et bcrypt
                if choice == 'a':
                    hashed = hashlib.sha256(word.encode()).hexdigest()
                    print(f"Mot haché (SHA256) : {hashed}")
                elif choice == 'b':
                    salt = bcrypt.gensalt()
                    hashed = bcrypt.hashpw(word.encode(), salt)
                    print(f"Mot haché (bcrypt) : {hashed}")
                # Ajoutez d'autres options ici
                elif choice == 'd':
                    break
                else:
                    print("Choix non valide.")
            elif choice == 'q':
                break
            else:
                print("Choix non valide.")
    else:
        print("Identifiants incorrects. Veuillez vous enregistrer.")
