import getpass
import re

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

# Ouvrir le fichier en mode ajout
with open("Enregistrement.txt", "a") as file:
    while True:
        email = input("Entrez votre email (ou tapez 'q' pour quitter) : ")
        if email == 'q':
            break
        while not is_valid_email(email):
            print("L'email n'est pas valide. Veuillez le ressaisir.")
            email = input("Entrez votre email : ")
        while True:
            password = getpass("Entrez votre mot de passe : ")
            if is_valid_password(password):
                file.write(f"Email: {email}, Pwd: {password}\n")
                print("Enregistrement réussi !")
                break
            else:
                print("Le mot de passe n'est pas valide. Veuillez le ressaisir.")
