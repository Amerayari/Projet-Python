import re
import os
import random
import hashlib
import bcrypt
import getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime

def is_valid_email(email):
    pattern = r'^\S+@\S+\.\S+'
    return re.match(pattern, email) is not None

def is_strong_password(password):
    return (
        len(password) == 8 and
        any(char.isupper() for char in password) and
        any(char.islower() for char in password) and
        any(char.isdigit() for char in password) and
        any(not char.isalnum() for char in password)
    )

def save_credentials(email, password):
    with open('Enregistrement.txt', 'a') as file:
        file.write(f'Email:{email}, Password:{password}\n')

def register():
    email = input("1-a. Entrez votre email : ")
    if not is_valid_email(email):
        print("Adresse e-mail invalide.")
        return

    password = getpass.getpass("1-b. Entrez votre mot de passe : ")
    if not is_strong_password(password):
        print("Le mot de passe ne respecte pas les critères.")
        return

    hashed_password = hash_password(password)
    save_credentials(email, hashed_password)
    print("Enregistrement réussi!")

def authenticate(email, password):
    with open('Enregistrement.txt', 'r') as file:
        for line in file:
            stored_email, stored_password = line.strip().split(', ')
            stored_email = stored_email.split(':')[1].strip()
            stored_password = stored_password.split(':')[1].strip()

            if email == stored_email and stored_password == hash_password(password):
                return True

    return False

def login():
    email = input("2-a. Entrez votre email : ")
    password = getpass.getpass("2-b. Entrez votre mot de passe : ")

    if authenticate(email, password):
        print("Authentification réussie!")
        menu()
    else:
        print("Les informations d'authentification sont incorrectes. Veuillez vous enregistrer.")

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_password_with_salt(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

def dictionary_attack():
    with open("dictionnaire.txt", "r") as f:
        stored_passwords = [line.strip() for line in f]

    email = input("Email de la cible : ")
    with open('Enregistrement.txt', 'r') as file:
        for line in file:
            stored_email, stored_password = line.strip().split(', ')
            stored_email = stored_email.split(':')[1].strip()
            stored_password = stored_password.split(':')[1].strip()

            if email == stored_email:
                for dictionary_password in stored_passwords:
                    if stored_password == hash_password(dictionary_password):
                        print(f"Le mot de passe est : {dictionary_password}")
                        return

    print("Le mot de passe n'a pas été trouvé dans le dictionnaire.")

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private_key.pem", "wb") as f:
        f.write(private_key)
    with open("public_key.pem", "wb") as f:
        f.write(public_key)
    print("Paires de clés RSA générées et enregistrées.")

def encrypt_message(message, public_key_path):
    with open(public_key_path, "rb") as f:
        public_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext

def decrypt_message(ciphertext, private_key_path):
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext).decode()
    return plaintext

def sign_message(message, private_key_path):
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(message, signature, public_key_path):
    with open(public_key_path, "rb") as f:
        public_key = RSA.import_key(f.read())
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def generate_self_signed_certificate():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, u'Mon certificat')]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, u'Mon certificat')]))
    builder = builder.not_valid_before(datetime.utcnow())
    builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    certificate = builder.sign(private_key, SHA256(), default_backend())

    with open("certificate.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
        f.write(private_key.export_key())

def encrypt_message_with_certificate(message, certificate_path):
    with open(certificate_path, "rb") as f:
        certificate = f.read()
    certificate = x509.load_pem_x509_certificate(certificate, default_backend())
    public_key = certificate.public_key()
    ciphertext = encrypt_message(message, public_key)
    return ciphertext

def decrypt_message_with_certificate(ciphertext, certificate_path, private_key_path):
    with open(certificate_path, "rb") as f:
        certificate = f.read()
    certificate = x509.load_pem_x509_certificate(certificate, default_backend())
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())
    public_key = certificate.public_key()
    plaintext = decrypt_message(ciphertext, private_key)
    return plaintext

def menu():
    while True:
        print("\nMenu:")
        print("A- Donnez un mot à hacher (en mode invisible)")
        print("B- Chiffrement (RSA)")
        print("C- Certificat (RSA)")
        print("X- Quitter")
        choice = input("Choisissez une option : ")
        if choice == 'A':
            print("A- Donnez un mot à hacher (en mode invisible)")
            print("a- Hacher le mot par sha256")
            print("b- Hacher le mot en générant un salt (bcrypt)")
            print("c- Attaquer par dictionnaire le mot inséré.")
            print("d- Revenir au menu principal")
            sub_choice = input("Choisissez une option : ")
            if sub_choice == 'a':
                text = getpass.getpass("Entrez le mot à hacher (invisible) : ")
                hashed_text = hash_password(text)
                print(f"Le hachage SHA-256 du texte est : {hashed_text}")
            elif sub_choice == 'b':
                text = getpass.getpass("Entrez le mot à hacher (invisible) : ")
                salted_hash = hash_password_with_salt(text)
                print(f"Le hachage bcrypt du texte est : {salted_hash.decode()}")
            elif sub_choice == 'c':
                dictionary_attack(getpass.getpass("Entrez l'email de la cible : "))
            elif sub_choice == 'd':
                continue
        elif choice == 'B':
            print("B- Chiffrement (RSA)")
            print("a- Générer les paires de clés RSA dans un fichier")
            print("b- Chiffrer un message de votre choix par RSA")
            print("c- Déchiffrer le message (b)")
            print("d- Signer un message de votre choix par RSA")
            print("e- Vérifier la signature du message (d)")
            print("f- Revenir au menu principal")
            sub_choice = input("Choisissez une option : ")
            if sub_choice == 'a':
                generate_rsa_keys()
            elif sub_choice == 'b':
                message = input("Entrez le message à chiffrer : ")
                public_key_path = input("Entrez le chemin du fichier de clé publique : ")
                ciphertext = encrypt_message(message, public_key_path)
                print(f"Message chiffré : {ciphertext}")
            elif sub_choice == 'c':
                ciphertext = input("Entrez le message chiffré : ")
                private_key_path = input("Entrez le chemin du fichier de clé privée : ")
                decrypted_message = decrypt_message(ciphertext, private_key_path)
                print(f"Message déchiffré : {decrypted_message}")
            elif sub_choice == 'd':
                message = input("Entrez le message à signer : ")
                private_key_path = input("Entrez le chemin du fichier de clé privée : ")
                signature = sign_message(message, private_key_path)
                print(f"Signature : {signature}")
            elif sub_choice == 'e':
                message = input("Entrez le message original : ")
                signature = input("Entrez la signature : ")
                public_key_path = input("Entrez le chemin du fichier de clé publique : ")
                if verify_signature(message, signature, public_key_path):
                    print("La signature est valide.")
                else:
                    print("La signature n'est pas valide.")
            elif sub_choice == 'f':
                continue
        elif choice == 'C':
            print("C- Certificat (RSA)")
            print("a- Générer un certificat autosigné par RSA")
            print("b- Chiffrer un message de votre choix par ce certificat")
            print("c- Revenir au menu principal")
            sub_choice = input("Choisissez une option : ")
            if sub_choice == 'a':
                generate_self_signed_certificate()
                print("Certificat autosigné généré et enregistré.")
            elif sub_choice == 'b':
                message = input("Entrez le message à chiffrer : ")
                certificate_path = input("Entrez le chemin du fichier de certificat : ")
                private_key_path = input("Entrez le chemin du fichier de clé privée : ")
                ciphertext = encrypt_message_with_certificate(message, certificate_path)
                print(f"Message chiffré avec le certificat : {ciphertext}")
            elif sub_choice == 'c':
                continue
        elif choice == 'X':
            break

if __name__ == "__main__":
    while True:
        print("\nMenu principal:")
        print("1- Enregistrement")
        print("2- Authentification")
        print("X- Quitter")
        choice = input("Choisissez une option : ")
        if choice == '1':
            register()
        elif choice == '2':
            login()
        elif choice == 'X':
            break
