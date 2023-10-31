import re
import hashlib
import bcrypt
import rsa
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Menu une fois authentifié
while True:
    print("Menu :")
    print("A- Donnez un mot à hacher (en mode invisible)")
    print("a- Hacher le mot par SHA256")
    print("b- Hacher le mot en générant un salt (bcrypt)")
    print("c- Attaquer par dictionnaire le mot inséré")
    print("B- Chiffrement (RSA)")
    print("a- Générer les paires de clés dans un fichier")
    print("b- Chiffrer un message de votre choix par RSA")
    print("c- Déchiffrer le message (b)")
    print("d- Signer un message de votre choix par RSA")
    print("e- Vérifier la signature du message (d)")
    print("C- Certificat (RSA)")
    print("a- Générer les paires de clés dans un fichier")
    print("b- Générer un certificat autosigné par RSA")
    print("c- Chiffrer un message de votre choix par ce certificat")
    print("d- Revenir au menu principal")

    choice = input("Entrez votre choix : ")
    if choice == 'C':
        keyfile = "cert_key.pem"
        certfile = "cert.pem"

        while True:
            if choice == 'a':
                (pubkey, privkey) = rsa.newkeys(2048)
                with open(keyfile, "wb") as keyfile:
                    keyfile.write(privkey.save_pkcs1())
                print("Paires de clés générées avec succès et sauvegardées dans cert_key.pem.")
            elif choice == 'b':
                privkey = rsa.PrivateKey.load_pkcs1(privkey.save_pkcs1())
                pubkey = rsa.PublicKey.load_pkcs1(pubkey.save_pkcs1())
                cert = x509.CertificateBuilder().subject_name(x509.Name([
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Example")
                ])).issuer_name(x509.Name([
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Example")
                ])).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)).serial_number(x509.random_serial_number()).public_key(pubkey).sign(privkey, hashes.SHA256(), default_backend())
                with open(certfile, "wb") as certfile:
                    certfile.write(cert.public_bytes(serialization.Encoding.PEM))
                print("Certificat autosigné généré avec succès et sauvegardé dans cert.pem.")
            elif choice == 'c':
                cert = x509.load_pem_x509_certificate(open(certfile, "rb").read(), default_backend())
                message = input("Entrez le message à chiffrer : ")
                encrypted_message = cert.public_key().encrypt(message.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                print(f"Message chiffré : {encrypted_message.hex()}")
            elif choice == 'd':
                break
            else:
                print("Choix non valide.")
    elif choice == 'q':
        break
    else:
        print("Choix non valide.")
