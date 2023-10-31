import re
import hashlib
import bcrypt
import rsa

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
    print("f- Revenir au menu principal")

    choice = input("Entrez votre choix : ")
    if choice == 'B':
        keyfile = "rsa_key.txt"

        while True:
            if choice == 'a':
                (pubkey, privkey) = rsa.newkeys(512)
                with open(keyfile, "w") as keyfile:
                    keyfile.write(privkey.save_pkcs1())
                    keyfile.write(pubkey.save_pkcs1())
                print("Paires de clés générées avec succès et sauvegardées dans rsa_key.txt.")
            elif choice == 'b':
                message = input("Entrez le message à chiffrer : ")
                pubkey = rsa.PublicKey.load_pkcs1(pubkey.save_pkcs1())
                encrypted_message = rsa.encrypt(message.encode(), pubkey)
                print(f"Message chiffré : {encrypted_message}")
            elif choice == 'c':
                encrypted_message = input("Entrez le message chiffré : ")
                privkey = rsa.PrivateKey.load_pkcs1(privkey.save_pkcs1())
                decrypted_message = rsa.decrypt(encrypted_message, privkey)
                print(f"Message déchiffré : {decrypted_message.decode()}")
            elif choice == 'd':
                message = input("Entrez le message à signer : ")
                privkey = rsa.PrivateKey.load_pkcs1(privkey.save_pkcs1())
                signature = rsa.sign(message.encode(), privkey, 'SHA-1')
                print(f"Signature du message : {signature}")
            elif choice == 'e':
                message = input("Entrez le message original : ")
                signature = input("Entrez la signature : ")
                pubkey = rsa.PublicKey.load_pkcs1(pubkey.save_pkcs1())
                try:
                    rsa.verify(message.encode(), signature, pubkey)
                    print("La signature est valide.")
                except rsa.pkcs1.VerificationError:
                    print("La signature n'est pas valide.")
            elif choice == 'f':
                break
            else:
                print("Choix non valide.")
    elif choice == 'q':
        break
    else:
        print("Choix non valide.")
