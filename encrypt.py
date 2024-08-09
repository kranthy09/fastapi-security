import os
import sys

from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = "XvYvP_c4gBDLCLbjgz6Hc47ND_BcoMYt3Cz5pAKx1qQ="

FERNET = Fernet(SECRET_KEY)

if len(sys.argv) > 1 and sys.argv[1] == "decrypt":
    with open("pw.txt") as f:
        stored_password = f.read()

    stored_dec_password = FERNET.decrypt(stored_password).decode()
    print(f"Decrypted Password: {stored_dec_password}")
else:
    new_password = input("New Password: ")
    new_enc_password = FERNET.encrypt(new_password.encode()).decode()

    with open("pw.txt", "w") as f:
        f.write(new_enc_password)

    print(f"Encrypted Password Stored: {new_enc_password}")
