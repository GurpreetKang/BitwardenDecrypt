#!/usr/bin/env python3

# Copyright (c) 2020 Gurpreet Kang
# All rights reserved.
#
# Released under the "GNU General Public License v3.0". Please see the LICENSE.
# https://github.com/GurpreetKang/BitwardenDecrypt


# BitwardenDecrypt
#
# Decrypts an encrypted Bitwarden data.json file (from the desktop App).
#
# To determine the location of the data.json file see:
# https://bitwarden.com/help/article/where-is-data-stored-computer/
#
#
# Outputs JSON containing:
#  - Logins
#  - Cards
#  - Secure Notes
#  - Identities
#  - Folders
# 
#
# Usage: ./BitwardenDecrypt.py  (reads data.json from current directory)
#        or
#        ./BitwardenDecrypt.py inputfile
# Password: (Enter Password)
#


import ast
import base64
import getpass
import json
import re
import sys


# This script depends on the 'cryptography' package
# pip install cryptography
try:
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
except ModuleNotFoundError:
    print("This script depends on the 'cryptography' package")
    print("pip install cryptography")
    exit(1)



def decodeMasterEncryptionKey(CipherString, key):
    encType     = int(CipherString.split(".")[0])   # Not Currently Used
    iv          = base64.b64decode(CipherString.split(".")[1].split("|")[0])
    ciphertext  = base64.b64decode(CipherString.split(".")[1].split("|")[1])

    unpadder    = padding.PKCS7(128).unpadder()
    cipher      = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor   = cipher.decryptor() 
    decrypted   = decryptor.update(ciphertext) + decryptor.finalize()

    try:
        cleartext = unpadder.update(decrypted) + unpadder.finalize()
    except:
        print()
        print("Wrong Password. Could Not Decode Protected Symmetric Key.")
        quit(1)

    stretchedmasterkey  = cleartext
    enc                 = stretchedmasterkey[0:32]
    mac                 = stretchedmasterkey[32:64]

    return([stretchedmasterkey,enc,mac])


def decodeCipherString(CipherString, key):
    if not CipherString:
        return(None)
    
    encType     = int(CipherString.split(".")[0])   # Not Currently Used
    iv          = base64.b64decode(CipherString.split(".")[1].split("|")[0])
    ciphertext  = base64.b64decode(CipherString.split(".")[1].split("|")[1])
    mac         = base64.b64decode(CipherString.split(".")[1].split("|")[2])    # Not Currently Used

    unpadder    = padding.PKCS7(128).unpadder()
    cipher      = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor   = cipher.decryptor() 
    decrypted   = decryptor.update(ciphertext) + decryptor.finalize()
    cleartext   = unpadder.update(decrypted) + unpadder.finalize()

    return(cleartext.decode('utf-8'))


def decryptBitwardenJSON(inputfile):
    BitwardenSecrets = {}
    decodedEntries = {}

    try:
        with open(inputfile) as f:
            datafile = json.load(f)
    except:
        print("ERROR: " + inputfile + " not found.")
        exit(1)


    BitwardenSecrets['email']           = datafile["userEmail"]
    BitwardenSecrets['kdfIterations']   = datafile["kdfIterations"]
    BitwardenSecrets['MasterPassword']  = getpass.getpass().encode("utf-8")
    BitwardenSecrets['ProtectedSymmetricKey'] = datafile["encKey"]


    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(BitwardenSecrets['email'], 'utf-8'),
        iterations=BitwardenSecrets['kdfIterations'],
        backend=default_backend()
        )
    BitwardenSecrets['MasterKey']       = kdf.derive(BitwardenSecrets['MasterPassword'])
    BitwardenSecrets['MasterKey_b64']   = base64.b64encode(BitwardenSecrets['MasterKey']).decode('utf-8')


    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"enc",
        backend=default_backend()
        )
    BitwardenSecrets['StretchedEncryptionKey']      = hkdf.derive(BitwardenSecrets['MasterKey'])
    BitwardenSecrets['StretchedEncryptionKey_b64']  = base64.b64encode(BitwardenSecrets['StretchedEncryptionKey']).decode('utf-8')

    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"mac",
        backend=default_backend()
        )
    BitwardenSecrets['StretchedMacKey']     = hkdf.derive(BitwardenSecrets['MasterKey'])
    BitwardenSecrets['StretchedMacKey_b64'] = base64.b64encode(BitwardenSecrets['StretchedMacKey']).decode('utf-8')

    BitwardenSecrets['StretchedMasterKey']      = BitwardenSecrets['StretchedEncryptionKey'] + BitwardenSecrets['StretchedMacKey']
    BitwardenSecrets['StretchedMasterKey_b64']  = base64.b64encode(BitwardenSecrets['StretchedMasterKey']).decode('utf-8')

    BitwardenSecrets['GeneratedSymmetricKey'], \
    BitwardenSecrets['GeneratedEncryptionKey'], \
    BitwardenSecrets['GeneratedMACKey']             = decodeMasterEncryptionKey(datafile["encKey"], BitwardenSecrets['StretchedEncryptionKey'] )
    BitwardenSecrets['GeneratedSymmetricKey_b64']   = base64.b64encode(BitwardenSecrets['GeneratedSymmetricKey']).decode('utf-8')
    BitwardenSecrets['GeneratedEncryptionKey_b64']  = base64.b64encode(BitwardenSecrets['GeneratedEncryptionKey']).decode('utf-8')
    BitwardenSecrets['GeneratedMACKey_b64']         = base64.b64encode(BitwardenSecrets['GeneratedMACKey']).decode('utf-8')


    regexPattern = re.compile(r"\d\.[^,]+\|[^,]+=+")

    for a in datafile:

        if a.startswith('folders_'):
            group = "folders"
        elif a.startswith('ciphers_'):
            group = "items"
        else:
            group = None


        if group:
            groupData = ast.literal_eval(str(datafile[a]))
            groupItemsList = []
    
            for b in groupData.items():
                groupEntries = json.loads(json.dumps(b))

                for c in groupEntries:
                    groupItem = json.loads(json.dumps(c))
                    
                    if type(groupItem) is dict:
                        tempString = json.dumps(c)

                        for match in regexPattern.findall(tempString):    
                            jsonEscapedString = json.JSONEncoder().encode(decodeCipherString(match, BitwardenSecrets['GeneratedEncryptionKey'])).strip("\"")
                            tempString = tempString.replace(match, jsonEscapedString)

                            # Get rid of the Bitwarden userId key/value pair.
                            userIdString = "\"userId\": \"" + datafile["userId"] + "\","
                            tempString = tempString.replace(userIdString, "")   

                        groupItemsList.append(json.loads(tempString))
                    
            decodedEntries[group] = groupItemsList

    return(decodedEntries)


def main():
    if len(sys.argv) == 2:
        inputfile = sys.argv[1]
    else:
        inputfile = "data.json"

    print(json.dumps(decryptBitwardenJSON(inputfile), indent=2))

if __name__ == "__main__":
          main()
