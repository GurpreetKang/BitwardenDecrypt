#!/usr/bin/env python3

# Copyright © 2020-2021 Gurpreet Kang
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
# Note: BitwardenDecrypt does not work with Bitwarden Encrypted JSON Exports.
#       These exports lack the Protected Symmetric Key needed to decrypt entries.
#
#
# Outputs JSON containing:
#  - Logins
#  - Cards
#  - Secure Notes
#  - Identities
#  - Folders
#  - Sends (Optional)
# 
#
# Usage: ./BitwardenDecrypt.py [options] (reads data.json from current directory)
#        or
#        ./BitwardenDecrypt.py [options] inputfile
# Password: (Enter Password)
#
# Options:
#       --includesends        Include Sends in the output.


import argparse
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
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetricpadding
    from cryptography.hazmat.primitives.serialization import load_der_private_key
except ModuleNotFoundError:
    print("This script depends on the 'cryptography' package")
    print("pip install cryptography")
    sys.exit(1)

BitwardenSecrets = {}

def getBitwardenSecrets(email, password, kdfIterations, encKey, encPrivateKey):
    BitwardenSecrets['email']           = email
    BitwardenSecrets['kdfIterations']   = kdfIterations
    BitwardenSecrets['MasterPassword']  = password
    BitwardenSecrets['ProtectedSymmetricKey'] = encKey
    BitwardenSecrets['ProtectedRSAPrivateKey'] = encPrivateKey

    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(BitwardenSecrets['email'], 'utf-8'),
        iterations=BitwardenSecrets['kdfIterations'],
        backend=default_backend()
        )
    BitwardenSecrets['MasterKey']       = kdf.derive(BitwardenSecrets['MasterPassword'])
    BitwardenSecrets['MasterKey_b64']   = base64.b64encode(BitwardenSecrets['MasterKey']).decode('utf-8')


    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(BitwardenSecrets['MasterPassword']),
        iterations=1,
        backend=default_backend()
        )
    BitwardenSecrets['MasterPasswordHash']  = base64.b64encode(kdf.derive(BitwardenSecrets['MasterKey'])).decode('utf-8')


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
    BitwardenSecrets['StretchedMACKey']     = hkdf.derive(BitwardenSecrets['MasterKey'])
    BitwardenSecrets['StretchedMACKey_b64'] = base64.b64encode(BitwardenSecrets['StretchedMACKey']).decode('utf-8')

    BitwardenSecrets['StretchedMasterKey']      = BitwardenSecrets['StretchedEncryptionKey'] + BitwardenSecrets['StretchedMACKey']
    BitwardenSecrets['StretchedMasterKey_b64']  = base64.b64encode(BitwardenSecrets['StretchedMasterKey']).decode('utf-8')

    BitwardenSecrets['GeneratedSymmetricKey'], \
    BitwardenSecrets['GeneratedEncryptionKey'], \
    BitwardenSecrets['GeneratedMACKey']             = decryptProtectedSymmetricKey(BitwardenSecrets['ProtectedSymmetricKey'], BitwardenSecrets['StretchedEncryptionKey'], BitwardenSecrets['StretchedMACKey'])
    BitwardenSecrets['GeneratedSymmetricKey_b64']   = base64.b64encode(BitwardenSecrets['GeneratedSymmetricKey']).decode('utf-8')
    BitwardenSecrets['GeneratedEncryptionKey_b64']  = base64.b64encode(BitwardenSecrets['GeneratedEncryptionKey']).decode('utf-8')
    BitwardenSecrets['GeneratedMACKey_b64']         = base64.b64encode(BitwardenSecrets['GeneratedMACKey']).decode('utf-8')


    BitwardenSecrets['RSAPrivateKey'] = decryptRSAPrivateKey(BitwardenSecrets['ProtectedRSAPrivateKey'], \
                                                            BitwardenSecrets['GeneratedEncryptionKey'], \
                                                            BitwardenSecrets['GeneratedMACKey'])

    return



def decryptProtectedSymmetricKey(CipherString, masterkey, mastermac):
    encType     = int(CipherString.split(".")[0])   # Not Currently Used, Assuming EncryptionType: 2
    iv          = base64.b64decode(CipherString.split(".")[1].split("|")[0])
    ciphertext  = base64.b64decode(CipherString.split(".")[1].split("|")[1])
    mac         = base64.b64decode(CipherString.split(".")[1].split("|")[2])


    # Calculate CipherString MAC
    h = hmac.HMAC(mastermac, hashes.SHA256(), backend=default_backend())
    h.update(iv)
    h.update(ciphertext)
    calculatedMAC = h.finalize()
    
    if mac != calculatedMAC:
        print("ERROR: MAC did not match. Protected Symmetric Key was not decrypted.")
        sys.exit(1)


    unpadder    = padding.PKCS7(128).unpadder()
    cipher      = Cipher(algorithms.AES(masterkey), modes.CBC(iv), backend=default_backend())
    decryptor   = cipher.decryptor() 
    decrypted   = decryptor.update(ciphertext) + decryptor.finalize()

    try:
        cleartext = unpadder.update(decrypted) + unpadder.finalize()
    except Exception as e:
        print()
        print("Wrong Password. Could Not Decode Protected Symmetric Key.")
        sys.exit(1)

    stretchedmasterkey  = cleartext
    enc                 = stretchedmasterkey[0:32]
    mac                 = stretchedmasterkey[32:64]

    return([stretchedmasterkey,enc,mac])


def decryptRSAPrivateKey(CipherString, key, mackey):
    if not CipherString:
        return(None)

    
    encType     = int(CipherString.split(".")[0])   # Not Currently Used, Assuming EncryptionType: 2
    iv          = base64.b64decode(CipherString.split(".")[1].split("|")[0])
    ciphertext  = base64.b64decode(CipherString.split(".")[1].split("|")[1])
    mac         = base64.b64decode(CipherString.split(".")[1].split("|")[2])


    # Calculate CipherString MAC
    h = hmac.HMAC(mackey, hashes.SHA256(), backend=default_backend())
    h.update(iv)
    h.update(ciphertext)
    calculatedMAC = h.finalize()

    if mac == calculatedMAC:       
        unpadder    = padding.PKCS7(128).unpadder()
        cipher      = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor   = cipher.decryptor() 
        decrypted   = decryptor.update(ciphertext) + decryptor.finalize()
        cleartext   = unpadder.update(decrypted) + unpadder.finalize()

        return(cleartext)

    else:
        return("ERROR: MAC did not match. RSA Private Key not decrypted.")



def decryptCipherString(CipherString, key, mackey):
    if not CipherString:
        return(None)

    
    encType     = int(CipherString.split(".")[0])   # Not Currently Used, Assuming EncryptionType: 2
    iv          = base64.b64decode(CipherString.split(".")[1].split("|")[0])
    ciphertext  = base64.b64decode(CipherString.split(".")[1].split("|")[1])
    mac         = base64.b64decode(CipherString.split(".")[1].split("|")[2])


    # Calculate CipherString MAC
    h = hmac.HMAC(mackey, hashes.SHA256(), backend=default_backend())
    h.update(iv)
    h.update(ciphertext)
    calculatedMAC = h.finalize()

    if mac == calculatedMAC:
        unpadder    = padding.PKCS7(128).unpadder()
        cipher      = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor   = cipher.decryptor() 
        decrypted   = decryptor.update(ciphertext) + decryptor.finalize()
        cleartext   = unpadder.update(decrypted) + unpadder.finalize()

        try:
            cleartext = cleartext.decode('utf-8')
        except UnicodeDecodeError as e:
            try:
                # Try to decrypt CipherString as an Attachment Protected Symmetric Key
                cleartext = decryptProtectedSymmetricKey(CipherString, BitwardenSecrets['GeneratedEncryptionKey'], BitwardenSecrets['GeneratedMACKey'])[0].hex()
            except Exception as e:
                cleartext = f"ERROR decrypting: {CipherString}"

        
        return(cleartext)

    else:
        return("ERROR: MAC did not match. CipherString not decrypted.")


def decryptRSA(CipherString, key):
    encType     = int(CipherString.split(".")[0])   # Not Currently Used, Assuming EncryptionType: 4
    ciphertext  = base64.b64decode(CipherString.split(".")[1].split("|")[0])
    private_key = load_der_private_key(key, password=None, backend=default_backend())

    cleartext = private_key.decrypt(ciphertext, asymmetricpadding.OAEP(mgf=asymmetricpadding.MGF1(algorithm=hashes.SHA1()), \
                                                                        algorithm=hashes.SHA1(), \
                                                                        label=None))

    return(cleartext)

def decryptSend(send):
    sendKey = decryptProtectedSymmetricKey(send['key'], BitwardenSecrets['GeneratedEncryptionKey'], BitwardenSecrets['GeneratedMACKey'])[0]
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=b"bitwarden-send",
        info=b"send",
        backend=default_backend()
        )
    sendStretchedKey = hkdf.derive(sendKey)
    sendEncKey = sendStretchedKey[0:32]
    sendMACKey = sendStretchedKey[32:64]

    send['key'] = sendStretchedKey.hex()
    decryptedSend = json.dumps(send)

    regexPattern = re.compile(r"\d\.[^,]+\|[^,]+=+")
    
    for match in regexPattern.findall(decryptedSend):    
        jsonEscapedString = json.JSONEncoder().encode(decryptCipherString(match, sendEncKey, sendMACKey))
        jsonEscapedString = jsonEscapedString[1:(len(jsonEscapedString)-1)]
        decryptedSend = decryptedSend.replace(match, jsonEscapedString)

    return(decryptedSend)


def decryptBitwardenJSON(options):
    decryptedEntries = {}

    try:
        with open(options.inputfile) as f:
            datafile = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: {options.inputfile} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: An error occured reading: {options.inputfile}")
        sys.exit(1)

    getBitwardenSecrets(datafile["$profile-var?"]["profile"]["email"], \
        getpass.getpass().encode("utf-8"), \
        datafile["$profile-var?"]["profile"]["kdfIterations"], \
        datafile['$profile-var?']['keys']['cryptoSymmetricKey']['encrypted'], \
        datafile['$profile-var?']['keys']['privateKey']['encrypted']    )


    BitwardenSecrets['OrgSecrets'] = {}
    encOrgKeys = list(datafile["encOrgKeys"])

    for i in encOrgKeys:
        BitwardenSecrets['OrgSecrets'][i] = decryptRSA(datafile["encOrgKeys"][i], BitwardenSecrets['RSAPrivateKey'])

    
    regexPattern = re.compile(r"\d\.[^,]+\|[^,]+=+")
    
    for a in datafile:

        if a.startswith('folders_'):
            group = "folders"
        elif a.startswith('ciphers_'):
            group = "items"
        elif a.startswith('organizations_'):
            group = "organizations"
        elif a.startswith('collections_'):
            group = "collections"
        elif a.startswith('sends_') and options.includesends == True:
            group = "sends"
        else:
            group = None


        if group:
            groupData = json.loads(json.dumps(datafile[a]))
            groupItemsList = []
    
            for b in groupData.items():
                groupEntries = json.loads(json.dumps(b))

                for c in groupEntries:
                    groupItem = json.loads(json.dumps(c))
                    
                    if type(groupItem) is dict:
                        tempString = json.dumps(groupItem)

                        if group == "sends":
                            tempString = decryptSend(groupItem)  

                        else:
                            try:
                                if groupItem.get('organizationId') is None:
                                    encKey = BitwardenSecrets['GeneratedEncryptionKey']
                                    macKey = BitwardenSecrets['GeneratedMACKey']
                                else:
                                    encKey = BitwardenSecrets['OrgSecrets'][groupItem['organizationId']][0:32]
                                    macKey = BitwardenSecrets['OrgSecrets'][groupItem['organizationId']][32:64]

                                for match in regexPattern.findall(tempString):    
                                    jsonEscapedString = json.JSONEncoder().encode(decryptCipherString(match, encKey, macKey))
                                    jsonEscapedString = jsonEscapedString[1:(len(jsonEscapedString)-1)]
                                    #nothing gets printed, maybe regex doesn't match?
                                    print(match,jsonEscapedString)
                                    tempString = tempString.replace(match, jsonEscapedString)

                            except Exception as e:
                                print(f"ERROR: Could Not Determine encKey/macKey for: {groupItem.get('id')}")                        
                        

                        # Get rid of the Bitwarden userId key/value pair.
                        userIdString = f"\"userId\": \"{datafile['userId']}\","
                        tempString = tempString.replace(userIdString, "")   

                        groupItemsList.append(json.loads(tempString))
                    
            decryptedEntries[group] = groupItemsList

    return(json.dumps(decryptedEntries, indent=2, ensure_ascii=False))


def main(options):
    decryptedJSON = decryptBitwardenJSON(options)
    print(decryptedJSON)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(allow_abbrev=False, description='Decrypts an encrypted Bitwarden data.json file.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("inputfile", nargs='?', default="data.json", help='INPUTFILE (optional)')
    parser.add_argument("--includesends", help="Include Sends in the output.", action="store_true", default=False)
    args = parser.parse_args()

    main(args)
