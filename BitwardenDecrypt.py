#!/usr/bin/env python3

# Copyright © 2020-2022 Gurpreet Kang
# All rights reserved.
#
# Released under the "GNU General Public License v3.0". Please see the LICENSE.
# https://github.com/GurpreetKang/BitwardenDecrypt


# BitwardenDecrypt
#
# Decrypts an encrypted Bitwarden data.json file (from the Desktop App).
#
# To determine the location of the data.json file see:
# https://bitwarden.com/help/data-storage/#on-your-local-machine
#
# Note: BitwardenDecrypt does not work with Bitwarden Encrypted JSON Exports.
#       These exports lack the Protected Symmetric Key needed to decrypt entries.
#       Password Protected Encrypted JSON Exports are supported.
#
#       Attachments are not supported (they are not stored locally in data.json).
#
#
# Outputs JSON containing:
#  - Logins
#  - Folders
#  - Organizations
#  - Collections
#  - Cards
#  - Secure Notes
#  - Identities
#  - Sends (Optional)
# 
#
# Usage: ./BitwardenDecrypt.py [options] (reads data.json from current directory)
#        or
#        ./BitwardenDecrypt.py [options] inputfile
# Password: (Enter Password)
#
# Options:
#       --includesends          Include Sends in the output.
#       --output OUTPUTFILE     Write decrypted output to file.
#                               Will overwrite contents if file exists.

import argparse
import base64
from   collections import OrderedDict
import getpass
import json
import os
import re
import sys
import uuid


# This script depends on the 'cryptography' package
# pip install cryptography
try:
    from cryptography.hazmat.backends                   import default_backend
    from cryptography.hazmat.primitives                 import ciphers, kdf, hashes, hmac, padding
    from cryptography.hazmat.primitives.kdf.pbkdf2      import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.hkdf        import HKDF, HKDFExpand
    from cryptography.hazmat.primitives.ciphers         import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric      import rsa, padding as asymmetricpadding
    from cryptography.hazmat.primitives.serialization   import load_der_private_key

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
    if encType != 2:
        print(f"ERROR: Protected Symmetric Key was not decrypted. Unsupported EncryptionType: {encType}\n\n"
              "Rotating your account encryption key should resolve this for future backups of data.json.\n"
              "Unfortunately a new sync/backup will be required after rotaion. \n\n\n"
              "https://bitwarden.com/help/account-encryption-key/#rotate-your-encryption-key")
        exit(1)

    iv          = base64.b64decode(CipherString.split(".")[1].split("|")[0])
    ciphertext  = base64.b64decode(CipherString.split(".")[1].split("|")[1])
    mac         = base64.b64decode(CipherString.split(".")[1].split("|")[2])



    # Calculate CipherString MAC
    h = hmac.HMAC(mastermac, hashes.SHA256(), backend=default_backend())
    h.update(iv)
    h.update(ciphertext)
    calculatedMAC = h.finalize()
    
    if mac != calculatedMAC:
        print("ERROR: MAC did not match. Protected Symmetric Key was not decrypted. (Password may be wrong)")
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
                cleartext = f"ERROR Decrypting: {CipherString}"

        
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

def isUUID(value):
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False

def checkFileFormatVersion(options):

    options.account = {}
    email = None
    kdfIterations = None
    encKey = None
    encPrivateKey = None

    try:
        with open(options.inputfile) as f:
            datafile = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: {options.inputfile} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: An error occurred reading: {options.inputfile}")
        sys.exit(1)
    

    # Check if datafile is a password protected excrypted json export.
    if datafile.get("encrypted") and datafile.get("passwordProtected"):
        options.fileformat = "EncryptedJSON"

        # Email address is used as the salt in data.json, in password protected excrypted json exports there is an explicit salt key/value (and no email).
        email = datafile.get("salt")
        kdfIterations = int(datafile.get("kdfIterations"))
        encKey = datafile.get("encKeyValidation_DO_NOT_EDIT")

    # Check if data.json is new/old format.
    elif datafile.get("userEmail") is None:
        options.fileformat = "NEW"
        accounts = []

        for a in datafile:
            if isUUID(a) and bool(datafile[a]['profile']):
                options.account['UUID'] = a
                options.account['email'] = datafile[a]['profile']['email']

                accounts.append((options.account['UUID'], options.account['email']))
        
        # If data.json contains multiple accounts, prompt to select which to decrypt.
        if (len(accounts) > 1):
            print("Which Account Would You Like To Decrypt?")

            for index, account in enumerate(accounts):
                print(f" {index+1}:\t{account[1]}")
            
            choice = 0
            print()
            while (choice < 1 ) or (choice > len(accounts) ):
                print("Enter Number: ", end="")
                try:
                    choice = int(input())
                except ValueError:
                    choice = 0
            print()
            
            options.account['UUID'] = accounts[choice-1][0]
            options.account['email'] = accounts[choice-1][1]

        email = options.account['email']
        kdfIterations = datafile[options.account['UUID']]['profile']['kdfIterations']
        encKey = datafile[options.account['UUID']]['keys']['cryptoSymmetricKey']['encrypted']
        encPrivateKey = datafile[options.account['UUID']]['keys']['privateKey']['encrypted']

    else:
        options.fileformat = "OLD"
        options.account['UUID'] = datafile.get("userId")
        options.account['email'] = datafile.get("userEmail")

        email = datafile.get("userEmail")
        kdfIterations = datafile.get("kdfIterations")
        encKey = datafile.get("encKey")
        encPrivateKey = datafile.get("encPrivateKey")

    f.close()

    return email, kdfIterations, encKey, encPrivateKey


def decryptBitwardenJSON(options):
    decryptedEntries = OrderedDict()

    try:
        with open(options.inputfile) as f:
            datafile = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: {options.inputfile} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: An error occurred reading: {options.inputfile}")
        sys.exit(1)


    email, kdfIterations, encKey, encPrivateKey = checkFileFormatVersion(options)

    # Set prompt text for when entering password.
    prompt_text = "EncryptedJSON" if options.fileformat == "EncryptedJSON" else email

    getBitwardenSecrets(email, \
        getpass.getpass(prompt = f"Enter Password ({prompt_text}):").encode("utf-8"), \
        kdfIterations, \
        encKey, \
        encPrivateKey)


    BitwardenSecrets['OrgSecrets'] = {}
    
    # RegEx to find CipherString
    regexPattern = re.compile(r"\d\.[^,]+\|[^,]+=+")

    if (options.fileformat == "EncryptedJSON"):
        EncryptedJSON = datafile.get("data")

        encKey = BitwardenSecrets['StretchedEncryptionKey']
        macKey = BitwardenSecrets['StretchedMACKey']

        decryptedEntries = OrderedDict(json.loads(decryptCipherString(EncryptedJSON, encKey, macKey)))

    
    elif (options.fileformat == "NEW"):
        # data.json file format changed in v1.30+

        datafile = datafile[options.account['UUID']]
        organizationKeys = datafile['keys']['organizationKeys']['encrypted']

        # Get/Decrypt All Organization Keys
        for uuid, value in organizationKeys.items():
            # File Format >= Desktop 2022.8.0
            if type(value) is dict:
                BitwardenSecrets['OrgSecrets'][uuid] = decryptRSA(value['key'], BitwardenSecrets['RSAPrivateKey'])
            # File Format < Desktop 2022.8.0
            elif type(value) is str:
                BitwardenSecrets['OrgSecrets'][uuid] = decryptRSA(value, BitwardenSecrets['RSAPrivateKey'])
            else:
                print(f"ERROR: Could Not Determine Organization Keys From File Format")


        for a in datafile['data']:

            supportedGroups = ['folders', 'ciphers', 'collections', 'organizations']

            if (any(x in a for x in supportedGroups)):
                group = a
            elif a == "sends" and options.includesends == True:
                group = "sends"
            else:
                group = None
            

            if group:

                if group == "organizations":
                    groupData = datafile['data'][group]
                else:
                    groupData = datafile['data'][group]['encrypted']
                
                groupItemsList = []
            
                for b in groupData.items():
                    groupEntries = list(b)

                    for groupItem in groupEntries:

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
                                        tempString = tempString.replace(match, jsonEscapedString)

                                except Exception as e:
                                    print(f"ERROR: Could Not Determine encKey/macKey for: {groupItem.get('id')}")

                            # Get rid of the Bitwarden userId key/value pair.
                            userIdString = f"\"userId\": \"{options.account['UUID']}\","
                            tempString = tempString.replace(userIdString, "")   

                            groupItemsList.append(json.loads(tempString))

                    # Bitwarden Apps export "ciphers" as "items", changed here to be consistent.
                    if (group == "ciphers"):
                        group = "items"

                    decryptedEntries[group] = groupItemsList

    # old data.json file format
    else:

        # Get/Decrypt All Organization Keys
        encOrgKeys = list(datafile["encOrgKeys"])

        for i in encOrgKeys:
            BitwardenSecrets['OrgSecrets'][i] = decryptRSA(datafile["encOrgKeys"][i], BitwardenSecrets['RSAPrivateKey'])

        for a in datafile:

            if a.startswith('folders_'):
                group = "folders"
            elif a.startswith('ciphers_'):
                # Bitwarden Apps export "ciphers" as "items", changed here to be consistent.
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
                groupData = datafile[a]
                groupItemsList = []
        
                for b in groupData.items():
                    groupEntries = list(b)

                    for groupItem in groupEntries:
                        
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
                                        tempString = tempString.replace(match, jsonEscapedString)

                                except Exception as e:
                                    print(f"ERROR: Could Not Determine encKey/macKey for: {groupItem.get('id')}")          
                            

                            # Get rid of the Bitwarden userId key/value pair.
                            userIdString = f"\"userId\": \"{datafile['userId']}\","
                            tempString = tempString.replace(userIdString, "")   

                            groupItemsList.append(json.loads(tempString))
                        
                decryptedEntries[group] = groupItemsList

    # Bitwarden exports always have "folders" first, not sure if it makes a difference for re-import.
    if(decryptedEntries.get('folders')):
        decryptedEntries.move_to_end('folders', False)
    
    # Move Sends to end.
    if(decryptedEntries.get('sends')):
        decryptedEntries.move_to_end('sends')

    return(json.dumps(decryptedEntries, indent=2, ensure_ascii=False))


def main(options):
    print()
    if (options.outputfile):
        if os.path.isfile(options.outputfile):
            print(f"Saving Output To: {options.outputfile} (File Exists, Will Be Overwritten)\n")
        else:
            print(f"Saving Output To: {options.outputfile}\n")
    
    decryptedJSON = decryptBitwardenJSON(options)

    if (options.outputfile):
        try:
            with open(options.outputfile, "w") as file:
                file.write(decryptedJSON)
        except:
            print(f"ERROR: Writing to {options.outputfile}")
    else:
        print(decryptedJSON)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(allow_abbrev=False, description='Decrypts an encrypted Bitwarden data.json file.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("inputfile", nargs='?', default="data.json", help='INPUTFILE')
    parser.add_argument("--includesends", help="Include Sends in the output.", action="store_true", default=False)
    parser.add_argument("--output", metavar='OUTPUTFILE', action="store", dest='outputfile', help='Saves decrypted output to OUTPUTFILE')
    args = parser.parse_args()

    main(args)
