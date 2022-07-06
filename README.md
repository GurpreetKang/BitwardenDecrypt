# BitwardenDecrypt
Decrypts an encrypted [Bitwarden](https://github.com/bitwarden) data.json file (from the Desktop App).  
You can safely store data.json as an encrypted, offline backup of your vault knowing you will always be able to decrypt it.

To determine the location of the data.json file see:  
https://bitwarden.com/help/data-storage/#on-your-local-machine

*Note: BitwardenDecrypt does not work with Bitwarden Encrypted JSON Exports.<br/>
These exports lack the Protected Symmetric Key needed to decrypt entries.*

<br/>

Outputs JSON containing:
- Logins
- Folders
- Organizations
- Collections
- Cards
- Secure Notes
- Identities
- Sends *(Optional)*

*Note: Outputs (almost) all key/value pairs, including ones you probably don't care about.*

### Usage: 
```
./BitwardenDecrypt.py [options]  (reads data.json from current directory)
or
./BitwardenDecrypt.py [options] inputfile

Password: (Enter Password)

Options:
        --includesends          Include Sends in the output.
        --output OUTPUTFILE     Write decrypted output to file.
                                Will overwrite contents if file exists.
```
On Windows:
```
py BitwardenDecrypt.py [options]
or
py BitwardenDecrypt.py [options] inputfile

Password: (Enter Password)

Options:
        --includesends          Include Sends in the output.
        --output OUTPUTFILE     Write decrypted output to file.
                                Will overwrite contents if file exists.
```
*Note: This script depends on the 'cryptography' package  
pip install cryptography*
  
  
    
## Donate
Find this useful?  If so, consider showing your appreciation. :slightly_smiling_face:  
https://paypal.me/GurpreetKang
  
<br/>

## Limitations

- Does not work with Bitwarden Encrypted JSON Exports.
<br/>*These exports lack the Protected Symmetric Key needed to decrypt entries.*
- ~~No validation of the CipherString.
I.e. No verification of the MAC before decrypting.~~ Now verifies the MAC.
- Can only decrypt EncryptionType: 2 (AesCbc256_HmacSha256_B64).  At the time of writing this is the default used for all entries in the personal vault.
- ~~Does not decrypt anything from a Collection (Organization).~~<br/>Initial support for decrypting items from a Collection (Organization). This adds support for decrypting EncryptionType: 4 (Rsa2048_OaepSha1_B64)


## To Do
[ ] Nothing.
Hopefully Bitwarden will implement an [encrypted export](https://community.bitwarden.com/t/encrypted-export/235) and this script can become obsolete.


## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details


## Acknowledgments

* [Kyle Spearrin](https://github.com/kspearrin) for creating [Bitwarden](https://github.com/bitwarden).
* Joshua Stein ([Rubywarden](https://github.com/jcs/rubywarden)) for the reverse engineered Bitwarden documentation.

#  
This project is not associated with [Bitwarden](https://github.com/bitwarden) or [Bitwarden, Inc.](https://bitwarden.com/)
