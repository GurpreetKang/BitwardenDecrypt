# BitwardenDecrypt
Decrypts an encrypted [Bitwarden](https://github.com/bitwarden) data.json file (from the desktop App).

To determine the location of the data.json file see:  
https://bitwarden.com/help/article/where-is-data-stored-computer/

Outputs JSON containing:
- Logins
- Cards
- Secure Notes
- Identities
- Folders

*Note: Outputs (almost) all key/value pairs, including ones you probably don't care about.*

### Usage: 
```
./BitwardenDecrypt.py  (reads data.json from current directory)
or
./BitwardenDecrypt.py inputfile
```
On Windows:
```
py BitwardenDecrypt
or
py BitwardenDecrypt.py inputfile

Password: (Enter Password)
```
*Note: This script depends on the 'cryptography' package  
pip install cryptography*
  
  
    
## Donate
Find this useful?  If so, consider showing your appreciation. :slightly_smiling_face:  
https://paypal.me/GurpreetKang
  
<br/>

## Limitations

- No validation of the CipherString.  
I.e. No verification of the MAC before decrypting.

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
