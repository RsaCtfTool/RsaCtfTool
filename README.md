# RsaCtfTool
RSA tool for ctf - uncipher data from weak public key

Attacks :
 - Weak public key factorization
 - Wiener'a attack
 - Small exponent attack

# WORK IN PROGRESS !
 - Wiener not fully implemented

## Usage:
usage: RsaCtfTool.py [-h] --publickey ./pub.pem --uncipher ./cipher [--verbose]

### Uncipher file :
./RsaCtfTool.py --publickey ./weak\_public\_key.pem --uncipher ./ciphered\_file

#### Requirements:
 - GMPY
 - libnum (https://github.com/hellman/libnum.git)
