# RsaCtfTool
RSA tool for ctf - uncipher data from weak public key

Attacks :
 - Weak public key factorization
 - Wiener'a attack
 - Small exponent attack

## Usage:
usage: RsaCtfTool.py [-h] --publickey ./pub.pem --uncipher ./cipher [--verbose]

### Uncipher file :
./RsaCtfTool.py --publickey ./weak\_public\_key.pem --uncipher ./ciphered\_file
