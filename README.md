# RsaCtfTool
RSA tool for ctf - uncipher data from weak public key and try to recover private key
Automatic selection of best attack for the given public key

Attacks :
 - Weak public key factorization
 - Wiener's attack
 - Hastad's attack (Small exponent attack)
 - Small q (q<100,000)
 - Common factor between ciphertext and modulus attack
 - Fermat's factorisation for close p and q

## Usage:
usage: RsaCtfTool.py [-h] --publickey ./pub.pem [--uncipher ./cipher [--verbose]] [--private]

 - publickey : public rsa key to crack
 - uncipher : cipher message to decrypt
 - private : display private rsa key if recovered

### Uncipher file :
./RsaCtfTool.py --publickey ./key.pub --uncipher ./ciphered\_file

### Print private key :
./RsaCtfTool.py --publickey ./key.pub --private

#### Examples :
 - weak\_public.pub, weak\_public.cipher : weak public key
 - wiener.pub, wiener.cipher : key vulnerable to Wiener's attack
 - small\exponent.pub, small\_exponent.cipher : key with e=3, vulnerable to Hastad's attack

#### Requirements:
 - GMPY
 - libnum (https://github.com/hellman/libnum.git)
