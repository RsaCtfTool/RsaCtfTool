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
 - Gimmicky Primes method

## Usage:
usage: RsaCtfTool.py [-h] \(--publickey PUBLICKEY | --createpub\)
                         [--uncipher UNCIPHER] [--verbose] [--private] [--n N]
                         [--e E]

Mode 1 - Attack RSA (specify --publickey)
 - publickey : public rsa key to crack
 - uncipher : cipher message to decrypt
 - private : display private rsa key if recovered

Mode 2 - Create a Public Key File Given n and e (specify --createpub)
 - n - modulus
 - e - public exponent

### Uncipher file :
./RsaCtfTool.py --publickey ./key.pub --uncipher ./ciphered\_file

### Print private key :
./RsaCtfTool.py --publickey ./key.pub --private

### Generate a public key :
./RsaCtfTool.py --createpub --n 7828374823761928712873129873981723...12837182 --e 65537

#### Examples :
 - weak\_public.pub, weak\_public.cipher : weak public key
 - wiener.pub, wiener.cipher : key vulnerable to Wiener's attack
 - small\exponent.pub, small\_exponent.cipher : key with e=3, vulnerable to Hastad's attack
 - small\_q.pub, small\_q.cipher : public key with a small prime
 - close\_primes.pub, close\_primes.cipher : public key with primes suceptible to fermat factorization
 - elite\_primes.pub : public key with a gimmick prime
 - fermat.pub : public key with another vulnerability to fermat factorization

#### Requirements:
 - GMPY
 - libnum (https://github.com/hellman/libnum.git)
