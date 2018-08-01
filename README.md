# RsaCtfTool
RSA tool for ctf - uncipher data from weak public key and try to recover private key
Automatic selection of best attack for the given public key

Attacks :
 - Weak public key factorization
 - Wiener's attack
 - Hastad's attack (Small public exponent attack)
 - Small q (q < 100,000)
 - Common factor between ciphertext and modulus attack
 - Fermat's factorisation for close p and q
 - Gimmicky Primes method
 - Past CTF Primes method
 - Self-Initializing Quadratic Sieve (SIQS) using Yafu
 - Common factor attacks across multiple keys
 - Small fractions method when p/q is close to a small fraction
 - Boneh Durfee Method when the private exponent d is too small compared to the modulus (i.e d < n^0.292)
 - Elliptic Curve Method
 - Pollards p-1 for relatively smooth numbers
 - Mersenne primes factorization

## Usage:
usage: RsaCtfTool.py [-h] [--publickey PUBLICKEY] [--createpub] [--dumpkey]
                     [--uncipherfile UNCIPHERFILE] [--uncipher UNCIPHER]
                     [--verbose] [--private] [--ecmdigits ECMDIGITS] [-n N]
                     [-p P] [-q Q] [-e E] [--key KEY]
                     [--attack {hastads,factordb,pastctfprimes,mersenne_primes,noveltyprimes,smallq,wiener,comfact_cn,primefac,fermat,siqs,Pollard_p_1,all}]


Mode 1 - Attack RSA (specify --publickey)
 - publickey : public rsa key to crack. You can import multiple public keys with wildcards.
 - uncipher : cipher message to decrypt
 - private : display private rsa key if recovered

Mode 2 - Create a Public Key File Given n and e (specify --createpub)
 - n - modulus
 - e - public exponent

Mode 3 - Dump the public and/or private numbers from a PEM/DER format public or private key (specify --dumpkey)
 - key - the public or private key in PEM or DER format

### Uncipher file :
`./RsaCtfTool.py --publickey ./key.pub --uncipherfile ./ciphered\_file`

### Print private key :
`./RsaCtfTool.py --publickey ./key.pub --private`

### Attempt to break multiple public keys with common factor attacks or individually - use quotes around wildcards to stop bash expansion
`./RsaCtfTool.py --publickey "*.pub" --private`

### Generate a public key :
`./RsaCtfTool.py --createpub -n 7828374823761928712873129873981723...12837182 -e 65537`

### Dump the parameters from a key:
`./RsaCtfTool.py --dumpkey --key ./key.pub`

### Factor with ECM when you know the approximate length in digits of a prime:
`./RsaCtfTool.py --publickey key.pub --ecmdigits 25 --verbose --private`

#### Examples :
 - weak\_public.pub, weak\_public.cipher : weak public key
 - wiener.pub, wiener.cipher : key vulnerable to Wiener's attack
 - small\_exponent.pub, small\_exponent.cipher : key with e=3, vulnerable to Hastad's attack
 - small\_q.pub, small\_q.cipher : public key with a small prime
 - close\_primes.pub, close\_primes.cipher : public key with primes suceptible to fermat factorization
 - elite\_primes.pub : public key with a gimmick prime
 - fermat.pub : public key with another vulnerability to fermat factorization
 - pastctfprimes.pub : public key with a prime from a past CTF
 - siqs.pub: 256bit public key that is factored in 30 seconds with SIQS
 - factordb_parsing.pub: a public key with a prime that is described as an expression on factordb.com
 - smallfraction.pub: a public key where p/q is close to a small fraction
 - boneh\_durfee.pub: a public key factorable using boneh\_durfee method
 - multikey-0.pub and multikey-1.pub: Public keys that share a common factor
 - ecm_method.pub: Public key with a 25 digit prime factorable with ECM method in around 2 minutes (use --ecmdigits 25 to test)

#### Requirements:
 - GMPY2
 - SymPy
 - PyCrypto
 - Requests
 - SageMath - optional but advisable
### Ubuntu 18.04 and Kali specific Instructions ###
git clone https://github.com/Ganapati/RsaCtfTool.git
sudo apt-get install libgmp3-dev libmpc-dev
pip install -r "requirements.txt"
python2.7 RsaCtfTool.py

### MacOS-specific Instructions
If `pip install -r "requirements.txt"` fails to install requirements accessible within environment, the following command may work.

`` easy_install `cat requirements.txt` ``

#### Todo
 - Implement multiple ciphertext handling for more attacks (Common modulus attack)
 - Implement support for MultiPrime RSA (see 0ctf 2016)
 - Possibly implement Msieve support...
 - Some kind of polynomial search...
 - Brainstorm moar attack types!
 - Saw a CTF where the supplied N was a 2048 bit prime. Detect this and solve using phi = (n - 1) * (n - 1) which seemed to work for that CTF
 - Replicate all functionality of rsatool.py
 - Support more types of expression based primes from factordb.com?
