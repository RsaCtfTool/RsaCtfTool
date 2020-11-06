# RsaCtfTool

![lint_python](https://github.com/Ganapati/RsaCtfTool/workflows/lint_python/badge.svg)
[![GitHub issues](https://img.shields.io/github/issues/Ganapati/RsaCtfTool.svg)](https://github.com/Ganapati/RsaCtfTool/issues)
[![GitHub forks](https://img.shields.io/github/forks/Ganapati/RsaCtfTool.svg)](https://github.com/Ganapati/RsaCtfTool/network)
[![GitHub stars](https://img.shields.io/github/stars/Ganapati/RsaCtfTool.svg)](https://github.com/Ganapati/RsaCtfTool/stargazers)
[![Rawsec's CyberSecurity Inventory](https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_flat.svg)](https://inventory.rawsec.ml/tools.html#RsaCtfTool)
[![GitHub license](https://img.shields.io/github/license/Ganapati/RsaCtfTool.svg)](https://github.com/Ganapati/RsaCtfTool)

RSA multi attacks tool : uncipher data from weak public key and try to recover private key
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
- Self-Initializing Quadratic Sieve (SIQS) using Yafu (<https://github.com/DarkenCode/yafu.git>)
- Common factor attacks across multiple keys
- Small fractions method when p/q is close to a small fraction
- Boneh Durfee Method when the private exponent d is too small compared to the modulus (i.e d < n^0.292)
- Elliptic Curve Method
- Pollards p-1 for relatively smooth numbers
- Mersenne primes factorization
- Factordb
- Londahl
- Noveltyprimes
- Partial q
- Primefac
- Qicheng
- Same n, huge e
- binary polynomial factoring
- Euler method
- Pollard Rho

## Usage

```bash
usage: RsaCtfTool.py [-h] [--publickey PUBLICKEY] [--timeout TIMEOUT]
                     [--createpub] [--dumpkey] [--ext]
                     [--uncipherfile UNCIPHERFILE] [--uncipher UNCIPHER]
                     [--verbosity {CRITICAL,ERROR,WARNING,DEBUG,INFO}]
                     [--private] [--ecmdigits ECMDIGITS] [-n N] [-p P] [-q Q]
                     [-e E] [--key KEY]
                     [--attack {mersenne_primes,pollard_p_1,smallfraction,smallq,boneh_durfee,noveltyprimes,ecm,factordb,wiener,siqs,pastctfprimes,partial_q,comfact_cn,hastads,fermat,nullattack,commonfactors,same_n_huge_e,binary_polinomial_factoring,euler,pollard_rho,all}]
```

Mode 1 : Attack RSA (specify --publickey or n and e)

- publickey : public rsa key to crack. You can import multiple public keys with wildcards.
- uncipher : cipher message to decrypt
- private : display private rsa key if recovered

Mode 2 : Create a Public Key File Given n and e (specify --createpub)

- n : modulus
- e : public exponent

Mode 3 : Dump the public and/or private numbers (optionally including CRT parameters in extended mode) from a PEM/DER format public or private key (specify --dumpkey)

- key : the public or private key in PEM or DER format

### Uncipher file

`./RsaCtfTool.py --publickey ./key.pub --uncipherfile ./ciphered\_file`

### Print private key

`./RsaCtfTool.py --publickey ./key.pub --private`

### Attempt to break multiple public keys with common factor attacks or individually- use quotes around wildcards to stop bash expansion

`./RsaCtfTool.py --publickey "*.pub" --private`

### Generate a public key

`./RsaCtfTool.py --createpub -n 7828374823761928712873129873981723...12837182 -e 65537`

### Dump the parameters from a key

`./RsaCtfTool.py --dumpkey --key ./key.pub`

### Factor with ECM when you know the approximate length in digits of a prime

`./RsaCtfTool.py --publickey key.pub --ecmdigits 25 --verbose --private`

For more examples, look at test.sh file

## Requirements

- GMPY2
- SymPy
- PyCrypto
- Requests
- Libnum
- SageMath : optional but advisable
- Sage binaries

### Ubuntu 18.04 and Kali specific Instructions

```bash
git clone https://github.com/Ganapati/RsaCtfTool.git
sudo apt-get install libgmp3-dev libmpc-dev
pip3 install -r "requirements.txt"
python3 RsaCtfTool.py
```

### MacOS-specific Instructions

If `pip3 install -r "requirements.txt"` fails to install requirements accessible within environment, the following command may work.

``easy_install `cat requirements.txt` ``

## Todo

- Brainstorm moar attack types !
