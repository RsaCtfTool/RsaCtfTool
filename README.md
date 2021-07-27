# RsaCtfTool
[![Test](https://github.com/pedroelbanquero/RsaCtfTool/actions/workflows/test.yml/badge.svg)](https://github.com/pedroelbanquero/RsaCtfTool/actions/workflows/test.yml)
![lint_python](https://github.com/Ganapati/RsaCtfTool/workflows/lint_python/badge.svg)
![CodeQL](https://github.com/Ganapati/RsaCtfTool/workflows/CodeQL/badge.svg)
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
- Wolfram alpha
- cm-factor
- z3 theorem prover
- Primorial pm1 gcd
- Mersenne pm1 gcd
- Fermat Numbers gcd
- Fibonacci gcd
- System primes gcd
- Small crt exponent
- Shanks's square forms factorization (SQUFOF)
- Return of Coppersmith's attack (ROCA) with NECA variant
- Dixon
- brent (Pollard rho variant)
- Pisano Period
- NSIF Vulnerability, Power Modular Factorization, Near Power Factors

## Usage

```bash
usage: RsaCtfTool.py [-h] [--publickey PUBLICKEY] [--timeout TIMEOUT]
                     [--createpub] [--dumpkey] [--ext] [--sendtofdb]
                     [--uncipherfile UNCIPHERFILE] [--uncipher UNCIPHER]
                     [--verbosity {CRITICAL,ERROR,WARNING,DEBUG,INFO}]
                     [--private] [--ecmdigits ECMDIGITS] [-n N] [-p P] [-q Q]

                     [-e E] [--key KEY] [--isconspicuous] [--convert_idrsa_pub] [--isroca] [--check_publickey]
                     [--attack {brent,fermat_numbers_gcd,comfact_cn,wiener,factordb,smallq,pollard_rho,euler,z3_solver,neca,cm_factor,mersenne_pm1_gcd,SQUFOF,small_crt_exp,fibonacci_gcd,smallfraction,boneh_durfee,roca,fermat,londahl,mersenne_primes,partial_q,siqs,noveltyprimes,binary_polinomial_factoring,primorial_pm1_gcd,pollard_p_1,ecm2,cube_root,system_primes_gcd,dixon,ecm,pastctfprimes,qicheng,wolframalpha,hastads,same_n_huge_e,commonfactors,pisano_period,nsif,all}]
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


### Optionaly send the results back to factordb

`./RsaCtfTool.py --publickey "*.pub" --private --sendtofdb`

### Generate a public key

`./RsaCtfTool.py --createpub -n 7828374823761928712873129873981723...12837182 -e 65537`

### Dump the parameters from a key

`./RsaCtfTool.py --dumpkey --key ./key.pub`

### Check a given private key for conspicuousness 

`./RsaCtfTool.py --key examples/conspicuous.priv --isconspicuous`

### Factor with ECM when you know the approximate length in digits of a prime

`./RsaCtfTool.py --publickey key.pub --ecmdigits 25 --verbose --private`


### NSIF Attack - factorization with GCD inverse modular exponent

`time ./RsaCtfTool.py -n 1078615880917389544637583114473414840170786187365383943640580486946396054833005778796250863934445216126720683279228360145952738612886499734957084583836860500440925043100784911137186209476676352971557693774728859797725277166790113706541220865545309534507638851540886910549436636443182335048699197515327493691587 --attack nsif -e 10000`

![image](https://user-images.githubusercontent.com/60758685/121983696-595c4480-cd57-11eb-87f6-7df7285c036a.png)


For more examples, look at test.sh file

### Convert idrsa.pub to pem format

`./RsaCtfTool.py  --convert_idrsa_pub --publickey $HOME/.ssh/id_rsa.pub`


### Check if a given key or keys are roca ###

`./RsaCtfTool.py --isroca --publickey "examples/*.pub"`

### Docker run ###

`docker pull ganapati/rsactftool`
`docker run -it --rm -v $PWD:/data ganapati/rsactftool <arguments>`

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
cd RsaCtfTool
pip3 install -r "requirements.txt"
python3 RsaCtfTool.py
```


### Fedora (33 and above) specific Instructions
```bash
git clone https://github.com/Ganapati/RsaCtfTool.git
sudo dnf install gcc python3-devel python3-pip python3-wheel gmp-devel mpfr-devel libmpc-devel
cd RsaCtfTool
pip3 install -r "requirements.txt"
python3 RsaCtfTool.py
```

If you also want the optional SageMath you need to do
```bash
sudo dnf install sagemath
pip3 install -r "optional-requirements.txt"
```

### MacOS-specific Instructions

If `pip3 install -r "requirements.txt"` fails to install requirements accessible within environment, the following command may work.

``easy_install `cat requirements.txt` ``

### Install neca
You can follow instructions from : `https://www.mersenneforum.org/showthread.php?t=23087`

## Todo (aka. Help wanted !)

- Implement test method in each attack
- Assign the correct speed value in each attack
