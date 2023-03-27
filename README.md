# RsaCtfTool
[![Test](https://github.com/RsaCtfTool/RsaCtfTool/actions/workflows/test.yml/badge.svg)](https://github.com/RsaCtfTool/RsaCtfTool/actions/workflows/test.yml)
![lint_python](https://github.com/RsaCtfTool/RsaCtfTool/workflows/lint_python/badge.svg)
![CodeQL](https://github.com/RsaCtfTool/RsaCtfTool/workflows/CodeQL/badge.svg)
[![GitHub issues](https://img.shields.io/github/issues/RsaCtfTool/RsaCtfTool.svg)](https://github.com/RsaCtfTool/RsaCtfTool/issues)
[![GitHub forks](https://img.shields.io/github/forks/RsaCtfTool/RsaCtfTool.svg)](https://github.com/RsaCtfTool/RsaCtfTool/network)
[![GitHub stars](https://img.shields.io/github/stars/RsaCtfTool/RsaCtfTool.svg)](https://github.com/RsaCtfTool/RsaCtfTool/stargazers)
[![GitHub license](https://img.shields.io/github/license/RsaCtfTool/RsaCtfTool.svg)](https://github.com/RsaCtfTool/RsaCtfTool)
[![GitHub contributors](https://img.shields.io/github/contributors/RsaCtfTool/RsaCtfTool.svg)](https://github.com/RsaCtfTool/RsaCtfTool/contributors)

RSA multi attacks tool : uncipher data from weak public key and try to recover private key.
The tool will cycle through each selected attack for a given public key.
RSA security relies on the complexity of the integer factorization problem.
This project is a glue between various integer factorization algorithms.
This is an educational tool and not every key will be broken in reasonable time (manage your expectations).
This tool only supports RSA textbook semiprime composite modulus and not composite multiprimes, this is a constraint embbeded upstream in the pycrypto lib (see TODO).

For an advanced integer factorization tool please use [msieve](https://github.com/radii/msieve), [yafu](https://github.com/bbuhrow/yafu.git) or [cado-nfs](https://gitlab.inria.fr/cado-nfs/cado-nfs).

Attacks :

- Attacks that doesn't depend on the factorization of integers (may depend on knowing n,e,cyphertext,etc...):
  - [Wiener's attack](https://en.wikipedia.org/wiki/Wiener%27s_attack)
  - Hastad's attack (Small public exponent)
  - [Boneh Durfee Method when the private exponent d is too small compared to the modulus (i.e d < n^0.292)](https://staff.emu.edu.tr/alexanderchefranov/Documents/CMSE491/Fall2019/BonehIEEETIT2000%20Cryptanalysis%20of%20RSA.pdf)
  - Same n, huge e
  - [Small CRT exponent](https://en.wikipedia.org/wiki/Chinese_remainder_theorem)
  - Common factor between ciphertext and modulus
  - Partial q
  - Partial d
  - [Simple lattice reduction](https://en.wikipedia.org/wiki/Lattice_reduction)

- Strict Integer factorization methods (only depends on knowing n):
  - Weak public key factorization
  - Small q (q < 100,000)
  - [Fermat's factorisation for close p and q](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method)
  - Gimmicky Primes method
  - Past CTF Primes method
  - Non RSA key in the form b^x, where b is prime
  - Common factor attacks across multiple keys
  - Small fractions method when p/q is close to a small fraction
  - [Elliptic Curve Method](https://en.wikipedia.org/wiki/Lenstra_elliptic-curve_factorization)
  - [Pollards p-1 for relatively smooth numbers](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm)
  - Mersenne primes factorization
  - [Factordb](http://factordb.com/)
  - [Londahl](https://web.archive.org/web/20220525193825/https://grocid.net/2017/09/16/finding-close-prime-factorizations/)
  - Noveltyprimes
  - [Qicheng](https://www.cs.ou.edu/~qcheng/paper/speint.pdf)
  - binary polynomial factoring
  - [Euler method](https://en.wikipedia.org/wiki/Euler_method)
  - [Pollard Rho](https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm)
  - [Wolfram alpha](https://www.wolframalpha.com/)
  - [Z3 theorem prover](https://en.wikipedia.org/wiki/Z3_Theorem_Prover)
  - [Primorial pm1 gcd](https://en.wikipedia.org/wiki/Primorial)
  - [Mersenne Numbers pm1 gcd](https://en.wikipedia.org/wiki/Mersenne_prime)
  - [Factorial pm1 gcd](https://en.wikipedia.org/wiki/Factorial)
  - [Compositorial pm1 gcd](https://oeis.org/wiki/Compositorial)
  - [Fermat Numbers gcd](https://en.wikipedia.org/wiki/Fermat_number)
  - [Fibonacci Numbers gcd](https://en.wikipedia.org/wiki/Fibonacci_sequence)
  - System primes gcd
  - [Shanks's square forms factorization (SQUFOF)](https://en.wikipedia.org/wiki/Shanks%27s_square_forms_factorization)
  - [Return of Coppersmith's attack (ROCA) with NECA variant](https://en.wikipedia.org/wiki/ROCA_vulnerability)
  - [Dixon](https://en.wikipedia.org/wiki/Dixon%27s_factorization_method)
  - brent (Pollard rho variant)
  - [Pisano Period](https://en.wikipedia.org/wiki/Pisano_period)
  - XYXZ form integer factorization where P prime > X^Y and Q prime > X^Z
  - High and Low Bits Equal
  - [Williams p+1](https://en.wikipedia.org/wiki/Williams%27s_p_%2B_1_algorithm)
  - [Hart algorithm (similar to fermat)](http://wrap.warwick.ac.uk/54707/1/WRAP_Hart_S1446788712000146a.pdf)
  - [Lehmer machine (similar to fermat)](https://en.wikipedia.org/wiki/Lehmer_sieve)
  - 2PN special form where P is prime > 2 and sqrt(2PN) is close to (Pp + 2q)/2 
  - [Kraitchik algorithm (improvement over fermat)](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method)
  - Lehman algorithm improvement over fermat
  - Carmichael algorithm
  - [Quadratic sieve](https://en.wikipedia.org/wiki/Quadratic_sieve)
  - [Classical part of Shor algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm)
  - [Lucas Numbers gcd](https://en.wikipedia.org/wiki/Lucas_number)

## Usage

```bash
usage: RsaCtfTool.py [-h] [--publickey PUBLICKEY] [--output OUTPUT] [--timeout TIMEOUT] [--createpub] [--dumpkey] [--ext] [--uncipherfile UNCIPHERFILE] [--uncipher UNCIPHER]
                     [--verbosity {CRITICAL,ERROR,WARNING,DEBUG,INFO}] [--private] [--tests] [--ecmdigits ECMDIGITS] [-n N] [-p P] [-q Q] [-e E] [--key KEY]
                     [--password PASSWORD] [--show-factors SHOW_FACTORS]
                     [--attack {SQUFOF,XYXZ,binary_polinomial_factoring,brent,comfact_cn,cube_root,ecm,ecm2,factordb,fermat_numbers_gcd,fibonacci_gcd,highandlowbitsequal,mersenne_pm1_gcd,mersenne_primes,neca,nonRSA,noveltyprimes,pastctfprimes,pisano_period,pollard_p_1,primorial_pm1_gcd,qicheng,roca,siqs,small_crt_exp,smallfraction,smallq,system_primes_gcd,wolframalpha,wiener,boneh_durfee,euler,pollard_rho,williams_pp1,partial_q,partial_d,londahl,z3_solver,dixon,lehmer,fermat,hart,common_factors,common_modulus,same_n_huge_e,hastads,lattice,lehman,carmichael,qs,classical_shor,all} [{SQUFOF,XYXZ,binary_polinomial_factoring,brent,comfact_cn,cube_root,ecm,ecm2,factordb,fermat_numbers_gcd,fibonacci_gcd,highandlowbitsequal,mersenne_pm1_gcd,mersenne_primes,neca,nonRSA,noveltyprimes,pastctfprimes,pisano_period,pollard_p_1,primorial_pm1_gcd,qicheng,roca,siqs,small_crt_exp,smallfraction,smallq,system_primes_gcd,wolframalpha,wiener,boneh_durfee,euler,pollard_rho,williams_pp1,partial_q,partial_d,londahl,z3_solver,dixon,lehmer,fermat,hart,common_factors,common_modulus,same_n_huge_e,hastads,lattice,lehman,carmichael,qs,classical_shor,factorial_pm1_gcd,lucas_gcd,all} ...]]
                     [--sendtofdb] [--isconspicuous] [--isroca] [--convert_idrsa_pub] [--check_publickey] [--partial]
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

For more examples, look at test.sh file

### Attack private keys with partial bits of Q known ###

`./RsaCtfTool.py --attack partial_q --key examples/masked.pem`

### Attack private keys with partial bits of D known ###

`./RsaCtfTool.py --attack partial_d --key examples/partial_d.pem`

### Convert idrsa.pub to pem format

`./RsaCtfTool.py  --convert_idrsa_pub --publickey $HOME/.ssh/id_rsa.pub`


### Check if a given key or keys are roca ###

`./RsaCtfTool.py --isroca --publickey "examples/*.pub"`

### Docker run ###

```bash
docker pull rsactftool/rsactftool
docker run -it --rm -v $PWD:/data rsactftool/rsactftool <arguments>
```


### Virtual environment run ###

Setup the venv
```bash
virtualenv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Run
```bash
source venv/bin/activate
./RsaCtfTool.py <arguments>
```

## Requirements

- GMPY2
- PyCrypto
- Requests
- Libnum
- SageMath : optional but advisable
- Sage binaries

### Ubuntu 18.04 and Kali specific Instructions

```bash
git clone https://github.com/RsaCtfTool/RsaCtfTool.git
sudo apt-get install libgmp3-dev libmpc-dev
cd RsaCtfTool
pip3 install -r "requirements.txt"
./RsaCtfTool.py
```


### Fedora (33 and above) specific Instructions
```bash
git clone https://github.com/RsaCtfTool/RsaCtfTool.git
sudo dnf install gcc python3-devel python3-pip python3-wheel gmp-devel mpfr-devel libmpc-devel
cd RsaCtfTool
pip3 install -r "requirements.txt"
./RsaCtfTool.py
```

If you also want the optional SageMath you need to do
```bash
sudo dnf install sagemath
pip3 install -r "optional-requirements.txt"
```

### MacOS-specific Instructions

If `pip3 install -r "requirements.txt"` fails to install requirements accessible within environment, the following command may work.

``easy_install `cat requirements.txt` ``

If you installed gmpy2 with homebrew(`brew install gmp`), you might have to point clang towards the header files with this command:
``CFLAGS=-I/opt/homebrew/include LDFLAGS=-L/opt/homebrew/lib pip3 install -r requirements.txt``

### Optional to factor roca keys upto 512 bits, Install neca:
You can follow instructions from : `https://www.mersenneforum.org/showthread.php?t=23087`

## TODO (aka. Help wanted !)

- Implement test method in each attack.
- Assign the correct algorithm complexity in **Big O** notation for each attack.
- Support multiprime RSA, the project currently supports textbook RSA.

## Contributing 

- Please read the CONTRIBUTING.md guideline for the bare minimum aceptable PRs.
