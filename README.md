# RsaCtfTool

<div align="center">

[![Test](https://github.com/RsaCtfTool/RsaCtfTool/actions/workflows/test.yml/badge.svg)](https://github.com/RsaCtfTool/RsaCtfTool/actions/workflows/test.yml)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/RsaCtfTool/RsaCtfTool/master/.github/badges/ruff.json)](https://github.com/RsaCtfTool/RsaCtfTool/actions/workflows/lint_python.yml)
[![CodeQL](https://github.com/RsaCtfTool/RsaCtfTool/workflows/CodeQL/badge.svg)](https://github.com/RsaCtfTool/RsaCtfTool/actions/workflows/CodeQL)
[![GitHub issues](https://img.shields.io/github/issues/RsaCtfTool/RsaCtfTool.svg)](https://github.com/RsaCtfTool/RsaCtfTool/issues)
[![GitHub forks](https://img.shields.io/github/forks/RsaCtfTool/RsaCtfTool.svg)](https://github.com/RsaCtfTool/RsaCtfTool/network)
[![GitHub stars](https://img.shields.io/github/stars/RsaCtfTool/RsaCtfTool.svg)](https://github.com/RsaCtfTool/RsaCtfTool/stargazers)
[![GitHub license](https://img.shields.io/github/license/RsaCtfTool/RsaCtfTool.svg)](https://github.com/RsaCtfTool/RsaCtfTool)
[![GitHub contributors](https://img.shields.io/github/contributors/RsaCtfTool/RsaCtfTool.svg)](https://github.com/RsaCtfTool/RsaCtfTool/contributors)

</div>

RSA multi-attack tool that decrypts data from weak public keys and recovers private keys.

## Overview

This tool is an utility designed to decrypt data from weak public keys and attempt to recover the corresponding private key. It offers a comprehensive range of attack options for cracking RSA encryption.

RSA security relies on the complexity of integer factorization. This project combines multiple factorization algorithms to enhance decryption capabilities.

> **Note:** This tool is primarily intended for **educational purposes**. Not every key can be broken in a reasonable timeframe. The tool only supports RSA textbook semiprime composite modulus (not multiprimes).

For advanced factorization, consider [msieve](https://github.com/RsaCtfTool/msieve), [yafu](https://github.com/bbuhrow/yafu), or [cado-nfs](https://gitlab.inria.fr/cado-nfs/cado-nfs).

## Usage

```bash
RsaCtfTool --publickey key.pub --private                    # Recover private key
RsaCtfTool --publickey key.pub --decryptfile ciphertext    # Decrypt file
RsaCtfTool --publickey key.pub --attack wiener             # Use specific attack
```

For complete usage, run: `RsaCtfTool --help`

## Installation

### Prerequisites

- Python 3.9+
- [SageMath](https://www.sagemath.org/) (optional but recommended)

### Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Docker

```bash
docker build -t rsactftool/rsactftool .
docker run -it --rm -v $PWD:/data rsactftool/rsactftool <arguments>
```

## Attacks

### Non-Factorization Attacks

- [Wiener's attack](https://en.wikipedia.org/wiki/Wiener%27s_attack)
- [Hastad's attack](https://en.wikipedia.org/wiki/Hastad%27s_broadcasting_attack) (small public exponent)
- [Boneh-Durfee](https://staff.emu.edu.tr/alexanderchefranov/Documents/CMSE491/Fall2019/BonehIEEETIT2000%20Cryptanalysis%20of%20RSA.pdf) (small private exponent d < n^0.292)
- Same n, huge e
- [Small CRT exponent](https://en.wikipedia.org/wiki/Chinese_remainder_theorem)
- Partial q / Partial d
- [Lattice reduction](https://en.wikipedia.org/wiki/Lattice_reduction)

### Integer Factorization Methods

| Method | Description |
|--------|-------------|
| [Fermat](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method) | Close p and q |
| [Pollard Rho](https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm) | General factorization |
| [Elliptic Curve (ECM)](https://en.wikipedia.org/wiki/Lenstra_elliptic-curve_factorization) | Smooth numbers |
| [Pollard p-1](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm) | Smooth numbers |
| [Williams p+1](https://en.wikipedia.org/wiki/Williams%27s_p_%2B_1_algorithm) | Smooth numbers |
| [ROCA](https://en.wikipedia.org/wiki/ROCA_vulnerability) | Vulnerable key generation |
| [SQUFOF](https://en.wikipedia.org/wiki/Shanks%27s_square_forms_factorization) | Square forms |
| [Quadratic Sieve](https://en.wikipedia.org/wiki/Quadratic_sieve) | General factorization |
| [Dixon](https://en.wikipedia.org/wiki/Dixon%27s_factorization_method) | Random squares |
| [Factordb](http://factordb.com/) | Online factorization database |
| Common factor attacks | Keys sharing factors |
| GCD attacks | Mersenne, Primorial, Fibonacci, etc. |

### CTF-Specific Methods

- Noveltyprimes
- Past CTF Primes
- Gimmicky Primes
- Non-RSA (b^x form)
- [Z3 Theorem Prover](https://en.wikipedia.org/wiki/Z3_Theorem_Prover)
- [Wolfram Alpha](https://www.wolframalpha.com/)

## Examples

### Recover Private Key

```bash
RsaCtfTool --publickey key.pub --private
```

### Decrypt a File

```bash
RsaCtfTool --publickey key.pub --decryptfile ciphertext
```

### Attack Multiple Keys

```bash
RsaCtfTool --publickey "*.pub" --private
```

### Create Public Key from n and e

```bash
RsaCtfTool --createpub -n 7828374823761928712873... -e 65537
```

### Dump Key Parameters

```bash
RsaCtfTool --dumpkey --key key.pub
RsaCtfTool --dumpkey --ext --key key.pub  # Include CRT parameters
```

### Factor with ECM

```bash
RsaCtfTool --publickey key.pub --ecmdigits 25 --private
```

### Use Specific Attack

```bash
RsaCtfTool --publickey key.pub --attack wiener --private
RsaCtfTool --publickey key.pub --attack factordb --private
```

### Send Results to Factordb

```bash
RsaCtfTool --publickey "*.pub" --private --sendtofdb
```

### Check for ROCA Vulnerability

```bash
RsaCtfTool --isroca --publickey "examples/*.pub"
```

### Convert SSH Key to PEM

```bash
RsaCtfTool --convert_idrsa_pub --publickey ~/.ssh/id_rsa.pub
```

For more examples, run `pytest tests/ --collect-only` to see available tests.

## Testing

Tests use **pytest** and are located in `tests/`.

### Running Tests

```bash
pytest tests/                 # Run all tests
pytest tests/ -m "not slow"   # Skip slow tests
pytest tests/ -v              # Verbose mode
pytest tests/ -k "fermat"     # Run tests matching "fermat"
```

### Test Markers

- `@pytest.mark.slow` - Slow factorization tests
- `@pytest.mark.network` - Tests requiring network (Factordb)
- `@pytest.mark.attack` - Attack integration tests

### Test Files

| File | Description |
|------|-------------|
| `test_number_theory.py` | Number theory functions (gcd, is_prime, phi, etc.) |
| `test_algos.py` | Factorization algorithms (fermat, brent, pollard_rho, etc.) |
| `test_keys_wrapper.py` | PublicKey/PrivateKey classes |
| `test_utils.py` | Utility functions |
| `test_pubkey_decode.py` | RSA public key decoding |
| `test_attacks.py` | Attack integration tests |
| `test_regression.py` | Bug fix regression tests |
| `test_exceptions.py` | Custom exceptions |
| `conftest.py` | pytest configuration and fixtures |

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## License

The original project was released under GPLv3. This code has been relicensed under the MIT License.

## Thanks

<a href="https://github.com/RsaCtfTool/RsaCtfTool/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=RsaCtfTool/RsaCtfTool" />
</a>
