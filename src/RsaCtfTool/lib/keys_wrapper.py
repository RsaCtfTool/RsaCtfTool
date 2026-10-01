#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import binascii
import subprocess
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from RsaCtfTool.lib.crypto_wrapper import RSA
from RsaCtfTool.lib.crypto_wrapper import PKCS1_OAEP
from RsaCtfTool.lib.conspicuous_check import privatekey_check
from RsaCtfTool.lib.number_theory import powmod, invert


logger = logging.getLogger("global_logger")


def load_partial_privkey(keyfile):
    """
    helper function to load a partial mangled asn1 PEM private key into an array of integers
    version, modulus(n), exponent(e), d, prime(p), prime(q), dp, dq, qi = tmp
    """
    keycmd = ["openssl", "asn1parse", "-in", keyfile]
    try:
        lines = subprocess.check_output(keycmd).decode("utf8").splitlines()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"cannot asn1-parse private key {keyfile}: {exc}")
    fields = []
    i = 0
    for line in lines:
        if "hl=2 l=   0 prim: " not in line:
            if i > 0 and "INTEGER" in line:
                # Non-INTEGER lines (OCTET STRING headers etc.) carry no key
                # field; padding them with 0 used to shift every later field.
                if "BAD INTEGER" in line:
                    val = int(line.split(":")[4].replace("[", "").replace("]", ""), 16)
                else:
                    val = int(line.split(":")[3], 16)
                fields.append(val)
            i += 1
    if len(fields) < 9:
        raise ValueError(
            f"private key {keyfile} yielded only {len(fields)} fields, expected 9"
        )
    return fields


def generate_pq_from_n_and_p_or_q(n, p=None, q=None):
    """Return (p, q) from (n, p) or (n, q).

    Raises ValueError when neither prime is supplied, or when the supplied
    prime does not divide n - callers previously received a silently
    wrong floor-division quotient in that case.
    """
    if p is None and q is None:
        raise ValueError("at least one prime factor must be provided")
    if p is None:
        p = n // q
    elif q is None:
        q = n // p
    if p * q != n:
        raise ValueError("the supplied prime does not divide n")
    return (p, q)


def generate_keys_from_p_q_e_n(p, q, e, n):
    """Generate keypair from p, q, e, n"""
    priv_key = None
    try:
        priv_key = PrivateKey(p, q, e, n)
    except (ValueError, TypeError):
        pass

    pub_key = RSA.construct((n, e)).publickey().exportKey()
    return (pub_key, priv_key)


class PublicKey(object):
    def __init__(self, key, filename=None):
        """Create RSA key from input content
        :param key: public key file content
        :type key: string
        """
        try:
            pub = RSA.importKey(key)
        except Exception:
            if filename:
                raise Exception(f"Key format not supported : {filename}.")
            else:
                raise Exception("Key format not supported.")

        self.filename = filename
        self.n = pub.n
        self.e = pub.e
        self.p = None
        self.q = None
        self.key = key

    def __str__(self):
        """Print armored public key"""
        if isinstance(self.key, bytes):
            return self.key.decode("utf-8")
        return self.key


class PrivateKey(object):
    def _init_fields(self, p, q, e, n, d, phi, primes=None):
        if primes is not None:
            self.primes = [int(x) for x in primes]
            self.primes.sort()
            self.p = self.primes[0]
            self.q = self.primes[1] if len(self.primes) > 1 else None
        else:
            self.primes = []
            if p is not None:
                self.primes.append(int(p))
            if q is not None and int(q) not in self.primes:
                self.primes.append(int(q))
            self.p = p
            self.q = q
        self.e = e
        self.n = n
        self.d = d
        self.phi = phi

    def _compute_phi(self):
        if self.phi is not None:
            return
        if self.primes and len(self.primes) > 2:
            import functools

            self.phi = functools.reduce(lambda acc, p: acc * (p - 1), self.primes, 1)
        elif self.p is not None and self.q is not None and self.phi is None:
            if self.p != self.q:
                self.phi = (self.p - 1) * (self.q - 1)
            else:
                self.phi = (self.p**2) - self.p

    def _compute_d(self, e):
        if self.d is not None:
            return
        if self.phi is not None and self.e is not None:
            # The phi-inverse also satisfies e*d == 1 (mod lambda) since
            # lambda divides phi, and RSA.construct validates against phi.
            # gmpy2 raises ZeroDivisionError (not ValueError) when no
            # inverse exists.
            try:
                self.d = int(invert(e, self.phi))
            except (ValueError, ZeroDivisionError):
                logger.error("[!] e^d==1 inversion error, check your math.")

    def _construct_key_from_components(self):
        if self.primes and len(self.primes) > 2:
            # Multi-prime RSA: standard PyCryptodome construct only accepts 2-prime tuples.
            # We preserve recovered parameters for direct textbook and CRT decryption.
            return True
        if self.p is not None and self.q is not None and self.d is not None:
            try:
                self.key = RSA.construct((self.n, self.e, self.d, self.p, self.q))
            except ValueError:
                logger.error("[!] Can't construct RSA PEM, internal error....")
            return True
        if self.n is not None and self.e is not None and self.d is not None:
            try:
                self.key = RSA.construct((self.n, self.e, self.d))
            except NotImplementedError:
                logger.error("[!] Unable to create PEM private key...")
                logger.info(
                    "n:%s\ne:%s\nd:%s\n" % (hex(self.n), hex(self.e), hex(self.d))
                )
            except ValueError:
                logger.error("[!] Unable to compute factors p and q from exponent d")
                logger.info("[+] n=%d,e=%d,d=%d" % (self.n, self.e, self.d))
            return True
        return False

    def _load_key_from_file(self, filename, password, p, q, d):
        if isinstance(password, str):
            password = password.encode()
        with open(filename, "rb") as key_data_fd:
            pem_bytes = key_data_fd.read()
            try:
                loaded = serialization.load_pem_private_key(
                    pem_bytes, password=password, backend=default_backend()
                )
                private_numbers = loaded.private_numbers()
                loadok = True
            except Exception:
                loadok = False

            if loadok:
                public_numbers = private_numbers.public_numbers
                if p is None:
                    self.p = private_numbers.p
                if q is None:
                    self.q = private_numbers.q
                if d is None:
                    self.d = private_numbers.d
                if self.e is None:
                    self.e = public_numbers.e
                if self.n is None:
                    self.n = public_numbers.n
                self.filename = filename
                self._compute_phi()
                # Rebuild a PyCryptodome key from the recovered components so
                # __str__/decrypt see the same uniform RSA object interface
                # instead of a cryptography-library key without exportKey().
                try:
                    self.key = RSA.construct((self.n, self.e, self.d, self.p, self.q))
                except (ValueError, IndexError, NotImplementedError, TypeError):
                    self._pem_bytes = pem_bytes
            else:
                tmp = load_partial_privkey(filename)
                self.n = tmp[1]
                self.e = tmp[2]
                self.d = tmp[3]
                self.p = tmp[4]
                self.q = tmp[5]
                self.dp = tmp[6]
                self.dq = tmp[7]
                self.di = tmp[8]
                self.filename = filename

    def __init__(
        self,
        p=None,
        q=None,
        e=None,
        n=None,
        d=None,
        phi=None,
        primes=None,
        filename=None,
        password=None,
    ):
        """Create private key from base components
        :param p: extracted from n
        :param q: extracted from n
        :param e: exponent
        :param n: n from public key
        :param primes: optional list of primes for multi-prime RSA
        """
        self.key = None
        self._pem_bytes = None
        self.filename = filename
        self._init_fields(p, q, e, n, d, phi, primes)
        self._compute_phi()
        self._compute_d(e)
        if not self._construct_key_from_components() and filename is not None:
            self._load_key_from_file(filename, password, p, q, d)

    def is_conspicuous(self):
        is_con, txt = privatekey_check(self.n, self.p, self.q, self.d, self.e)
        if is_con:
            msg = "[!] The given privkey has conspicuousness:\n"
            msg += "[!] It is not advisable to use it in production\n%s" % txt
            logger.error(f"{msg}")
        return is_con

    def decrypt(self, cipher):
        """Decrypt data with private key
        :param cipher: input cipher
        :type cipher: string
        """
        if not isinstance(cipher, list):
            cipher = [cipher]

        # Build the OAEP decryptor once instead of re-importing per cipher;
        # stays None when no constructable key exists.
        rsakey = None
        pem = str(self)
        if pem:
            try:
                rsakey = PKCS1_OAEP.new(RSA.importKey(pem))
            except Exception:
                rsakey = None

        plain = []
        for c in cipher:
            # PKCS#1 OAEP first: it validates its own padding and fails
            # cleanly on anything else.
            if rsakey is not None:
                try:
                    plain.append(rsakey.decrypt(c))
                    continue
                except Exception:
                    pass

            # Multi-prime CRT decryption if all primes are known
            if (
                self.primes
                and len(self.primes) > 2
                and self.d is not None
                and self.n is not None
            ):
                try:
                    from RsaCtfTool.lib.number_theory import chinese_remainder

                    cipher_int = int.from_bytes(c, "big")
                    residues = [
                        powmod(cipher_int, self.d % (p - 1), p) for p in self.primes
                    ]
                    m_int = chinese_remainder(self.primes, residues)
                    m_hex = hex(m_int)[2:]
                    if len(m_hex) % 2 == 1:
                        m_hex = f"0{m_hex}"
                    plain.append(binascii.unhexlify(m_hex))
                    continue
                except Exception:
                    pass

            # Textbook RSA with the recovered exponent.
            if self.n is not None and self.d is not None:
                try:
                    cipher_int = int.from_bytes(c, "big")
                    m_hex = hex(powmod(cipher_int, self.d, self.n))[2:]
                    if len(m_hex) % 2 == 1:
                        m_hex = f"0{m_hex}"
                    plain.append(binascii.unhexlify(m_hex))
                    continue
                except Exception:
                    pass

            # Nothing worked - keep the raw ciphertext so the caller sees
            # an entry for this input instead of a silently dropped one.
            plain.append(c)
        return plain

    def __str__(self):
        """Print armored private key"""
        if self.key is not None:
            export = getattr(self.key, "exportKey", None) or getattr(
                self.key, "export_key", None
            )
            if export is not None:
                out = export()
                return out.decode("utf-8") if isinstance(out, bytes) else out
        if self._pem_bytes is not None:
            return self._pem_bytes.decode("utf-8")
        if self.primes and len(self.primes) > 2 and self.d is not None:
            lines = [
                "-----BEGIN MULTI-PRIME RSA PARAMETERS-----",
                f"Modulus (n): {self.n}",
                f"Public Exponent (e): {self.e}",
                f"Private Exponent (d): {self.d}",
                f"Number of Primes: {len(self.primes)}",
                f"Primes: {', '.join(str(p) for p in self.primes)}",
                "-----END MULTI-PRIME RSA PARAMETERS-----",
            ]
            return "\n".join(lines)
        return ""
