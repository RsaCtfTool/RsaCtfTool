#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import tempfile
import binascii
import subprocess
from lib.crypto_wrapper import RSA
from lib.crypto_wrapper import PKCS1_OAEP
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from lib.conspicuous_check import privatekey_check
from lib.number_theory import powmod, invert


logger = logging.getLogger("global_logger")


def load_partial_privkey(keyfile):
    """
    helper function to load a partial mangled asn1 PEM private key into an array of integers
    version, modulus(n), exponent(e), d, prime(p), prime(q), dp, dq, qi = tmp
    """
    keycmd = ["openssl", "asn1parse", "-in", keyfile]
    fields = []
    i = 0
    for line in subprocess.check_output(keycmd).decode("utf8").splitlines():
        if "hl=2 l=   0 prim: " not in line:
            if i > 0:
                val = 0
                if "INTEGER" in line:
                    if "BAD INTEGER" in line:
                        val = int(
                            line.split(":")[4].replace("[", "").replace("]", ""), 16
                        )
                    else:
                        val = int(line.split(":")[3], 16)
                fields.append(val)
            i += 1
    return fields


def generate_pq_from_n_and_p_or_q(n, p=None, q=None):
    """Return p and q from (n, p) or (n, q)"""
    if p is None:
        p = n // q
    elif q is None:
        q = n // p
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
        except:
            if filename:
                raise Exception(f"Key format not supported : {filename}.")
            else:
                raise Exception("Key format not supported.")

        self.filename = filename
        self.n = pub.n
        self.e = pub.e
        self.key = key

    def __str__(self):
        """Print armored public key"""
        return self.key


class PrivateKey(object):
    def __init__(
        self,
        p=None,
        q=None,
        e=None,
        n=None,
        d=None,
        phi=None,
        filename=None,
        password=None,
    ):
        """Create private key from base components
        :param p: extracted from n
        :param q: extracted from n
        :param e: exponent
        :param n: n from public key
        """
        self.p = None
        if p is not None:
            self.p = p

        self.q = None
        if q is not None:
            self.q = q

        self.e = None
        if e is not None:
            self.e = e

        self.n = None
        if n is not None:
            self.n = n

        self.phi = None
        if phi is not None:
            self.phi = phi

        if self.p is not None and self.q is not None and self.phi is None:
            if self.p != self.q:
                self.phi = (self.p - 1) * (self.q - 1)
            else:
                self.phi = (self.p**2) - self.p

        if d is not None:
            self.d = d
        elif self.phi is not None and self.e is not None:
            try:
                self.d = int(invert(e, self.phi))
            except ValueError:
                # invmod failure
                logger.error("[!] e^d==1 inversion error, check your math.")
        self.key = None
        if self.p is not None and self.q is not None and self.d is not None:
            try:
                # There is no CRT coefficient to construct a key if p equals q
                self.key = RSA.construct((self.n, self.e, self.d, self.p, self.q))
            except ValueError:
                logger.error("[!] Can't construct RSA PEM, internal error....")
        elif n is not None and e is not None and d is not None:
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
        elif filename is not None:
            with open(filename, "rb") as key_data_fd:
                try:
                    self.key = serialization.load_pem_private_key(
                        key_data_fd.read(), password=password, backend=default_backend()
                    )
                    private_numbers = self.key.private_numbers()
                    loadok = True
                except:
                    loadok = False

                if loadok:
                    if p is None:
                        self.p = private_numbers.p
                    if q is None:
                        self.q = private_numbers.q
                    if d is None:
                        self.d = private_numbers.d
                    if self.p and self.q:
                        self.n = self.p * self.q
                    if self.phi is None:
                        if self.p != self.q:
                            self.phi = (self.p - 1) * (self.q - 1)
                        else:
                            self.phi = (self.p**2) - self.p
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

        plain = []
        for c in cipher:
            if self.n is not None and self.d is not None:
                try:
                    cipher_int = int.from_bytes(c, "big")
                    m_int = hex(powmod(cipher_int, self.d, self.n))
                    if len(m_int) % 2 == 1:
                        m_int = f"0{m_int}"
                    m = binascii.unhexlify(hex(m_int)[2:])
                    plain.append(m)
                except:
                    pass

            try:
                rsakey = RSA.importKey(str(self))
                rsakey = PKCS1_OAEP.new(rsakey)
                plain.append(rsakey.decrypt(c))
            except:
                pass

            try:
                tmp_priv_key = tempfile.NamedTemporaryFile()
                with open(tmp_priv_key.name, "wb") as tmpfd:
                    tmpfd.write(str(self).encode("utf8"))
                tmp_priv_key_name = tmp_priv_key.name

                tmp_cipher = tempfile.NamedTemporaryFile()
                with open(tmp_cipher.name, "wb") as tmpfd:
                    tmpfd.write(c)
                tmp_cipher_name = tmp_cipher.name

                with open("/dev/null") as DN:
                    try:
                        openssl_result = subprocess.check_output(
                            [
                                "openssl",
                                "rsautl",
                                "-raw",
                                "-decrypt",
                                "-in",
                                "-oaep",
                                tmp_cipher_name,
                                "-inkey",
                                tmp_priv_key_name,
                            ],
                            stderr=DN,
                            timeout=30,
                        )
                        plain.append(openssl_result)
                    except:
                        pass

                    try:
                        openssl_result = subprocess.check_output(
                            [
                                "openssl",
                                "rsautl",
                                "-raw",
                                "-decrypt",
                                "-in",
                                tmp_cipher_name,
                                "-inkey",
                                tmp_priv_key_name,
                            ],
                            stderr=DN,
                            timeout=30,
                        )
                        plain.append(openssl_result)
                    except:
                        pass
            except:
                plain.append(cipher)
        return plain

    def __str__(self):
        # print(type(self.key))
        """Print armored private key"""
        if self.key is not None:
            return self.key.exportKey().decode("utf-8")
        # else:
        #    return "partial key:\nn: %d\ne: %d\nd: %d\np: %d\nq: %d\ndp: %d\ndq: %d\ndi: %d\n%s\n" % (self.n, self.e, self.d, self.p, self.q,self.dp,self.dq,self.di,self.filename)
