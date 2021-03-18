#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import tempfile
import binascii
import subprocess
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from lib.rsalibnum import invmod
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from lib.conspicuous_check import privatekey_check

logger = logging.getLogger("global_logger")


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
                raise Exception("Key format not supported : %s." % filename)
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

        if self.p is not None and self.q is not None and self.phi is None:
            if self.p != self.q:
                self.phi = (self.p - 1) * (self.q - 1)
            else:
                self.phi = (self.p ** 2) - self.p

        self.d = None
        if self.phi is not None and self.e is not None:
            self.d = invmod(e, self.phi)

        self.key = None
        if self.p is not None and self.q is not None and self.d is not None:
            self.key = RSA.construct((self.n, self.e, self.d, self.p, self.q))
        elif n is not None and e is not None and d is not None:
            try:
                self.key = RSA.construct((self.n, self.e, self.d))
            except NotImplementedError:
                pass

        elif filename is not None:
            with open(filename, "rb") as key_data_fd:
                self.key = serialization.load_pem_private_key(
                    key_data_fd.read(), password=password, backend=default_backend()
                )

                private_numbers = self.key.private_numbers()

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
                        self.phi = (self.p ** 2) - self.p

    def is_conspicuous(self):
        is_con, txt = privatekey_check(self.n, self.p, self.q, self.d, self.e)
        if is_con == True:
            msg = "[!] The given privkey has conspicuousness:\n"
            msg += "[!] It is not advisable to use it in production\n%s" % txt
            logger.error("%s" % msg)
        return is_con

    def decrypt(self, cipher):
        """Uncipher data with private key
        :param cipher: input cipher
        :type cipher: string
        """
        if not isinstance(cipher, list):
            cipher = [cipher]

        plain = []
        for c in cipher:
            if self.n is not None and self.d is not None and self.key is None:
                try:
                    cipher_int = int.from_bytes(c, "big")
                    m_int = pow(cipher_int, self.d, self.n)
                    m = binascii.unhexlify(hex(m_int)[2:]).decode()
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
        """Print armored private key"""
        return self.key.exportKey().decode("utf-8")
