#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from attacks.abstract_attack import AbstractAttack
import requests
from lib.rsalibnum import invmod
from lib.keys_wrapper import PrivateKey
from lib.exceptions import FactorizationError
from Crypto.Util.number import long_to_bytes
from lib.utils import timeout, TimeoutError
from gmpy2 import powmod


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def solveforp(self, equation):
        """Parse factordb response"""
        try:
            if "^" in equation:
                k, j = equation.split("^")
            if "-" in j:
                j, sub = j.split("-")
            eq = list(map(int, [k, j, sub]))
            return pow(eq[0], eq[1]) - eq[2]
        except Exception as e:
            self.logger.error(
                "[*] FactorDB gave something we couldn't parse sorry (%s). Got error: %s"
                % (equation, e)
            )
            raise FactorizationError()

    def attack(self, publickey, cipher=[], progress=True):
        """Factors available online?"""
        with timeout(self.timeout):
            try:
                url_1 = "http://factordb.com/index.php?query=%i"
                url_2 = "http://factordb.com/index.php?id=%s"
                s = requests.Session()
                r = s.get(url_1 % publickey.n, verify=False)
                regex = re.compile(r"index\.php\?id\=([0-9]+)", re.IGNORECASE)
                ids = regex.findall(r.text)

                # check if only 1 factor is returned
                if len(ids) == 2:
                    # theres a chance that the only factor returned is prime, and so we can derive the priv key from it
                    regex = re.compile(r"<td>P<\/td>")
                    prime = regex.findall(r.text)
                    if len(prime) == 1:
                        # n is prime, so lets get the key from it
                        d = invmod(publickey.e, publickey.n - 1)
                        # construct key using only n and d
                        priv_key = PrivateKey(
                            e=int(publickey.e), n=int(publickey.n), d=d
                        )
                        return (priv_key, None)

                elif len(ids) == 3:
                    try:
                        regex = re.compile(r'value="([0-9\^\-]+)"', re.IGNORECASE)
                        p_id = ids[1]
                        r_1 = s.get(url_2 % p_id, verify=False)
                        key_p = regex.findall(r_1.text)[0]
                        publickey.p = (
                            int(key_p) if key_p.isdigit() else self.solveforp(key_p)
                        )

                        q_id = ids[2]
                        r_2 = s.get(url_2 % q_id, verify=False)
                        key_q = regex.findall(r_2.text)[0]
                        publickey.q = (
                            int(key_q) if key_q.isdigit() else self.solveforp(key_q)
                        )

                        if publickey.n != int(publickey.p) * int(publickey.q):
                            return (None, None)

                    except IndexError:
                        return (None, None)

                    try:
                        priv_key = PrivateKey(
                            p=int(publickey.p),
                            q=int(publickey.q),
                            e=int(publickey.e),
                            n=int(publickey.n),
                        )
                    except ValueError:
                        return (None, None)

                    return (priv_key, None)
                elif len(ids) > 3:
                    phi = 1
                    for p in ids[1:]:
                        phi *= int(p) - 1
                    d = invmod(publickey.e, phi)
                    plains = []

                    if cipher is not None and len(cipher) > 0:
                        for c in cipher:
                            int_big = int.from_bytes(c, "big")
                            plain1 = powmod(int_big, d, publickey.n)
                            plains.append(long_to_bytes(plain1))

                            return (None, plains)
                return (None, None)
            except NotImplementedError:
                return (None, None)
            except TimeoutError:
                return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MC0wDQYJKoZIhvcNAQEBBQADHAAwGQISAwm6aZnGyIrl57QGF+4RdcjlAgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
