#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from factordb.factordb import FactorDB
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.keys_wrapper import PrivateKey


def getfdb(composite):
    f = FactorDB(composite)
    f.connect()
    return f.get_factor_list()


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickey, cipher=[], progress=True):
        """Factors available online?"""
        try:
            n = publickey.n
            pq = getfdb(n)
            if pq[0] != n:
                if len(pq) == 2:
                    p, q = pq
                    if publickey.n != int(p) * int(q):
                        return None, None
                    publickey.p = p
                    publickey.q = q
                    priv_key = PrivateKey(
                        p=int(publickey.p),
                        q=int(publickey.q),
                        e=int(publickey.e),
                        n=int(publickey.n),
                    )
                    if priv_key.key is None:
                        return None, None
                    return priv_key, None
                elif len(pq) > 2:
                    # Multi-Prime RSA support
                    import functools
                    prod = functools.reduce(lambda x, y: x * y, pq)
                    if prod != publickey.n:
                        return None, None
                    phi = functools.reduce(lambda x, y: x * (y - 1), pq, 1)
                    d = pow(int(publickey.e), -1, phi)
                    priv_key = PrivateKey(
                        p=int(pq[0]),
                        q=int(pq[1]),
                        d=int(d),
                        e=int(publickey.e),
                        n=int(publickey.n),
                    )
                    if priv_key.key is None:
                        return None, None
                    return priv_key, None
                else:
                    self.logger.error(
                        "[!] factordb returned invalid factors count: %d"
                        % len(pq)
                    )
                    return None, None
            else:
                self.logger.error(
                    "[!] Composite not in factordb, couldn't factorize..."
                )
                return None, None
        except Exception:
            self.logger.error("[!] internal error :-(")
            return None, None

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MC0wDQYJKoZIhvcNAQEBBQADHAAwGQISAwm6aZnGyIrl57QGF+4RdcjlAgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
