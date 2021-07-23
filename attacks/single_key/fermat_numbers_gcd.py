#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError
from lib.rsalibnum import gcd


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run tests against fermat composites"""
        with timeout(self.timeout):
            try:
                limit = 10000
                p = q = None
                for x in tqdm(range(1, limit), disable=(not progress)):
                    f = (2 ** 2 ** x) + 1
                    fermat = gcd(f, publickey.n)
                    if 1 < fermat < publickey.n:
                        p = publickey.n // fermat
                        q = fermat
                        break
                if p is not None and q is not None:
                    priv_key = PrivateKey(
                        int(p), int(q), int(publickey.e), int(publickey.n)
                    )
                    return (priv_key, None)
                return (None, None)
            except TimeoutError:
                return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MF4wDQYJKoZIhvcNAQEBBQADTQAwSgJDTuJNJVnOa1qp8n91iIWs30F6xA+I/nkf
MV7Ad/0M5seWOKImUngYig60DRfrXwXa7GWh8qmK0V5sR+ib27+bbZfwAQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
