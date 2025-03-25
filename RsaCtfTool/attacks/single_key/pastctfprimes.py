#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.number_theory import is_divisible
import glob


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickey, cipher=[], progress=True):
        """Search for previously used primes in CTFs"""
        for txtfile in glob.glob("data/*.txt"):
            self.logger.info(f"[+] loading prime list file {txtfile}...")
            primes = sorted([int(l.rstrip()) for l in open(txtfile, "r").readlines()])
            for prime in tqdm(primes, disable=(not progress)):
                if is_divisible(publickey.n, prime):
                    publickey.q = prime
                    publickey.p = publickey.n // publickey.q
                    priv_key = PrivateKey(
                        int(publickey.p),
                        int(publickey.q),
                        int(publickey.e),
                        int(publickey.n),
                    )
                    return priv_key, None
        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIIBfjANBgkqhkiG9w0BAQEFAAOCAWsAMIIBZgKCAV0BAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAEcN5PtyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE7i1xIeWbfAOhAgMB
AAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
