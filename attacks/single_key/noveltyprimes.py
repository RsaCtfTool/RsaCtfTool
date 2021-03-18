#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.rsalibnum import invmod
import binascii
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError


class Attack(AbstractAttack):
    def __init__(self, attack_rsa_obj, timeout=60):
        super().__init__(attack_rsa_obj, timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[]):
        """ "primes" of the form 31337 - 313333337 - see ekoparty 2015 "rsa 2070"
        not all numbers in this form are prime but some are (25 digit is prime)
        """
        with timeout(self.timeout):
            try:
                maxlen = 25  # max number of digits in the final integer
                for i in tqdm(range(maxlen - 4)):
                    prime = int("3133" + ("3" * i) + "7")
                    if publickey.n % prime == 0:
                        publickey.p = prime
                        publickey.q = publickey.n // publickey.p
                        priv_key = PrivateKey(
                            p=int(publickey.p),
                            q=int(publickey.q),
                            e=int(publickey.e),
                            n=int(publickey.n),
                        )

                        return (priv_key, None)
            except TimeoutError:
                return (None, None)
        return (None, None)


if __name__ == "__main__":
    attack = Attack()
    attack.test()