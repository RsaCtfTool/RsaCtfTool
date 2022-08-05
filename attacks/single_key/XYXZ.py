#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.exceptions import FactorizationError
from lib.rsalibnum import isqrt, gcd, next_prime, is_prime, primes, powmod

def factor_XYXZ(n, base=3):
  """
  A104081:  Smallest prime >= 3^n.
  Factor a x^y*x^z form integer
  """
  power = 1
  while True:
    p = next_prime(base ** power)
    if n % p == 0:
      return p, n // p
    power += 1
    
class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run (X^Y)(X^Z) form attack with a timeout"""
        try:
            publickey.p, publickey.q = factor_XYXZ(publickey.n)
        except FactorizationError:
            return None, None

        if publickey.p is not None and publickey.q is not None:
            try:
                priv_key = PrivateKey(
                    n=publickey.n,
                    p=int(publickey.p),
                    q=int(publickey.q),
                    e=int(publickey.e),
                )
                return priv_key, None
            except ValueError:
                return None, None

        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGBMA0GCSqGSIb3DQEBAQUAA3AAMG0CZgtR6qd1mkWTV8BvZUh84Y8jzytSu6s0
mD4isqXK3eM/yw8aWr/KkMT4EygFOhzHVnbE9LwyQ9hMkr5WRowHi5xmL3+aXJSX
UNxJdaAdtLV4pRHcziCDgJEvc4Yi1UAMkgaNoeoWiwIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
