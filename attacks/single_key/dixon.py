#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.exceptions import FactorizationError
from lib.utils import timeout, TimeoutError
from lib.rsalibnum import isqrt, gcd, next_prime, is_prime, primes, powmod
import bitarray


def dixon_factor(N, B=7, explain=False):

    if is_prime(N):
        return N, 1

    start = isqrt(N)

    if (start ** 2) == N:
        return start, start

    base = primes(B)
    lqbf = pow(base[-1], 2) + 1
    QBF = bitarray.bitarray(lqbf)  # This is our quasi-bloom-filter

    basej2N = []
    for j in range(0, len(base)):
        p = powmod(base[j], 2, N)
        basej2N.append(p)
        QBF[p] = 1  # We populate our quasi-bloom-filter

    i = start
    while i < N:
        i2N = pow(i, 2, N)
        if i2N < lqbf and QBF[i2N] == 1:
            for k in range(0, len(base)):
                if QBF[basej2N[k]] == 1:
                    # if i2N == basej2N[k]: # this is replaced with a quasi-bloom-filter
                    f = gcd(i - base[k], N)
                    if explain:
                        print("N = %d" % N)
                        print("%d = isqrt(N)" % start)
                        print("%d = pow(%d,2,n)" % (i2N, i))
                        print("%d = pow(%d,2,n)" % (basej2N[k], base[k]))
                        print("%d - %d = %d" % (i, base[k], f))
                        print("%d = gcd(%d - % d, N)" % (f, i, base[k]))
                        print(
                            "%d = gcd(%d + % d, N)" % (gcd(i + base[k], N), i, base[k])
                        )
                    if 1 < f < N:
                        return f, N // f
        i += 1
    return None, None


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run dixon attack with a timeout"""
        try:
            with timeout(seconds=self.timeout):
                try:
                    if publickey.n <= 10 ** 10:
                        publickey.p, publickey.q = dixon_factor(publickey.n)
                    else:
                        self.logger.info("[-] Dixon is too slow for pubkeys > 10^10...")
                        return (None, None)
                except TimeoutError:
                    return (None, None)

        except FactorizationError:
            return (None, None)

        if publickey.p is not None and publickey.q is not None:
            try:
                priv_key = PrivateKey(
                    n=publickey.n,
                    p=int(publickey.p),
                    q=int(publickey.q),
                    e=int(publickey.e),
                )
                return (priv_key, None)
            except ValueError:
                return (None, None)

        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCAwDQYJKoZIhvcNAQEBBQADDwAwDAIFAQAwAjcCAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
