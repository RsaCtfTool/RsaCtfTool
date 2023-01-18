# /usr/bin/env python
# code taken from https://maths.dk/teaching/courses/math357-spring2016/projects/factorization.pdf

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.number_theory import gcd, isqrt_rem, isqrt, is_congruent
import logging


def euler(n):
    """
    Euler factorization method is very much like fermat's
    """
    end = isqrt(n)
    a = 0
    b = 0
    solutionsFound = []
    firstb = -1

    lf = 0
    while a < end:
        b, f = isqrt_rem(n - (a * a))
        if f == 0 and (a != firstb) and (b != firstb):
            solutionsFound.append([b, a])
            firstb = b
            lf = len(solutionsFound)
            if lf == 2:
                break
        a += 1

    if lf < 2:
        return None

    a = solutionsFound[0][0]
    b = solutionsFound[0][1]
    c = solutionsFound[1][0]
    d = solutionsFound[1][1]

    k = pow(gcd(a - c, d - b), 2)
    h = pow(gcd(a + c, d + b), 2)
    m = pow(gcd(a + c, d - b), 2)
    l = pow(gcd(a - c, d + b), 2)

    return gcd(k + h, n), gcd(l + m, n)


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.logger = logging.getLogger("global_logger")

    def attack(self, publickey, cipher=[], progress=True):
        """Run attack with Euler method"""
        if not hasattr(publickey, "p"):
            publickey.p = None
        if not hasattr(publickey, "q"):
            publickey.q = None

        # Euler attack
        try:
            if is_congruent(publickey.n, 1, 4):
                euler_res = euler(publickey.n)
            else:
                self.logger.error(
                    "[!] Public key modulus must be congruent 1 mod 4 to work with euler method."
                )
                return None, None
        except:
            return None, None
        if euler_res and len(euler_res) > 1:
            publickey.p, publickey.q = euler_res

        if publickey.q is not None:
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
MCIwDQYJKoZIhvcNAQEBBQADEQAwDgIHEAABggAEpQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data))
        return result != (None, None)
