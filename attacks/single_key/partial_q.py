#!/usr/bin/python3

from lib.number_theory import invmod
from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.number_theory import gcd
from lib.exceptions import FactorizationError

# Source:
# https://0day.work/0ctf-2016-quals-writeups/

# Based on:
# RSA? Challenge in 0ctf 2016

# we are given a private key masked and have the components of the
# chinese remainder theorem and a partial "q"

# The above writeup detailed a method to derive q candidates
# given the CRT component dQ

# CRT Components definition
# dP    = e^-1 mod(p-1)
# dQ    = e^-1 mod(q-1)
# qInv  = q^-1 mod p

# Equations from https://0day.work/0ctf-2016-quals-writeups/

# dP Equalities
# -------------
# dP                 = d mod (p - 1)
# dP                 = d mod (p - 1)
# e * dP             = 1 mod (p - 1)
# e * dP - k*(p - 1) = 1
# e * dP             = 1 + k*(p-1)
# e * dP -1          = k*(p-1)
# (e * dP -1)/k      = (p-1)
# (e * dP -1)/k +1   = p

# dQ Equalities
# -------------
# dQ                 = d mod (q - 1)
# dQ                 = d mod (q - 1)
# e * dQ             = 1 mod (q - 1)
# e * dQ - k*(p - 1) = 1
# e * dQ             = 1 + k*(q-1)
# e * dQ -1          = k*(q-1)
# (e * dQ -1)/k      = (q-1)
# (e * dQ -1)/k +1   = p

# qInv Equalities
# ---------------
# qInv            = q^-1 mod p
# q * qInv        = 1 (mod p)
# q * qInv - k*p  = 1            (For some value "k")
# q * qInv        = 1 + k*p
# q * qInv - 1    = k*p
# (q * qInv -1)/k = p

# Additionally the following paper details an algorithm to generate
# p and q prime candidates with just the CRT components

# https://eprint.iacr.org/2004/147.pdf


def solve_partial_q(e, dp, dq, qi, part_q, progress=True, Limit=100000):
    """Search for partial q.
    Tunable to search longer.
    """

    edqm1 = e * dq - 1
    edpm1 = e * dp - 1

    for j in tqdm(range(Limit, 1, -1), disable=(not progress)):
        q = edqm1 // j + 1
        if q & part_q == part_q:
            break

    for k in tqdm(range(1, Limit, 1), disable=(not progress)):
        p = edpm1 // k + 1
        if gcd(p, q) == 1 and invmod(q, p) == qi:
            break

    print("p = " + str(p), k)
    print("q = " + str(q), j)
    return p, q


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run partial_q attack with a timeout"""
        try:

            if not isinstance(publickey, PrivateKey):
                self.logger.error(
                    "[!] partial_q attack is only for partial private keys not pubkeys..."
                )
                raise FactorizationError

            e = publickey.e
            if e == 0:
                e = 65537
            dp = publickey.dp
            dq = publickey.dq
            di = publickey.di
            partial_q = publickey.q
            publickey.p, publickey.q = solve_partial_q(e, dp, dq, di, partial_q)
            if publickey.e == 0:
                publickey.e = 65537
            if publickey.n == 0:
                publickey.n = publickey.p * publickey.q

        except FactorizationError:
            return None, None

        if publickey.p is not None and publickey.q is not None:
            try:
                priv_key = PrivateKey(
                    n=int(publickey.n),
                    p=int(publickey.p),
                    q=int(publickey.q),
                    e=int(publickey.e),
                )
                # print(priv_key)
                return priv_key, None
            except ValueError:
                return None, None

        return None, None

    def test(self):

        raise NotImplementedError
