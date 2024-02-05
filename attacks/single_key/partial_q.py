#!/usr/bin/python3

from lib.number_theory import invmod
from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.exceptions import FactorizationError
from lib.algos import solve_partial_q


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

            n = publickey.n
            if (e := publickey.e) == 0:
                e = 65537
            dp = publickey.dp
            dq = publickey.dq
            di = publickey.di
            partial_q = publickey.q
            publickey.p, publickey.q = solve_partial_q(n, e, dp, dq, di, partial_q)
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
