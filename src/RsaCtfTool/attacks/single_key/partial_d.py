#!/usr/bin/python3

from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath
from lib.exceptions import FactorizationError


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        print("attack initialized...")
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run partial_d attack with a timeout"""
        try:
            if not isinstance(publickey, PrivateKey):
                self.logger.error(
                    "[!] partial_d attack is only for partial private keys not pubkeys..."
                )
                raise FactorizationError

            CMD = [
                "sage",
                f"{rootpath}/sage/partial_d.sage",
                str(publickey.n),
                str(publickey.e),
                str(publickey.d),
            ]
            ret = [
                int(x)
                for x in subprocess.check_output(
                    CMD,
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
                .decode("utf8")
                .rstrip()
                .split(" ")
            ]
            p, q = ret
            assert p * q == publickey.n
            publickey.p = p
            publickey.q = q

        except:
            self.logger.error("[!] partial_d internal error...")
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
