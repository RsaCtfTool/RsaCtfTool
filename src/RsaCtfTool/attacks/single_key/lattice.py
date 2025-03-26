#!/usr/bin/python3

from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        print("attack initialized...")
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run simple lattice attack with a timeout"""
        try:
            if not hasattr(publickey, "p"):
                self.logger.error(
                    "[!] simple lattice attack is for partial keys only..."
                )
                return None, None
            sageresult = subprocess.check_output(
                [
                    "sage",
                    f"{rootpath}/sage/lattice.sage",
                    str(publickey.n),
                    str(publickey.p),
                ],
                timeout=self.timeout,
                stderr=subprocess.DEVNULL,
            ).decode("utf8")
            p, q = [
                int(x) for x in sageresult.replace("[", "").replace("]", "").split(",")
            ]
            priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
            return (priv_key, None)

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            return (None, None)

    def test(self):
        raise NotImplementedError
