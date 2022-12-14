#!/usr/bin/python3

from lib.number_theory import invmod
from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
import logging
import importlib
import subprocess
from lib.keys_wrapper import PublicKey, PrivateKey
from lib.number_theory import is_prime, isqrt, gcd
from lib.utils import rootpath
from lib.exceptions import FactorizationError


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        print("attack initialized...")
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run simple lattice attack with a timeout"""
        #raise NotImplementedError
        #print(publickey.n, publickey.p)
        try:
            sageresult = subprocess.check_output(["sage", "%s/sage/lattice.sage" % rootpath, str(publickey.n),str(publickey.p)],
                    timeout=self.timeout, stderr=subprocess.DEVNULL,).decode("utf8")
            p, q = [int(x) for x in sageresult.replace("[","").replace("]","").split(",")]
            priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
            return (priv_key, None)

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            return (None, None)


    def test(self):
        raise NotImplementedError

