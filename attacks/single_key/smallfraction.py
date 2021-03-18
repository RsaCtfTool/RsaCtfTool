#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, attack_rsa_obj, timeout=60):
        super().__init__(attack_rsa_obj, timeout)
        self.speed = AbstractAttack.speed_enum["medium"]
        self.sage_required = True

    def attack(self, publickey, cipher=[]):
        """Code/idea from Renaud Lifchitz's talk 15 ways to break RSA security @ OPCDE17
        only works if the sageworks() function returned True
        """
        try:
            r = subprocess.check_output(
                ["sage", "%s/sage/smallfraction.sage" % rootpath, str(publickey.n)],
                timeout=attack_rsa_obj.args.timeout,
                stderr=subprocess.DEVNULL,
            )
            sageresult = int(r)
            if sageresult > 0:
                publickey.p = sageresult
                publickey.q = publickey.n // publickey.p
                priv_key = PrivateKey(
                    int(publickey.p),
                    int(publickey.q),
                    int(publickey.e),
                    int(publickey.n),
                )
                return (priv_key, None)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return (None, None)
        return (None, None)


if __name__ == "__main__":
    attack = Attack()
    attack.test()