#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.timeout import timeout
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, attack_rsa_obj, timeout=60):
        super().__init__(attack_rsa_obj, timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.sage_required = True

    def attack(self, publickey, cipher=[]):
        try:
            sageresult = subprocess.check_output(
                ["sage", "%s/sage/roca_attack.py" % rootpath, str(publickey.n)],
                timeout=self.timeout,
                stderr=subprocess.DEVNULL,
            )

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return (None, None)

        if b"FAIL" not in sageresult and b":" in sageresult:
            sageresult = sageresult.decode("utf-8").strip()
            p, q = map(int, sageresult.split(":"))
            priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
            return (priv_key, None)
        else:
            return (None, None)


if __name__ == "__main__":
    attack = Attack()
    attack.test()