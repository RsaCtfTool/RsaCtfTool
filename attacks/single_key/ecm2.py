#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.rsalibnum import modInv
from lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, attack_rsa_obj, timeout=60):
        super().__init__(attack_rsa_obj, timeout)
        self.speed = AbstractAttack.speed_enum["medium"]
        self.sage_required = True

    def attack(self, publickey, cipher=[]):
        """use elliptic curve method
        only works if the sageworks() function returned True
        """

        try:
            sageresult = []
            try:
                sageresult = subprocess.check_output(
                    ["sage", "%s/sage/ecm2.sage" % rootpath, str(publickey.n)],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
                sageresult = sageresult[1:-2].split(b", ")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                return (None, None)

            if len(sageresult) > 0:
                plain = []
                sageresults = [int(_.decode("utf-8")) for _ in sageresult]
                phi = 1
                for fac in sageresults:
                    phi = phi * (int(fac) - 1)

                for c in cipher:
                    try:
                        cipher_int = int.from_bytes(c, "big")
                        d = modInv(publickey.e, phi)
                        m = hex(pow(cipher_int, d, publickey.n))[2::]
                        plain.append(bytes.fromhex(m))
                    except:
                        continue

                return (None, plain)
            return (None, None)
        except KeyboardInterrupt:
            pass
        return (None, None)


if __name__ == "__main__":
    attack = Attack()
    attack.test()