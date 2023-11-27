#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
import subprocess
import os
from lib.utils import rootpath, TimeoutError, terminate_proc_tree
from lib.number_theory import invert, powmod


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """use elliptic curve method
        only works if the sageworks() function returned True
        """

        try:
            sageresult = []
            try:
                sage_proc = subprocess.Popen(
                    ["sage", f"{rootpath}/sage/ecm2.sage", str(publickey.n)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                sage_proc.wait(timeout=self.timeout)
                stdout, stderr = sage_proc.communicate()
                sageresult = stdout
                sageresult = sageresult[1:-2].split(b", ")
            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                TimeoutError,
            ):
                terminate_proc_tree(os.getpgid(sage_proc.pid))
                return (None, None)

            if len(sageresult) > 0:
                plain = []
                sageresults = [int(_.decode("utf-8")) for _ in sageresult]
                phi = 1
                for fac in sageresults:
                    phi = phi * (int(fac) - 1)

                if cipher is not None and len(cipher) > 0:
                    for c in cipher:
                        try:
                            cipher_int = int.from_bytes(c, "big")
                            d = invert(publickey.e, phi)
                            m = hex(powmod(cipher_int, d, publickey.n))[2::]
                            if len(m) % 2 != 0:
                                m = f"0{m}"
                            plain.append(bytes.fromhex(m))
                        except ZeroDivisionError:
                            continue

                return (None, plain)
            return (None, None)
        except KeyboardInterrupt:
            pass
        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGtMA0GCSqGSIb3DQEBAQUAA4GbADCBlwKBjw+vePt+ocGhwLTa5ONmKUvyhdAX
fU99ZyaGskpxn2DAkPett8hD/3eySSPMgd/y9oXYYsIm/0x5hfs7wLLh/Av5Qx7x
Or5ejGechok7VVoUbw6KTBB1fWy1lC39jFyTa4oZAGCQLf9nJRMYbDGzzrWnDm7K
ynOXWY/6keaIBeg2Xh7VkK5VOl33WjCkSARfAgMBAAE=
-----END PUBLIC KEY-----"""
        cipher = 7102577393434866594929140550804968099111271800384955683330956013020579564684516163830573468073604865935034522944441894535695787080676107364035121171758895218132464499398807752144702697548021940878072503062685829101838944413876346837812265739970980202827485238414586892442822429233004808821082551675699702413952211939387589361654209039260795229
        result = self.attack(
            PublicKey(key_data),
            [cipher.to_bytes((cipher.bit_length() + 7) // 8, "big")],
            progress=False,
        )
        return result != (None, None)
