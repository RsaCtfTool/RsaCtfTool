#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60, ecmdigits=25):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.required_binaries = ["sage"]
        self.ecmdigits = ecmdigits

    def attack(self, publickey, cipher=[], progress=True):
        """use elliptic curve method, may return a prime or may never return
        only works if the sageworks() function returned True
        """

        try:
            try:
                if self.ecmdigits is not None:
                    sageresult = int(
                        subprocess.check_output(
                            [
                                "sage",
                                "%s/sage/ecm.sage" % rootpath,
                                str(publickey.n),
                                str(self.ecmdigits),
                            ],
                            timeout=self.timeout,
                            stderr=subprocess.DEVNULL,
                        )
                    )
                else:
                    sageresult = int(
                        subprocess.check_output(
                            ["sage", "%s/sage/ecm.sage" % rootpath, str(publickey.n)],
                            timeout=self.timeout,
                            stderr=subprocess.DEVNULL,
                        )
                    )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                return (None, None)

            if sageresult > 0:
                publickey.p = sageresult
                publickey.q = publickey.n // publickey.p
                try:
                    priv_key = PrivateKey(
                        int(publickey.p),
                        int(publickey.q),
                        int(publickey.e),
                        int(publickey.n),
                    )
                    return (priv_key, None)
                except NotImplementedError:
                    return (None, None)
            return (None, None)
        except KeyboardInterrupt:
            pass
        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgRBNZTe9G/tNqNNwNZz4JDgmOVmk
ZheJybt5Ew4jKnUjKcfLY8rs8nGCbVdYyKUdq3WQSKCsYy2StxBSZn4qgxoA7G5n
DGWWBFisWHeLM+lUr3jfnOTbnAZt3utu8plSMbv2irXohbDRxN/6NgzoQMVcmhIQ
bD3qa8mMScpXZXD2qwIDAQAB
-----END PUBLIC KEY-----"""
        self.timeout = 180
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
