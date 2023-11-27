#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """Factor n if mininum of crt exponent is small enough"""
        try:
            p = int(
                subprocess.check_output(
                    [
                        "sage",
                        f"{rootpath}/sage/small_crt_exp.sage",
                        str(publickey.n),
                        str(publickey.e),
                        str(1 << 32),
                    ],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return (None, None)
        if p > 0:
            q = publickey.n // p
            privatekey = PrivateKey(
                p=p,
                q=q,
                e=publickey.e,
                n=publickey.n,
            )
            return (privatekey, None)
        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAQBdR3T47dmS7hhRFn9WeLj1
ZTYG0e0w9EcFbflJ7Z/FYjPCLxeFaIW1iMLCVXVsXLMqY255y/4hdEmPa2NP9X/b
72JJEUgPhi9o/2fzM+fFemdlo+ikXoFXRxpz3F0ACJm2FZidVfkJBQU8V7HO1Urn
FT9SuNt77CggNQliEKmSuNmnOfsN9U7694XltgqjxHOnnwKxm9qpvhte9xy6lSco
ckvf329/Ui4C2iBlfKkEzavhEgVj1wgCp/B77h/CHz+d62TnCO9WHWUQ/e0QcaiI
T0nv7RPKACYE5vkLXOwB7AiENf01ZCTRHtM0yDsmy3N18TsruxMMKf2tRfWtEGqt
AoIBABzfv6RIiqEg6T4OlTdnViAecGKXCFXg0cbzt5ZN8/ASV012mR44ogjIywYY
O6DolPNYGMSCVj1ZtXJn/gpVssH5PcrMLeamQoHs60VD5gBuz75qIsUtxOj6uPqK
PpThSunYWNg4NbEn0sVIhbKetRjCWDGGJqvQOSlUrcYs+E27VenZ55URQHjfqPcK
csmn70OHR+vD/gPq2qLb+STG4LGFpeez7Kssgio5hNRbeSvSd+DacrKcV3J/j+QW
IKglOWAqKED9Ahc9d5KufAO0WSf2H2GPiosSkn9LVrfIUAupPUf/xe4X8p4WvAfT
HiV/C1S+/8j2BWST7rdOtNN7SGc=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
