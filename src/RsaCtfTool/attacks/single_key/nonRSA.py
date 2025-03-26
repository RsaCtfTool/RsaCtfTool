#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.number_theory import is_prime, invmod, ilog2, introot, iroot, powmod


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickey, cipher=[], progress=True):
        """try to factorize n when is in the form: root^x, with root prime"""
        n = publickey.n
        e = publickey.e

        if is_prime(n):
            phi = n - 1
            d = invmod(e, phi)
            priv_key = PrivateKey(n=n, e=e, d=d)
            return (priv_key, None)

        for i in range(2, ilog2(n) + 1)[
            ::-1
        ]:  # we need to find the largest power first, otherwise, it would never be prime
            root, f = iroot(n, i)
            if f:
                # self.logger.info("n = %d^%d" % (root, i))
                if not is_prime(root):
                    self.logger.warning("[!] n = base^x, but base is not prime")
                    return (None, None)
                else:
                    phi = (root - 1) * powmod(root, i - 1, n)
                    d = invmod(e, phi)
                    # self.logger.info("d = %d" % d)
                    self.logger.warning(
                        "[!] Since this is not a valid RSA key, attempts to display the private key will fail"
                    )
                    priv_key = PrivateKey(n=n, e=e, d=d)
                    return (priv_key, None)

        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIIBIzANBgkqhkiG9w0BAQEFAAOCARAAMIIBCwKCAQILdjaT+X2D8Er2cSNPoG6k
oFBngdQrBrtcAwykNQ9hxbZzX2ZCImBZ7apKUsbJuuK1+1+jcaYJMMkGE9FeVgo/
7xu8KTvRX6Y5Y+RbQUzpqux64BBA9chkkOYoI2nZse0L/LrvqJBDAfeGRNS3MAOc
ipiPqnu3KcRgO+e2f/Nl8m7YqjQJsrMiRlUf8WstNVAn598EBgqw8oDt0pATVRSR
7Zc7xKbuehqOQNw2We3SJrP06+/IM7TQ9hTRv4v9u5lAa923neE4WXDa1HXEspeN
bSZ+A/Iw4Vt09AY9zPRqUzxfn7t9kTqsL9+/R8bdREA2byem8SWhCXvWJexmanUr
ZcECAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
