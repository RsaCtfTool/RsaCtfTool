#!/usr/bin/python3

import subprocess

from RsaCtfTool.attacks.abstract_attack import SAGE_MIN_TIMEOUT, AbstractAttack
from RsaCtfTool.lib.coppersmith import CoppersmithError
from RsaCtfTool.lib.exceptions import FactorizationError
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60, d_known_bits=None):
        super().__init__(max(timeout, SAGE_MIN_TIMEOUT))
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/partial_d.sage"]
        self.d_known_bits = d_known_bits

    def attack(self, publickey, cipher=[], progress=True):
        """Run partial_d attack with a timeout"""
        if not isinstance(publickey, PrivateKey) or publickey.d is None:
            self.logger.error(
                "[!] partial_d attack is only for partial private keys not pubkeys..."
            )
            return None, None

        try:
            cmd = [
                "sage",
                f"{rootpath}/sage/partial_d.sage",
                str(publickey.n),
                str(publickey.e),
                str(publickey.d),
            ]
            if self.d_known_bits is not None:
                cmd.append(str(self.d_known_bits))

            result = subprocess.check_output(
                cmd,
                timeout=self.timeout,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            try:
                p, q = (int(value) for value in result.split())
                if p * q == publickey.n:
                    publickey.p = p
                    publickey.q = q
                    return self.create_private_key(publickey)
            except ValueError:
                pass
            return None, None
        except CoppersmithError as exc:
            if "Sage" in str(exc):
                self.logger.info("[!] partial_d attack requires Sage dependency")
            else:
                self.logger.error(f"[!] partial_d attack failed: {exc}")
            return None, None
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            ValueError,
            TypeError,
            FactorizationError,
            FileNotFoundError,
        ) as exc:
            self.logger.error(f"[!] partial_d attack failed: {exc}")
            
        return None, None

    def test(self):
        p = 1000037
        q = 1000121
        n = p * q
        e = 3
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        known_bits = 20
        d_low = d & ((1 << known_bits) - 1)
        key = PrivateKey(n=n, e=e, d=d_low)
        self.d_known_bits = known_bits

        priv, _ = self.attack(key, progress=False)
        return priv is not None and priv.p * priv.q == n
