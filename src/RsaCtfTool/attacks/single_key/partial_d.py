#!/usr/bin/python3

import subprocess
from RsaCtfTool.attacks.abstract_attack import AbstractAttack, SAGE_MIN_TIMEOUT
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.utils import rootpath
from RsaCtfTool.lib.exceptions import FactorizationError


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(max(timeout, SAGE_MIN_TIMEOUT))
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/partial_d.sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run partial_d attack with a timeout"""
        if not isinstance(publickey, PrivateKey) or publickey.d is None:
            self.logger.error(
                "[!] partial_d attack is only for partial private keys not pubkeys..."
            )
            return None, None

        try:
            import shutil
            if shutil.which("sage"):
                cmd = [
                    "sage",
                    f"{rootpath}/sage/partial_d.sage",
                    str(publickey.n),
                    str(publickey.e),
                    str(publickey.d),
                ]
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
            else:
                from RsaCtfTool.lib.algos import partial_d
                p, q = partial_d(publickey.n, publickey.e, publickey.d)
                if p is not None and q is not None:
                    if p * q != publickey.n:
                        raise FactorizationError("Returned factors do not match n")
                    publickey.p = p
                    publickey.q = q
                    return self.create_private_key(publickey)
        except Exception as exc:
            self.logger.error(f"[!] partial_d attack failed: {exc}")
            
        return None, None

    def test(self):
        raise NotImplementedError
