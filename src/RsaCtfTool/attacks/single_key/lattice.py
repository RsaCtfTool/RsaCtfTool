#!/usr/bin/env python3

import ast
import subprocess
from RsaCtfTool.attacks.abstract_attack import AbstractAttack, SAGE_MIN_TIMEOUT
from RsaCtfTool.lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(max(timeout, SAGE_MIN_TIMEOUT))
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/lattice.sage"]

    def attack(self, publickey, cipher=[], progress=True):
        try:
            if getattr(publickey, "p", None) is None:
                self.logger.error(
                    "[!] simple lattice attack is for partial keys only..."
                )
                return None, None
                
            import shutil
            if shutil.which("sage"):
                sageresult = subprocess.check_output(
                    [
                        "sage",
                        f"{rootpath}/sage/lattice.sage",
                        str(publickey.n),
                        str(publickey.p),
                    ],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                p, q = (int(value) for value in ast.literal_eval(sageresult))
                if p * q != publickey.n:
                    raise ValueError("Sage returned factors that do not match n")
                return self.create_private_key_from_pqe(p, q, publickey.e, publickey.n)
            else:
                from RsaCtfTool.lib.algos import lattice_partial_p
                p, q = lattice_partial_p(publickey.n, publickey.p)
                
                if p is not None and q is not None:
                    return self.create_private_key_from_pqe(
                        p, q, publickey.e, publickey.n
                    )
                return None, None

        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            SyntaxError,
            TypeError,
            ValueError,
        ):
            return (None, None)

    def test(self):
        raise NotImplementedError
