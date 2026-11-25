#!/usr/bin/env python3

import ast
import subprocess

from RsaCtfTool.attacks.abstract_attack import SAGE_MIN_TIMEOUT, AbstractAttack
from RsaCtfTool.lib.coppersmith import CoppersmithError
from RsaCtfTool.lib.keys_wrapper import PrivateKey
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

        except CoppersmithError as exc:
            if "Sage" in str(exc):
                self.logger.info("[!] lattice attack requires Sage dependency")
            else:
                self.logger.error(f"[!] lattice attack failed: {exc}")
            return None, None
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            SyntaxError,
            TypeError,
            ValueError,
            FileNotFoundError,
        ) as exc:
            self.logger.error(f"[!] lattice attack failed: {exc}")
            return None, None

    def test(self):
        p = 11814314815079808793202754845823415996236940468297640287934698158609319560359607901183228305190944525696915884370873052504610782679806230947564723036978431

        q = 6850324446788129079827624526540564637521699316237423751807524631616380311577742212267150797376483718097199550312926103390141403454742728224455964881423377
        n = p * q
        e = 65537
        near_p = p + 123456
        key = PrivateKey(n=n, e=e, p=near_p)
        priv, _ = self.attack(key, progress=False)
        return (
            priv is not None
            and priv.n == n
            and {int(priv.p), int(priv.q)} == {p, q}
        )
