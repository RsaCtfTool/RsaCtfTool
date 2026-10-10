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
        p = 10103734139880193134105432658825866164227306239169601614210080645607316139414594625574542861614947937397753696147493139818816434444080183149867086884639911
        q = 13197779919106263590458129202517036640822606828551139453738096181958434773489812423719918239272304919149791481136453186259836952873839211322237554904771617
        n = p * q
        e = 65537
        near_p = p + 123456
        key = PrivateKey(n=n, e=e, p=near_p)
        priv, _ = self.attack(key, progress=False)
        return priv is not None and priv.p * priv.q == n
