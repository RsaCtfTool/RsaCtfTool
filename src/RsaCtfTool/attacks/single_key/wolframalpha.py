#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import importlib.util
import os
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.keys_wrapper import PrivateKey


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]
        self.wa_client = None

    def can_run(self):
        # wolframalpha is a Python library, not an executable: check for an
        # importable module plus the API key instead of a PATH binary.
        if not super().can_run():
            return False
        if importlib.util.find_spec("wolframalpha") is None:
            self.logger.warning(
                f"Can't load {self.get_name()} because the wolframalpha "
                "python module is not installed (pip install wolframalpha)"
            )
            return False
        if os.environ.get("WA_API_KEY") is None:
            self.logger.warning(
                f"Can't load {self.get_name()} because WA_API_KEY is not set "
                "(see https://products.wolframalpha.com/api/documentation/)"
            )
            return False
        return True

    def wa_query_factors(self, n, safe=True):
        tmp = []
        if safe and len(str(n)) > 192:
            self.logger.warning("[!] wolfram alpha only works for pubkeys < 192 digits")
            return
        q = f"factor({n})"
        if self.wa_client is not None:
            res = self.wa_client.query(q)
            if pods := list(res.pods):
                for pod in pods:
                    # e.g. "3×5 (2 distinct prime factors)"; the pod's repr
                    # is not JSON, so read the subpod text directly.
                    for tmp in pod.texts:
                        if tmp and tmp.find("×") > 0:
                            tmp = tmp.split("(")[0].replace(" ", "")
                            factors = []
                            for f in tmp.split("×"):
                                base, _, exp = f.partition("^")
                                factors += [int(base)] * int(exp or 1)
                            return factors
            else:
                self.logger.error(
                    "[!] Could not get factorization from RsaCtfTool.wolfram alpha"
                )

    def attack(self, publickey, cipher=[], progress=True):
        """Factors available online?"""

        try:
            wa_enabled = True
            import wolframalpha

            app_id = os.environ.get("WA_API_KEY")
            wa_enabled = app_id is not None
        except Exception:
            self.logger.warning("[!] Wolfram Alpha is not enabled, install the lib.")
            wa_enabled = False

        if not wa_enabled:
            self.logger.warning(
                "[!] Wolfram Alpha is not enabled, check if ENV WA_API_KEY is set."
            )
            self.logger.warning(
                "[!] follow: https://products.wolframalpha.com/api/documentation/"
            )
            self.logger.warning("[!] export WA_API_KEY=XXXXXX-XXXXXXXXXX")
            self.wa_client = None
            return None, None
        else:
            self.wa_client = wolframalpha.Client(app_id)

        try:
            factors = self.wa_query_factors(publickey.n)
            self.logger.info(f"Factors: {str(factors)}")
            if factors is not None and len(factors) > 1:
                publickey.q = factors[
                    -1
                ]  # Let it be the last prime which is the bigger one
                publickey.p = publickey.n // publickey.q
                priv_key = PrivateKey(
                    p=int(publickey.p),
                    q=int(publickey.q),
                    e=int(publickey.e),
                    n=int(publickey.n),
                )
                return priv_key, None
            else:
                return None, None
        except Exception as e:
            self.logger.error("[*] wolfram alpha could not get a factorization.")
            self.logger.debug(str(e))
            return None, None
