#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]
        self.wa_client = None

    def can_run(self):
        try:
            import wolframalpha

            app_id = os.environ.get("WA_API_KEY")
            assert app_id != None
            return True
        except Exception:
            return False

    def wa_query_factors(self, n, safe=True):
        tmp = []
        if safe and len(str(n)) > 192:
            self.logger.warning("[!] wolfram alpha only works for pubkeys < 192 digits")
            return
        q = "factor(%s)" % n
        if self.wa_client != None:
            res = self.wa_client.query(q)
            pods = list(res.pods)
            if len(pods) > 0:
                for pod in pods:
                    x = str(pod).replace("@", "").replace("'", '"')
                    pod = json.loads(x)
                    tmp = pod["subpod"]["plaintext"]
                    if tmp.find("×") > 0:
                        tmp = tmp.split(" ")[0]
                        # tmp2 = list(map(lambda x:int(x,16),tmp.split("×")))
                        tmp2 = list(map(int, tmp.split("×")))

                        return tmp2
            else:
                self.logger.error("[!] Could not get factorization from wolfram alpha")

    def attack(self, publickey, cipher=[], progress=True):
        """Factors available online?"""

        try:
            wa_enabled = True
            import wolframalpha

            app_id = os.environ.get("WA_API_KEY")
            wa_enabled = app_id != None
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
            return (None, None)
        else:
            self.wa_client = wolframalpha.Client(app_id)

        with timeout(self.timeout):
            try:
                factors = self.wa_query_factors(publickey.n)
                self.logger.info("Factors: %s" % str(factors))
                if factors != None and len(factors) > 1:
                    publickey.q = factors[
                        -1
                    ]  # Let it be the last prime wich is the bigger one
                    publickey.p = publickey.n // publickey.q
                    priv_key = PrivateKey(
                        p=int(publickey.p),
                        q=int(publickey.q),
                        e=int(publickey.e),
                        n=int(publickey.n),
                    )
                    return (priv_key, None)
                else:
                    return (None, None)
            except Exception as e:
                self.logger.error("[*] wolfram alpha could not get a factorization.")
                self.logger.debug(str(e))
                return (None, None)
            except TimeoutError:
                return (None, None)
