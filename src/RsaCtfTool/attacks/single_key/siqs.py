#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# Implements a class which simply interfaces to Yafu
#
# We implement SIQS in this but this can be extended to
# other factorisation methods supported by Yafu very
# simply.
#
# @CTFKris - https://github.com/sourcekris/RsaCtfTool/
#

import re
import logging
from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey


class SiqsAttack(object):
    def __init__(self, n, timeout=180):
        """Configuration"""
        self.logger = logging.getLogger("global_logger")
        self.threads = 2  # number of threads
        self.timeout = timeout  # max time to try the sieve

        self.n = n
        self.p = None
        self.q = None

    def doattack(self):
        """Perform attack"""
        yafurun = subprocess.check_output(
            [
                "yafu",
                f"siqs({str(self.n)})",
                "-siqsT",
                str(self.timeout),
                "-threads",
                str(self.threads),
            ],
            timeout=self.timeout,
            stderr=subprocess.DEVNULL,
        )

        if b"input too big for SIQS" in yafurun:
            self.logger.error("[-] Modulus too big for SIQS method.")
            return

        primesfound = [
            int(line.split(b"=")[1])
            for line in yafurun.splitlines()
            if re.search(b"^P[0-9]+ = [0-9]+$", line)
        ]

        if len(primesfound) == 2:
            self.p = primesfound[0]
            self.q = primesfound[1]

        if len(primesfound) > 2:
            self.logger.warning("[*] > 2 primes found. Is key multiprime?")

        if len(primesfound) < 2:
            self.logger.error("[*] SIQS did not factor modulus.")

        return


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.required_binaries = ["yafu"]
        self.logger = logging.getLogger("global_logger")
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Try to factorize using yafu"""
        if publickey.n.bit_length() > 1024:
            self.logger.error("[!] Warning: Modulus too large for SIQS attack module")
            return None, None

        siqsobj = SiqsAttack(publickey.n, self.timeout)
        siqsobj.doattack()

        if siqsobj.p and siqsobj.q:
            publickey.q = siqsobj.q
            publickey.p = siqsobj.p
            priv_key = PrivateKey(
                int(publickey.p),
                int(publickey.q),
                int(publickey.e),
                int(publickey.n),
            )
            return priv_key, None

        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAM7gDElzPMzEU1htubZ8KvfHomChbmwN
ZrJ1fw38h5l1AgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
