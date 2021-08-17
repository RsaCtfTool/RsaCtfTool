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

import os
import pathlib
import re
import logging
from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError


class SiqsAttack(object):
    def __init__(self, n, timeout=180):
        """Configuration"""
        self.logger = logging.getLogger("global_logger")
        self.threads = 2  # number of threads
        self.timeout = timeout  # max time to try the sieve

        self.n = n
        self.p = None
        self.q = None

    def testyafu(self):
        """Test if yafu can be run"""

        try:
            yafutest = subprocess.check_output(
                ["yafu", "siqs(1549388302999519)"],
                timeout=self.timeout,
                stderr=subprocess.DEVNULL,
            )
        except:
            yafutest = b""

        return b"48670331" in yafutest

    def doattack(self):
        """Perform attack"""
        yafurun = subprocess.check_output(
            [
                "yafu",
                "siqs(" + str(self.n) + ")",
                "-siqsT",
                str(self.timeout),
                "-threads",
                str(self.threads),
            ],
            timeout=self.timeout,
            stderr=subprocess.DEVNULL,
        )

        primesfound = []

        if b"input too big for SIQS" in yafurun:
            self.logger.info("[-] Modulus too big for SIQS method.")
            return

        for line in yafurun.splitlines():
            if re.search(b"^P[0-9]+ = [0-9]+$", line):
                primesfound.append(int(line.split(b"=")[1]))

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
        with timeout(self.timeout):
            try:
                if publickey.n.bit_length() > 1024:
                    self.logger.error(
                        "[!] Warning: Modulus too large for SIQS attack module"
                    )
                    return (None, None)

                siqsobj = SiqsAttack(publickey.n, self.timeout)

                if siqsobj.testyafu():
                    siqsobj.doattack()
                else:
                    return (None, None)

                if siqsobj.p and siqsobj.q:
                    publickey.q = siqsobj.q
                    publickey.p = siqsobj.p
                    priv_key = PrivateKey(
                        int(publickey.p),
                        int(publickey.q),
                        int(publickey.e),
                        int(publickey.n),
                    )
                    return (priv_key, None)
            except TimeoutError:
                return (None, None)
        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAM7gDElzPMzEU1htubZ8KvfHomChbmwN
ZrJ1fw38h5l1AgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
