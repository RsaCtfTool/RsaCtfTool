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

import subprocess
import re
import logging
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.keys_wrapper import PrivateKey


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
                "-siqsT",
                str(self.timeout),
                "-threads",
                str(self.threads),
            ],
            input=f"siqs({self.n})\n".encode(),
            # yafu's own -siqsT budget is self.timeout; give the process a
            # grace period on top so it can print results before we kill it.
            timeout=self.timeout + 30,
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
        self.primes = primesfound

        if len(primesfound) == 2:
            self.p = primesfound[0]
            self.q = primesfound[1]

        if len(primesfound) > 2:
            self.logger.info(f"[*] {len(primesfound)} primes found (Multi-Prime RSA).")

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
        # SIQS becomes impractical well below 1024 bits; ~512 bits (155
        # digits) is the realistic ceiling, and yafu rejects larger inputs
        # with "input too big for SIQS" anyway.
        if publickey.n.bit_length() > 512:
            self.logger.error("[!] Warning: Modulus too large for SIQS attack module")
            return None, None

        siqsobj = SiqsAttack(publickey.n, self.timeout)
        try:
            siqsobj.doattack()
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            OSError,
        ):
            # yafu crashed, hit the timeout, or vanished from PATH after the
            # can_run preflight - all of these are a plain miss.
            return None, None

        if hasattr(siqsobj, "primes") and len(siqsobj.primes) > 2:
            import functools
            prod = functools.reduce(lambda x, y: x * y, siqsobj.primes, 1)
            if prod == publickey.n:
                return self.create_private_key_from_primes(
                    siqsobj.primes, publickey.e, publickey.n
                )

        if siqsobj.p and siqsobj.q:
            publickey.q = siqsobj.q
            publickey.p = siqsobj.p
            return self.create_private_key_from_pqe(
                publickey.p, publickey.q, publickey.e, publickey.n
            )

        return None, None

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAM7gDElzPMzEU1htubZ8KvfHomChbmwN
ZrJ1fw38h5l1AgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
