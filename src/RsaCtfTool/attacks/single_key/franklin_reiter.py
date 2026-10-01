#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import franklin_reiter


class Attack(AbstractAttack):
    def __init__(self, timeout=60, fr_a=None, fr_b=None):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]
        self.fr_a = fr_a
        self.fr_b = fr_b

    def attack(self, publickey, cipher=[], progress=True):
        """
        Franklin-Reiter related message attack.

        Requires exactly two ciphertexts c1 and c2 passed via --decryptfile
        where m2 = fr_a * m1 + fr_b mod N.
        """
        if self.fr_a is None or self.fr_a == 0 or self.fr_b is None or self.fr_b == 0:
            self.logger.warning(
                "[!] Franklin-Reiter attack requires --fr-a and --fr-b to be non-zero"
            )
            return None, None

        if cipher is None or len(cipher) != 2:
            self.logger.warning(
                "[!] Franklin-Reiter attack requires exactly 2 ciphertexts "
                "(comma-separated via --decryptfile)"
            )
            return None, None

        try:
            c1 = int.from_bytes(cipher[0], byteorder="big")
            c2 = int.from_bytes(cipher[1], byteorder="big")
            a = int(self.fr_a)
            b = int(self.fr_b)
            n = int(publickey.n)
            e = int(publickey.e)
        except (TypeError, ValueError):
            self.logger.warning(
                "[!] Invalid Franklin-Reiter parameters or ciphertexts"
            )
            return None, None

        self.logger.info(
            f"[*] Franklin-Reiter parameters received: fr_a={a}, fr_b={b}"
        )

        try:
            result = franklin_reiter(
                n=n,
                e=e,
                c1=c1,
                c2=c2,
                a=a,
                b=b,
            )
        except (ValueError, TypeError):
            self.logger.warning("[!] Franklin-Reiter attack failed")
            return None, None

        if result is None:
            self.logger.info("[!] Franklin-Reiter attack found no solution")
            return None, None

        m1, m2 = result

        if m2 != (a * m1 + b) % n:
            self.logger.warning(
                "[!] Recovered messages do not satisfy the supplied relation"
            )
            return None, None

        self.logger.info(
            "[+] Franklin-Reiter attack recovered related messages"
        )
        self.logger.info(f"[+] m1 = {m1}")
        self.logger.info(f"[+] m2 = {m2}")

        m1_bytes = m1.to_bytes((m1.bit_length() + 7) // 8 or 1, byteorder="big")
        m2_bytes = m2.to_bytes((m2.bit_length() + 7) // 8 or 1, byteorder="big")

        return None, [m1_bytes, m2_bytes]

    def test(self):
        raise NotImplementedError