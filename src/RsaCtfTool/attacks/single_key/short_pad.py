#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import short_pad

class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def attack(self, publickey, cipher=[], progress=True):
        """
        Coppersmith Short Pad Attack.
        
        Requires exactly two ciphertexts c1 and c2 passed via --decryptfile
        where m2 = m1 + delta mod N and delta is unknown but small.
        """
        if cipher is None or len(cipher) != 2:
            self.logger.warning(
                "[!] Short Pad attack requires exactly 2 ciphertexts "
                "(comma-separated via --decryptfile)"
            )
            return None, None

        try:
            c1 = int.from_bytes(cipher[0], byteorder="big")
            c2 = int.from_bytes(cipher[1], byteorder="big")
            n = int(publickey.n)
            e = int(publickey.e)
        except (TypeError, ValueError):
            self.logger.warning(
                "[!] Invalid Short Pad ciphertexts"
            )
            return None, None

        self.logger.info("[*] Performing Short Pad attack...")

        try:
            m1, m2 = short_pad(n, e, c1, c2)
            
            if m1 is not None and m2 is not None:
                self.logger.info("[+] Short Pad attack recovered related messages")
                self.logger.info(f"[+] m1 = {m1}")
                self.logger.info(f"[+] m2 = {m2}")
                
                m1_bytes = m1.to_bytes((m1.bit_length() + 7) // 8 or 1, byteorder="big")
                m2_bytes = m2.to_bytes((m2.bit_length() + 7) // 8 or 1, byteorder="big")
                
                return None, [m1_bytes, m2_bytes]
                
            return None, None
        except Exception as exc:
            self.logger.error(f"[!] Short Pad attack failed: {exc}")
            return None, None

    def test(self):
        raise NotImplementedError
