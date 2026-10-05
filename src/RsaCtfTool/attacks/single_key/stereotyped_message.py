#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import stereotyped_message
import binascii

class Attack(AbstractAttack):
    def __init__(self, timeout=60, sm_prefix=None, sm_suffix=None, sm_len=None):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]
        self.sm_prefix = sm_prefix
        self.sm_suffix = sm_suffix
        self.sm_len = sm_len

    def attack(self, publickey, cipher=[], progress=True):
        """
        Stereotyped message attack (Univariate Coppersmith).
        Recovers the message if a prefix or suffix is known and the 
        unknown part is sufficiently small.
        """
        if self.sm_len is None:
            return None, None

        if self.sm_prefix is None and self.sm_suffix is None:
            return None, None

        if not cipher or len(cipher) == 0:
            self.logger.warning(
                "[!] Stereotyped message attack requires a ciphertext via --decryptfile or --decrypt"
            )
            return None, None

        c = int.from_bytes(cipher[0], byteorder="big")
        n = int(publickey.n)
        e = int(publickey.e)

        try:
            prefix_val = 0
            prefix_len = 0
            if self.sm_prefix:
                if self.sm_prefix.startswith("0x"):
                    prefix_bytes = binascii.unhexlify(self.sm_prefix[2:])
                else:
                    try:
                        prefix_bytes = binascii.unhexlify(self.sm_prefix)
                    except binascii.Error:
                        prefix_bytes = self.sm_prefix.encode()
                prefix_val = int.from_bytes(prefix_bytes, "big")
                prefix_len = len(prefix_bytes)

            suffix_val = 0
            suffix_len = 0
            if self.sm_suffix:
                if self.sm_suffix.startswith("0x"):
                    suffix_bytes = binascii.unhexlify(self.sm_suffix[2:])
                else:
                    try:
                        suffix_bytes = binascii.unhexlify(self.sm_suffix)
                    except binascii.Error:
                        suffix_bytes = self.sm_suffix.encode()
                suffix_val = int.from_bytes(suffix_bytes, "big")
                suffix_len = len(suffix_bytes)

            # Construct A and B for M = A * x + B
            A = 256 ** suffix_len
            B = prefix_val * (256 ** (self.sm_len + suffix_len)) + suffix_val
            X = 256 ** self.sm_len

            self.logger.info(f"[*] Stereotyped message parameters: A={A}, B={B}, X={X}")

            x = stereotyped_message(n, e, c, A, B, X)

            if x is not None:
                m = A * x + B
                m_bytes = m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")
                self.logger.info(f"[+] Stereotyped message recovered: {m_bytes}")
                return None, [m_bytes]
                
            return None, None
        except Exception as e:
            self.logger.error(f"[!] Stereotyped message attack failed: {e}")
            return None, None

    def test(self):
        raise NotImplementedError
