#!/usr/bin/env python3

import binascii

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import STEREOTYPED_MAX_E, stereotyped_message
from RsaCtfTool.lib.coppersmith import CoppersmithError
from RsaCtfTool.lib.keys_wrapper import PublicKey
from RsaCtfTool.lib.utils import parse_text_or_hex

class Attack(AbstractAttack):
    def __init__(self, timeout=60, sm_prefix=None, sm_suffix=None, sm_len=None):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.required_binaries = ["sage"]
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

        n = int(publickey.n)
        e = int(publickey.e)

        if e > STEREOTYPED_MAX_E:
            self.logger.warning(
                f"[!] Stereotyped message attack requires e <= {STEREOTYPED_MAX_E}, got e={e}"
            )
            return None, None

        X = 256 ** self.sm_len
        if X <= 0 or pow(X, e) >= n:
            self.logger.warning(
                f"[!] Stereotyped message search space X={X} violates bound X < N^(1/{e})"
            )
            return None, None

        try:
            c = int.from_bytes(cipher[0], byteorder="big")
            prefix_val, prefix_len = parse_text_or_hex(self.sm_prefix)
            suffix_val, suffix_len = parse_text_or_hex(self.sm_suffix)

            # Construct A and B for M = A * x + B
            A = 256 ** suffix_len
            B = prefix_val * (256 ** (self.sm_len + suffix_len)) + suffix_val

            self.logger.info(f"[*] Stereotyped message parameters: A={A}, B={B}, X={X}")

            x = stereotyped_message(n, e, c, A, B, X)

            if x is not None:
                m = A * x + B
                m_bytes = m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")
                self.logger.info(f"[+] Stereotyped message recovered: {m_bytes}")
                return None, [m_bytes]
                
            return None, None
        except CoppersmithError as exc:
            if "Sage" in str(exc):
                self.logger.info("[!] Stereotyped message attack requires Sage dependency")
            else:
                self.logger.error(f"[!] Stereotyped message attack failed: {exc}")
            return None, None
        except (ValueError, TypeError, binascii.Error) as exc:
            self.logger.error(f"[!] Stereotyped message attack failed: {exc}")
            return None, None

    def test(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        p = 1000003
        q = 1000033
        n = p * q
        e = 3
        pub_pem = RSA.construct((n, e)).publickey().exportKey()
        key = PublicKey(pub_pem)
        msg = b"hello!"
        m = int.from_bytes(msg, "big")
        c = pow(m, e, n)
        c_bytes = c.to_bytes((c.bit_length() + 7) // 8 or 1, "big")

        self.sm_prefix = "hello"
        self.sm_suffix = None
        self.sm_len = 1

        _, decrypted = self.attack(key, [c_bytes], progress=False)
        return decrypted is not None and len(decrypted) > 0 and decrypted[0] == msg
