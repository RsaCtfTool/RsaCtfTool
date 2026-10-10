#!/usr/bin/env python3

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import SHORT_PAD_MAX_E, short_pad
from RsaCtfTool.lib.coppersmith import CoppersmithError
from RsaCtfTool.lib.keys_wrapper import PublicKey


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.required_binaries = ["sage"]

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

        if e > SHORT_PAD_MAX_E:
            self.logger.warning(
                f"[!] Short Pad attack requires e <= {SHORT_PAD_MAX_E}, got e={e}"
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
        except CoppersmithError as exc:
            if "Sage" in str(exc):
                self.logger.info("[!] Short Pad attack requires Sage dependency")
            else:
                self.logger.error(f"[!] Short Pad attack failed: {exc}")
            return None, None
        except (ValueError, TypeError) as exc:
            self.logger.error(f"[!] Short Pad attack failed: {exc}")
            return None, None

    def test(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        p = 1000003
        q = 1000033
        n = p * q
        e = 3
        pub_pem = RSA.construct((n, e)).publickey().exportKey()
        key = PublicKey(pub_pem)
        m1 = 12345
        m2 = 12347
        c1 = pow(m1, e, n)
        c2 = pow(m2, e, n)
        c1_bytes = c1.to_bytes((c1.bit_length() + 7) // 8 or 1, "big")
        c2_bytes = c2.to_bytes((c2.bit_length() + 7) // 8 or 1, "big")

        _, decrypted = self.attack(key, [c1_bytes, c2_bytes], progress=False)
        if decrypted and len(decrypted) == 2:
            r1 = int.from_bytes(decrypted[0], "big")
            r2 = int.from_bytes(decrypted[1], "big")
            return r1 == m1 and r2 == m2
        return False
