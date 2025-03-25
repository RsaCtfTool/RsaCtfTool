#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Try to decrypt c if m < n/e and small e"""
        if publickey.e not in [3, 5]:
            return None, None
        plain = []
        if (cipher is None) or (len(cipher) < 1):
            self.logger.info(
                "[-] No ciphertexts specified, skiping the cube_root test..."
            )
            return None, None
        for c in cipher:
            cipher_int = int.from_bytes(c, "big")
            low = 0
            high = cipher_int
            while low < high:
                mid = (low + high) >> 1
                if pow(mid, publickey.e) < cipher_int:
                    low = mid + 1
                else:
                    high = mid
            plain.append(low.to_bytes((low.bit_length() + 7) // 8, byteorder="big"))
        return None, plain

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA6FqEbjr1AgKR+WtbpHa3
1kvsipKxGoKPWtZDCLnrzvwnyVJVdlyvKEYVqVGHhiuJU2RH+8oSQsGF/yjMaOzc
CxB5/cCrXAFere5nsN2SQsAEG8xS1ccn9YWoEfKAJrsdxUZd5CoSkwlQzvX01JMN
ap5u35o+emK3/ny5QdzZpoie0xp4l8uCFR/cp33cvZj2+VOP4ch6szpTG2u0h7sP
SfNvAHUqrZ8YscwkWEUk6N+55mQMviuLV8cqY1O9Lu+Q8yL5EtZj0vtxhb4Pj/ad
+GMzczpiZxZDjfpEVHaP67ntl7Ut8zhfWjQ69/Un7hjjdqQuh7GPGfhGd6ohbX6E
uQIBAw==
-----END PUBLIC KEY-----"""

        cipher = 2205316413931134031074603746928247799030155221252519872650101242908540609117693035883827878696406295617513907962419726541451312273821810017858485722109359971259158071688912076249144203043097720816270550387459717116098817458584146690177125

        result = self.attack(
            PublicKey(key_data),
            [cipher.to_bytes((cipher.bit_length() + 7) // 8, "big")],
            progress=False,
        )
        return result != (None, None)
