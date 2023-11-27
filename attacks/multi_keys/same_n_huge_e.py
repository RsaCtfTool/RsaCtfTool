#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.crypto_wrapper import number
from lib.number_theory import gcdext, powmod


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Same n huge e attack"""
        if not isinstance(publickey, list):
            return (None, None)

        if len({_.n for _ in publickey}) == 1:
            n = publickey[0].n

            e_array = [k.e for k in publickey]
            if (cipher is None) or (len(cipher) < 2):
                self.logger.info(
                    "[-] Lack of ciphertexts, skiping the same_n_huge_e test..."
                )
                return (None, None)

            # e1*s1 + e2*s2 = 1
            _, s1, s2 = gcdext(e_array[0], e_array[1])

            # m ≡ c1^s1 * c2*s2 mod n
            cipher_bytes = [int.from_bytes(c, "big") for c in cipher]
            plain = (
                powmod(cipher_bytes[0], s1, n) * powmod(cipher_bytes[1], s2, n)
            ) % n

            return None, number.long_to_bytes(plain)

        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key1_data = """-----BEGIN PUBLIC KEY-----
        MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQCenPk2Mrwap7Du5QA+ikywFpd+
        qlErff2id/KC3hlQ40+9XvVTAsNi+d9hm4bInV4hBG8Qj98fOnyy2xG0MZr3RCko
        x9vkk2GgNSkiUZT0xy7DGI2UDs/2tnFlUPDbNPRJddErhj1P1Vhsyru9BOoftfR1
        aE7ad9DdkTtjrvsZWQIBEQ==
        -----END PUBLIC KEY-----"""
        key2_data = """-----BEGIN PUBLIC KEY-----
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCenPk2Mrwap7Du5QA+ikywFpd+
        qlErff2id/KC3hlQ40+9XvVTAsNi+d9hm4bInV4hBG8Qj98fOnyy2xG0MZr3RCko
        x9vkk2GgNSkiUZT0xy7DGI2UDs/2tnFlUPDbNPRJddErhj1P1Vhsyru9BOoftfR1
        aE7ad9DdkTtjrvsZWQIDAQAB
        -----END PUBLIC KEY-----"""

        cipher1 = 54995751387258798791895413216172284653407054079765769704170763023830130981480272943338445245689293729308200574217959018462512790523622252479258419498858307898118907076773470253533344877959508766285730509067829684427375759345623701605997067135659404296663877453758701010726561824951602615501078818914410959610
        cipher2 = 91290935267458356541959327381220067466104890455391103989639822855753797805354139741959957951983943146108552762756444475545250343766798220348240377590112854890482375744876016191773471853704014735936608436210153669829454288199838827646402742554134017280213707222338496271289894681312606239512924842845268366950

        result = self.attack(
            [PublicKey(key1_data), PublicKey(key2_data)],
            [
                cipher1.to_bytes((cipher1.bit_length() + 7) // 8, "big"),
                cipher2.to_bytes((cipher2.bit_length() + 7) // 8, "big"),
            ],
            progress=False,
        )

        return result != (None, None)
