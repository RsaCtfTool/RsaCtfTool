#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.number_theory import gcd, common_modulus_related_message
from lib.crypto_wrapper import long_to_bytes, bytes_to_long
import itertools


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def common_modulus_related_message_attack(self, c1, c2, k1, k2):
        if k1.n != k2.n:
            return None

        c1 = bytes_to_long(c1)
        c2 = bytes_to_long(c2)

        decrypted_message = common_modulus_related_message(k1.e, k2.e, k1.n, c1, c2)
        return long_to_bytes(decrypted_message)

    def attack(self, publickeys, cipher=[]):
        """Common modulus attack"""
        if len(publickeys) < 2:
            return (None, None)
        if cipher is None or len(cipher) < 2:
            return (None, None)

        plains = []
        for k1, k2 in itertools.combinations(publickeys, 2):
            plains.extend(
                self.common_modulus_related_message_attack(c1, c2, k1, k2)
                for c1, c2 in itertools.combinations(cipher, 2)
            )
        if all(_ is None for _ in plains):
            plains = None

        return (None, plains)

    def test(self):
        from lib.keys_wrapper import PublicKey
        import base64

        key1_data = """-----BEGIN PUBLIC KEY-----
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtbdQAzdaO7GHXxUsVZ+FmcddA
        Hrugq+azkVdfgnHu6teK3hDQlk0BdNz9LlQT3BoHXg5/g9FDv3bBwaulpQEQPlGM
        UXEUnQAJ69KSVaLxHb5Wmb0vqX/qySKc8Hseqt5wbXklOrnZeHJ3Hm3mUeIplpWP
        f19C6goN3bUGrrniwwIDAQAB
        -----END PUBLIC KEY-----"""
        key2_data = """-----BEGIN PUBLIC KEY-----
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtbdQAzdaO7GHXxUsVZ+FmcddA
        Hrugq+azkVdfgnHu6teK3hDQlk0BdNz9LlQT3BoHXg5/g9FDv3bBwaulpQEQPlGM
        UXEUnQAJ69KSVaLxHb5Wmb0vqX/qySKc8Hseqt5wbXklOrnZeHJ3Hm3mUeIplpWP
        f19C6goN3bUGrrniwwIDBTy3
        -----END PUBLIC KEY-----"""

        cipher1 = base64.b64decode(
            "BzFd4riBUZdFuPCkB3LOh+5iyMImeQ/saFLVD+ca2L8VKSz0+wtTaL55RRpHBAQdl24Fb3XyVg2N9UDcx3slT+vZs7tr03W7oJZxVp3M0ihoCwer3xZNieem8WZQvQvyNP5s5gMT+K6pjB9hDFWWmHzsn7eOYxRJZTIDgxA4k2w="
        )
        cipher2 = base64.b64decode(
            "jmVRiKyVPy1CHiYLl8fvpsDAhz8rDa/Ug87ZUXZ//rMBKfcJ5MqZnQbyTJZwSNASnQfgel3J/xJsjlnf8LoChzhgT28qSppjMfWtQvR6mar1GA0Ya1VRHkhggX1RUFA4uzL56X5voi0wZEpJITUXubbujDXHjlAfdLC7BvL/5+w="
        )
        print("cypher decoded..")
        result = self.attack(
            [PublicKey(key1_data), PublicKey(key2_data)],
            [
                cipher1,
                cipher2,
            ],
        )
        print(result)
        return result != (None, None)
