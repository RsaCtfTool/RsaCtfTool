#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.number_theory import introot, chinese_remainder
from attacks.abstract_attack import AbstractAttack
from collections import defaultdict


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickeys, cipher=[], progress=True):
        """Hastad attack for low public exponent
        this has found success for e = 3
        """
        if not isinstance(publickeys, list):
            return None, None

        if cipher is None or len(cipher) == 0:
            return None, None

        ciphers = [int.from_bytes(c, "big") for c in cipher]

        es = defaultdict(lambda: ([], []))  # e -> (list of modulus, list of ciphers)

        for ind, key in enumerate(publickeys):
            es[key.e][0].append(key.n)
            es[key.e][1].append(ciphers[ind])

        for e in es:
            maybe_plaintext_to_the_e = chinese_remainder(*es[e])
            maybe_plaintext = int(introot(maybe_plaintext_to_the_e, e))

            if (
                pow(maybe_plaintext, e) == maybe_plaintext_to_the_e
            ):  # Found the ciphertext
                plaintext = maybe_plaintext.to_bytes(
                    (maybe_plaintext.bit_length() + 7) // 8, "big"
                )
                return None, plaintext

        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        # From PICO CTF Level 3 Crypto
        keys = [
            """-----BEGIN PUBLIC KEY-----
            MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQWRvnuRNTVQJP6hBLizABSDFX+4
            fq5hMTEZGTCYE68yr+8m86qLUFicM+oahsqmJh9GY8tBiOtDOtffW+uHX1iTrywc
            OiDRXaauJRc6YOVqjignxDbDJFhlNj0p4ixlzSq2jhjWLUBT2t0K7kFF3ftBQ8pZ
            x6ZJrpDSV6zINgjFiwIBAw==
            -----END PUBLIC KEY-----""",
            """-----BEGIN PUBLIC KEY-----
            MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQJB+GsN38eQ+HOLorjSjgLlmm48
            mfEjWmmHwUNI9l4sS7MEK+IS46WfC91+ztCPY9H52AQDwXZpDKLkc0uJ7M0hWZdp
            QnyuKoyFPDI5cp52fQoU+7r1Ac4/j9iDQH0XHAHsfzJqmpmFy8q9CPBSuG0S2vzK
            pQc4Io4xb5TVeJDjdQIBAw==
            -----END PUBLIC KEY-----""",
            """-----BEGIN PUBLIC KEY-----
            MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQazf7/WQoGtCLesOf+LsuhmCFS2
            N0Msd/rwjlcpmVS3hcmHAUDaxh/B1fkrQ8jrB04cZBcaDD7W4axVj3VfA9tj0gWD
            g01Roo8LP9taw1Rb4Zv2w1mjrQ9et/jQaU0iODcCHSgsEsorGF/Y0F/Cs+f2ld1e
            ZBJzCth/ZPJAB9eFKwIBAw==
            -----END PUBLIC KEY-----""",
        ]
        ciphers = [
            261345950255088824199206969589297492768083568554363001807292202086148198677263604958247638518239089545015544140878441375704999371548235205708718116265184277053405937898051706510050325657424248032017194168466912140157665066494528590260879287464030275170787644749401275343677539640347609231708327119700420050952,
            147535246350781145803699087910221608128508531245679654307942476916759248448374688671157343167317710093065456240596223287904483080800880319712443044372346198448258006286828355244986776657425121775659144630571637596283100201930037799979864768887420615134036083295810488407488056595808231221356565664602262179441,
            633230627388596886579908367739501184580838393691617645602928172655297372282390454586345936209841638502749645277206386289490247066959822668419069562380546618337543323956757811325946190976649051724173510367477564435069180291575386473277111391106753472257905377429144209593931226163885326581862398737742032667573,
        ]

        result = self.attack(
            [PublicKey(key) for key in keys],
            [
                cipher.to_bytes((cipher.bit_length() + 7) // 8, "big")
                for cipher in ciphers
            ],
            progress=False,
        )

        return result[1] is not None
