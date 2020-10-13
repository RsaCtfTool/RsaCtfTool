#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from rsactftool.lib.keys_wrapper import PrivateKey


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Try to uncipher c if m < n/e and small e
    """
    if publickey.e == 3 or publickey.e == 5:
        plain = []
        for c in cipher:
            cipher_int = int.from_bytes(c, "big")
            low = 0
            high = cipher_int
            while low < high:
                mid = (low + high) // 2
                if pow(mid, publickey.e) < cipher_int:
                    low = mid + 1
                else:
                    high = mid
            plain.append(low.to_bytes((low.bit_length() + 7) // 8, byteorder="big"))
        return (None, plain)
    return (None, None)
