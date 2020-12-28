#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from lib.rsalibnum import invmod
import binascii
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError


def attack(attack_rsa_obj, publickey, cipher=[]):
    """ "primes" of the form 31337 - 313333337 - see ekoparty 2015 "rsa 2070"
    not all numbers in this form are prime but some are (25 digit is prime)
    """
    with timeout(attack_rsa_obj.args.timeout):
        try:
            maxlen = 25  # max number of digits in the final integer
            for i in tqdm(range(maxlen - 4)):
                prime = int("3133" + ("3" * i) + "7")
                if publickey.n % prime == 0:
                    publickey.p = prime
                    publickey.q = publickey.n // publickey.p
                    priv_key = PrivateKey(
                        p=int(publickey.p),
                        q=int(publickey.q),
                        e=int(publickey.e),
                        n=int(publickey.n),
                    )

                    return (priv_key, None)
        except TimeoutError:
            return (None, None)
    return (None, None)
