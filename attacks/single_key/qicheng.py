#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import subprocess
from lib.timeout import timeout
from lib.keys_wrapper import PrivateKey

__SAGE__ = True

logger = logging.getLogger("global_logger")


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Qi Cheng - A New Class of Unsafe Primes
        """
    try:
        sageresult = int(
            subprocess.check_output(
                ["sage", "./sage/qicheng.sage", str(publickey.n)],
                timeout=attack_rsa_obj.args.timeout,
            )
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return (None, None)

    if sageresult > 0:
        p = sageresult
        q = publickey.n // sageresult
        priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
        return (priv_key, None)
    else:
        return (None, None)
