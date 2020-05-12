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
    try:
        sageresult = subprocess.check_output(
            ["sage", "./sage/roca_attack.py", str(publickey.n)],
            timeout=attack_rsa_obj.args.timeout,
        )

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return (None, None)

    if b"FAIL" not in sageresult and b":" in sageresult:
        sageresult = sageresult.decode("utf-8").strip()
        p, q = map(int, sageresult.split(":"))
        priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
        return (priv_key, None)
    else:
        return (None, None)
