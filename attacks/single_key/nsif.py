#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import subprocess
from lib.timeout import timeout
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath


logger = logging.getLogger("global_logger")


def attack(attack_rsa_obj, publickey, cipher=[]):
    try:
        result = subprocess.run(["lib/bin/nsif", publickey.n, "/dev/null"], capture_output=True)

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return (None, None)

    if b"FAIL" not in result and b":" in result:
        rresult = result.decode("utf-8").strip()
        return ("carmichael derivate : "+rresult, None)
    else:
        return (None, None)
