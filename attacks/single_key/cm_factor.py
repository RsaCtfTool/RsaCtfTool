#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from tqdm import tqdm
import logging
import subprocess
from lib.timeout import timeout
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath

__SAGE__ = True

logger = logging.getLogger("global_logger")


def attack(attack_rsa_obj, publickey, cipher=[]):
    """cm_factor attack"""
    D_candidates = [3,11,19,43,67,163]
    sageresult = 0
    for D_candidate in tqdm(D_candidates):
        try:
            sageresult = subprocess.check_output(
                [
                    "sage",
                    "%s/sage/cm_factor.sage" % rootpath,
                    "-N",
                    str(publickey.n),
                    "-D",
                    str(D_candidate),
                ],
                timeout=attack_rsa_obj.args.timeout,
                stderr=subprocess.DEVNULL,
            )
            if sageresult == b"Factorization failed\n":
                continue
            X = str(sageresult).replace("'", "").split("\\n")
            X = list(filter(lambda x: x.find(" * ") > 0, X))
            if len(X) == 0:
                continue
            sageresult = int(X[0].split(" ")[0])
            break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            continue

    if isinstance(sageresult, int):
        if sageresult > 0:
            p = sageresult
            q = publickey.n // sageresult
            priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
            return (priv_key, None)

    return (None, None)
