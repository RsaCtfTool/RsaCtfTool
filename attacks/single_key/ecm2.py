#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import subprocess
from lib.rsalibnum import modInv
from lib.timeout import timeout
from lib.keys_wrapper import PrivateKey

__SAGE__ = True

logger = logging.getLogger("global_logger")


def attack(attack_rsa_obj, publickey, cipher=[]):
    """use elliptic curve method
       only works if the sageworks() function returned True
    """
    logger.warning(
        "[*] ECM2 Method can run forever and may never succeed, timeout set to %ssec. Hit Ctrl-C to bail out."
        % attack_rsa_obj.args.timeout
    )

    try:
        sageresult = []
        try:
            dir_path = os.path.dirname(os.path.realpath(__file__))
            sagepath = os.path.join(dir_path, "../../sage/ecm2.sage")
            sageresult = subprocess.check_output(
                ["sage", sagepath, str(publickey.n)],
                timeout=attack_rsa_obj.args.timeout,
            )
            sageresult = sageresult[1:-2].split(b", ")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return (None, None)

        if len(sageresult) > 0:
            plain = []
            sageresults = [int(_.decode("utf-8")) for _ in sageresult]
            phi = 1
            for fac in sageresults:
                phi = phi * (int(fac) - 1)

            for c in cipher:
                try:
                    cipher_int = int.from_bytes(c, "big")
                    d = modInv(publickey.e, phi)
                    m = hex(pow(cipher_int, d, publickey.n))[2::]
                    plain.append(bytes.fromhex(m))
                except:
                    continue

            return (None, plain)
        return (None, None)
    except KeyboardInterrupt:
        pass
    return (None, None)
