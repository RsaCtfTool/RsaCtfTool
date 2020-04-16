#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from lib.timeout import timeout
from lib.keys_wrapper import PrivateKey

__SAGE__ = True

logger = logging.getLogger("global_logger")


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Use sage's built in Elliptic Curve Method for factorization of large composites
       may return a prime or may never return
       only works if the sageworks() function returned True
    """
    from sage.all import ecm

    logger.warning(
        "[*] ECM Method can run forever and may never succeed, timeout set to %ssec. Hit Ctrl-C to bail out."
        % attack_rsa_obj.args.timeout
    )
    with timeout(seconds=attack_rsa_obj.args.timeout):
        try:
            ecmdigits = attack_rsa_obj.args.ecmdigits
            sageresult = ecm.find_factor(publickey.n, ecmdigits)
            if sageresult:
                publickey.p = sageresult[0]
                publickey.q = publickey.n // publickey.p
                priv_key = PrivateKey(
                    int(publickey.p),
                    int(publickey.q),
                    int(publickey.e),
                    int(publickey.n),
                )
                return (priv_key, None)
            return (None, None)
        except KeyboardInterrupt:
            return (None, None)
