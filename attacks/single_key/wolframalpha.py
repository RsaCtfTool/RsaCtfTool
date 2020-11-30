#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import sys
import os
import re
import logging
import requests
from lib.rsalibnum import invmod
from Crypto.PublicKey import RSA
from lib.keys_wrapper import PrivateKey
from lib.exceptions import FactorizationError
from Crypto.Util.number import long_to_bytes

logger = logging.getLogger("global_logger")

try:
    wa_enabled = True
    import wolframalpha
    app_id = os.environ.get('WA_API_KEY')
    wa_enabled = (app_id != None)
except Exception as e:
    logger.error("[!] Wolphram Alfa is not enabled, install the lib.")
    wa_enabled = False

if not wa_enabled:
    logger.error("[!] Wolphram Alfa is not enabled, check if ENV WA_API_KEY is set.")
    logger.error("[!] follow: https://products.wolframalpha.com/api/documentation/")
    logger.error("[!] export WA_API_KEY=XXXXXX-XXXXXXXXXX")
    wa_client = None
else:
    wa_client = wolframalpha.Client(app_id)

def wa_query_factors(n, safe = True):
    tmp = []
    if safe and len(str(n)) > 192:
        logger.error("[!] wolfram alpha only works for pubkeys < 192 digits")
        return
    q = 'factor(%s)' % n
    if wa_client != None:
        res = wa_client.query(q)
        pods = list(res.pods)
        if len(pods) > 0:
            for pod in pods:
                x = str(pod).replace("@","").replace("'",'"')
                pod = json.loads(x)
                tmp = pod['subpod']['plaintext']
                if tmp.find("×") > 0:
                    tmp = tmp.split(" ")[0]
                    #tmp2 = list(map(lambda x:int(x,16),tmp.split("×")))
                    tmp2 = list(map(int,tmp.split("×")))

                    return tmp2
        else:
            logger.error("[!] Could not get factorization from wolfram alpha")

def attack(attack_rsa_obj, publickey, cipher=[]):
    """Factors available online?"""
    try:
        factors = wa_query_factors(publickey.n)
        logger.info("Factors: %s" % str(factors))
        if factors != None and len(factors) > 1:
            publickey.q = factors[-1] # Let it be the last prime wich is the bigger one
            publickey.p = publickey.n // publickey.q
            priv_key = PrivateKey(
                p=int(publickey.p),
                q=int(publickey.q),
                e=int(publickey.e),
                n=int(publickey.n)
                )
            return(priv_key, None)
        else:
            return(None, None)
    except Exception as e:
        logger.error("[*] wolfram alpha could not get a factorization.")
        logger.debug(str(e))
        return (None, None)
