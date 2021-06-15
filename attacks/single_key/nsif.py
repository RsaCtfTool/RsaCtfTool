#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import subprocess
from lib.timeout import timeout
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath
import json

logger = logging.getLogger("global_logger")


def attack(attack_rsa_obj, publickey, cipher=[]):
    #print (int(attack_rsa_obj.args.uncipher[0])) 
    if hasattr(attack_rsa_obj.args, 'uncipher'):
        m = int.from_bytes(attack_rsa_obj.args.uncipher[0], byteorder="big")
    else:
        m = (2**32) * 3

    e = attack_rsa_obj.args.e

    if hasattr(attack_rsa_obj,"args.nsif"):
        f = attack_rsa_obj.args.nsif
    else:
        f = 0
    
    #debug
#    print(publickey.n,m,e)

    result = os.system("lib/nsif/nsif "+str(publickey.n)+" "+str(m)+" "+str(e) )

    return (str(result), None)
