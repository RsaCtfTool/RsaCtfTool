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
    
    if hasattr(attack_rsa_obj, 'uncipher'):
        m = attack_rsa_obj.args.uncipher
    else:
        m = 2**32 

    e = attack_rsa_obj.args.e

    f = attack_rsa_obj.args.nsif
   
    print(f,e,m)

    result = os.system("lib/nsif/nsif "+str(publickey.n)+" "+str(f)+" "+str(e)+" "+str(m))

    return (str(result), None)
