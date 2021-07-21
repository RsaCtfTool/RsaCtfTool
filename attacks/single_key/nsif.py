#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
from attacks.abstract_attack import AbstractAttack

import subprocess
from lib.timeout import timeout
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath
import json

logger = logging.getLogger("global_logger")

print("Module NSIF LOADED")
class Attack(AbstractAttack):
    
    def attack(self, publickey, cipher=[]):
        #print (int(attack_rsa_obj.args.uncipher[0])) 

        e = 10000 

    
    #debug
#    print(publickey.n,m,e)

        result = os.system("lib/nsif/nsif "+str(publickey.n)+" "+str("512")+" "+str(e) )

        return (str(result), None)
