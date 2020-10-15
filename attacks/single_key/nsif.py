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
    result = os.system("lib/nsif/nsif "+str(publickey.n)+" 0")


    return ("carmichael derivate : "+str(result), None)
