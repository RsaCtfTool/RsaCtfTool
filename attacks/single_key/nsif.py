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


class Attack(AbstractAttack):
    def attack(self, publickey, cipher=[]):
        raise NotImplementedError()
        e = 10000
        result = os.system("lib/nsif/nsifc " + str(publickey.n))
        return (str(result), None)
