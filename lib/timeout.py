#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import signal
from lib.exceptions import FactorizationError


# source http://stackoverflow.com/a/22348885
class timeout:
    """Manage timeout for long running attacks"""

    def __init__(self, seconds=30, error_message="[-] Timeout"):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise FactorizationError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)
