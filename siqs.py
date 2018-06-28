#
# Implements a class which simply interfaces to Yafu
#
# We implement SIQS in this but this can be extended to
# other factorisation methods supported by Yafu very
# simply.
#
# @CTFKris - https://github.com/sourcekris/RsaCtfTool/
#

import os
import subprocess
import re


class SiqsAttack(object):
    def __init__(self, args, n):
        """Configuration
        """

        self.yafubin = "./yafu"  # where the binary is
        self.threads = 2  # number of threads
        self.maxtime = 180  # max time to try the sieve

        self.n = n
        self.p = None
        self.q = None
        self.verbose = args.verbose

    def testyafu(self):
        with open('/dev/null') as DN:
            try:
                yafutest = subprocess.check_output([self.yafubin,
                                                   'siqs(1549388302999519)'],
                                                   stderr=DN)
            except:
                yafutest = b''

        if b'48670331' in yafutest:
            # yafu is working
            if self.verbose:
                print("[*] Yafu SIQS is working.")
            return True
        else:
            if self.verbose:
                print("[*] Yafu SIQS is not working.")
            return False

    def checkyafu(self):
        # check if yafu exists and we can execute it
        if os.path.isfile(self.yafubin) and os.access(self.yafubin, os.X_OK):
            return True
        else:
            return False

    def benchmarksiqs(self):
        # NYI
        # return the time to factor a 256 bit RSA modulus
        return

    def doattack(self):
        with open('/dev/null') as DN:
            yafurun = subprocess.check_output(
                [self.yafubin, 'siqs(' + str(self.n) + ')',
                 '-siqsT',  str(self.maxtime),
                 '-threads', str(self.threads)], stderr=DN)

            primesfound = []

            if b'input too big for SIQS' in yafurun:
                if self.verbose:
                    print("[-] Modulus too big for SIQS method.")
                return

            for line in yafurun.splitlines():
                if re.search('^P[0-9]+\ =\ [0-9]+$', line):
                    primesfound.append(int(line.split('=')[1]))

            if len(primesfound) == 2:
                self.p = primesfound[0]
                self.q = primesfound[1]

            if len(primesfound) > 2:
                if self.verbose:
                    print("[*] > 2 primes found. Is key multiprime?")

            if len(primesfound) < 2:
                if self.verbose:
                    print("[*] SIQS did not factor modulus.")

        return
