import os
import subprocess
import re

TIMEOUT = 600
MSIEVE_BIN = os.environ.get("MSIEVE_BIN", "NONE")
YAFU_BIN = os.environ.get("YAFU_BIN", "NONE")
CADO_BIN = os.environ.get("CADO_BIN", "NONE")
NECA_BIN = os.environ.get("NECA_BIN", "NONE")


def ifferm(fname):
    os.system("if [ -f '%s' ];  then rm '%s'; fi" % (fname, fname))


def msieve_factor_driver(n):
    global MSIEVE_BIN
    print("[*] Factoring %d with msieve..." % n)
    tmp = []
    proc = subprocess.Popen(
        [MSIEVE_BIN, "-s", "/tmp/%d.dat" % n, "-t", "8", "-v", str(n)],
        stdout=subprocess.PIPE,
    )
    for line in proc.stdout:
        line = line.rstrip().decode("utf8")
        if re.search("factor: ", line):
            tmp += [int(line.split()[2])]
    ifferm("/tmp/%d.dat" % n)
    return tmp


def yafu_factor_driver(n):
    global YAFU_BIN, TIMEOUT
    print("[*] Factoring %d with yafu..." % n)
    tmp = []
    proc = subprocess.Popen(
        [
            "timeout",
            str(TIMEOUT),
            YAFU_BIN,
            "factor(%s)" % str(n),
            "-session",
            str(n),
            "-qssave",
            "/tmp/qs_%s.dat" % str(n),
        ],
        stdout=subprocess.PIPE,
    )
    for line in proc.stdout:
        line = line.rstrip().decode("utf8")
        if re.search(r"P\d+ = \d+", line):
            tmp += [int(line.split("=")[1])]
    ifferm("/tmp/qs_%d.dat" % n)
    return tmp


def neca_factor_driver(n, timeout=None):
    print("[*] Factoring %d with neca..." % n)
    necaresult = subprocess.check_output(
        [NECA_BIN, "%s" % n],
        timeout=timeout,
        stderr=subprocess.DEVNULL,
    )
    necaresult_l = necaresult.decode("utf8").split("\n")
    if b"FAIL" not in necaresult and b"*" in necaresult:
        for line in necaresult_l:
            r0 = line.find("N = ")
            r1 = line.find(" * ")
            if r0 > -1 and r1 > -1:
                return list(map(int, line.split("=")[1].split("*")))


def cado_factor_driver(n):
    return


def external_factorization(n):
    factors = yafu_factor_driver(n)
    if len(factors) == 0:
        factors = msieve_factor_driver(n)
    return factors
