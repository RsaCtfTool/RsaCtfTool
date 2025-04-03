import os
import subprocess
import re

TIMEOUT = 600
MSIEVE_BIN = os.environ.get("MSIEVE_BIN", "NONE")
YAFU_BIN = os.environ.get("YAFU_BIN", "NONE")
CADO_BIN = os.environ.get("CADO_BIN", "NONE")
NECA_BIN = os.environ.get("NECA_BIN", "NONE")


def ifferm(fname):
    os.system(f"if [ -f '{fname}' ];  then rm '{fname}'; fi")


def msieve_factor_driver(n):
    # global MSIEVE_BIN  # not required for read-only use of globals
    print(f"[*] Factoring {n} with msieve...")
    tmp = []
    proc = subprocess.Popen(
        [MSIEVE_BIN, f"-s", "/tmp/{n}.dat", "-t", "8", "-v", str(n)],
        stdout=subprocess.PIPE,
    )
    for line in proc.stdout:
        line = line.rstrip().decode("utf8")
        if re.search("factor: ", line):
            tmp += [int(line.split()[2])]
    ifferm("/tmp/%d.dat" % n)
    return tmp


def yafu_factor_driver(n):
    # global YAFU_BIN, TIMEOUT  # not required for read-only use of globals
    print(f"[*] Factoring {n} with yafu...")
    tmp = []
    proc = subprocess.Popen(
        [
            "timeout",
            str(TIMEOUT),
            YAFU_BIN,
            f"factor({str(n)})",
            "-session",
            str(n),
            "-qssave",
            f"/tmp/qs_{str(n)}.dat",
        ],
        stdout=subprocess.PIPE,
    )
    for line in proc.stdout:
        line = line.rstrip().decode("utf8")
        if re.search(r"P\d+ = \d+", line):
            tmp += [int(line.split("=")[1])]
    ifferm(f"/tmp/qs_{n}.dat")
    return tmp


def neca_factor_driver(n, timeout=None):
    print(f"[*] Factoring {n} with neca...")
    necaresult = subprocess.check_output(
        [NECA_BIN, f"{n}"], timeout=timeout, stderr=subprocess.DEVNULL
    )
    necaresult_l = necaresult.decode("utf8").split("\n")
    if b"FAIL" not in necaresult and b"*" in necaresult:
        for line in necaresult_l:
            r0 = line.find("N = ")
            r1 = line.find(" * ")
            if r0 > -1 and r1 > -1:
                return list(map(int, line.split("=")[1].split("*")))


# comment-out unused function
# def cado_factor_driver(n):
#     return


def external_factorization(n):
    factors = yafu_factor_driver(n)
    if len(factors) == 0:
        factors = msieve_factor_driver(n)
    return factors
