import os
import subprocess

NECA_BIN = os.environ.get("NECA_BIN", "NONE")


def neca_factor_driver(n, timeout=None):
    print("[*] Factoring %d with neca..." % n)
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



