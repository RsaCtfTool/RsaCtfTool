#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tqdm import tqdm
from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.required_binaries = ["sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """cm_factor attack"""
        D_candidates = [3, 11, 19, 43, 67, 163]
        sageresult = 0
        for D_candidate in tqdm(D_candidates, disable=(not progress)):
            try:
                sageresult = subprocess.check_output(
                    [
                        "sage",
                        "%s/sage/cm_factor.sage" % rootpath,
                        "-N",
                        str(publickey.n),
                        "-D",
                        str(D_candidate),
                    ],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
                if sageresult == b"Factorization failed\n":
                    continue
                X = str(sageresult).replace("'", "").split("\\n")
                X = list(filter(lambda x: x.find(" * ") > 0, X))
                if len(X) == 0:
                    continue
                sageresult = int(X[0].split(" ")[0])
                break
            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                ValueError,
            ):
                continue

        if isinstance(sageresult, int):
            if sageresult > 0:
                p = sageresult
                q = publickey.n // sageresult
                priv_key = PrivateKey(
                    int(p), int(q), int(publickey.e), int(publickey.n)
                )
                return (priv_key, None)

        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEBIRb3M+neIDFb/YRV7KC6
gNbuE3PACl6XF308lnbE5nlhbW7Hv9cqa1ejjXhrlY/yEOqa0P+tVHpRg6UPTFI6
Tdo6XsQrBMXj5qmhdWXVdybJlk5vZdfHdUUgVY6n9YEEff2++mzfD68AzWXadCT6
rEAHgNey44VyLrDg9obVgrmtc7wXtBr+YVrepRfDcrm0D4ZMKeUb07DErZ6GM4I5
/nqLsv8fG55HsWnDp53HCjnWF21I8UvLQqS3qo5N2HQSi7JoONfwsgCwN92t5P/F
jJX0E06PvXqny7uBtSu00KQ1t/srkn47EU4u7U3z+hgJ1kYITrtUG/u+H0xhz9MD
iJtmMx+tfBg7fLSeYQ4uFyxurNakcDYY0D9zu60OT8MzgCby94jydHwowavvyxT9
akEdv/urdgF4Cu0arYCl0DPFDwSvZxyicywbacIHqqalwTm4jRwUK43vJp+5xbTG
cek5zZTIhGbTkhTGTkYWNnQs5QE8UW4y4Z61+sNtpz3rJ7z9PTPd2jGFHmb0X2f/
DogSs0Vjse3lbJsTiM08dwxyP+TtsMIp6AXqClWsjx2RItxGtAmUuyQgE+HG/VaO
+f/EZcSnDcUwLs8XRpDwHVH/kx780H2NTk3LOM5RARWzLmr0HleZSU2IyWLHB9+n
YNyR4N29HHEfixQFgwHapccCAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
