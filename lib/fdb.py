# reports factors to factordb
import re
import urllib3

http = urllib3.PoolManager()


def send2fdb(composite, factors):
    factors = map(str, factors)
    payload = {"report": str(composite) + "=" + "*".join(factors)}
    url = "http://factordb.com/report.php"
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    response = http.request(
        "POST", url, encode_multipart=False, headers=headers, fields=payload
    )
    webpage = str(response.data.decode("utf-8"))
    print("Factordb: " + re.findall("Found [0-9] factors and [0-9] ECM", webpage)[0])
