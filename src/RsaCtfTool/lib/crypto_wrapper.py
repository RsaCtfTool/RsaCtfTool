try:
    from Crypto.Cipher import PKCS1_OAEP
except ModuleNotFoundError:
    from Cryptodome.Cipher import PKCS1_OAEP
try:
    from Crypto.PublicKey import RSA
except ModuleNotFoundError:
    from Cryptodome.PublicKey import RSA
try:
    from Crypto.Util import number
except ModuleNotFoundError:
    from Cryptodome.Util import number
try:
    from Crypto.Util.number import long_to_bytes, bytes_to_long
except ModuleNotFoundError:
    from Cryptodome.Util.number import long_to_bytes, bytes_to_long

bytes_to_long = bytes_to_long
long_to_bytes = long_to_bytes
number = number
PKCS1_OAEP = PKCS1_OAEP
RSA = RSA
__all__ = [RSA, PKCS1_OAEP, number, long_to_bytes, bytes_to_long]
