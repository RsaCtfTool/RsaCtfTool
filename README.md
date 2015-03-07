# RsaCtfTool
RSA tool for ctf - retreive private key from weak public key and/or uncipher data

## Usage:
usage: RsaCtfTool.py [-h] --publickey PUBLIC\_KEY [--private]
                     [--uncipher UNCIPHER] [--verbose]
                     RsaCtfTool.py: error: argument --publickey is required

### Get private key :
./RsaCtfTool.py --publickey ./weak\_public\_key.pem --private

### Uncipher file :
./RsaCtfTool.py --publickey ./weak\_public\_key.pem --uncipher

### Get n, e, p, q :
./RsaCtfTool.py --publickey ./weak\_public\_key.pem --private --verbose
