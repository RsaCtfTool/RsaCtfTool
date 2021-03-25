# ssh id_rsa.pub field decoder
import binascii
import sys
import os
import time
import base64

def disect_idrsa_pub(pub):
    a = pub.split(' ')
    if a[0] == 'ssh-rsa':
        bindata = base64.standard_b64decode(a[1])

        def getdata(start,end):
            field = bindata[start:end]
            if len(field) > 0:
                pos = int(binascii.hexlify(field),16)
                data = bindata[end: end+pos]
            else:
                pos = len(bindata)
                data = None
            return pos,data
        
        if bindata:
            start = 0
            end = 4
            pos = 0
            c = []
            data = ""

            while pos < len(bindata):
                pos,data = getdata(start,end)
                if data != None:
                    c.append(data)
                start+=pos+4
                end=start+4

            E = int(binascii.hexlify(c[1]),16)
            N = int(binascii.hexlify(c[2]),16)
            return (N,E)
        else:
            return None
    else:
        return None

