#!/usr/bin/python

import hashlib, binascii

t='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def numtowif(numpriv):
 step1 = '80'+hex(numpriv)[2:].strip('L').zfill(64)
 step2 = hashlib.sha256(binascii.unhexlify(step1)).hexdigest()
 step3 = hashlib.sha256(binascii.unhexlify(step2)).hexdigest()
 step4 = int(step1 + step3[:8] , 16)
 return ''.join([t[step4/(58**l)%58] for l in range(100)])[::-1].lstrip('1')

def wiftonum(wifpriv):
 return sum([t.index(wifpriv[::-1][l])*(58**l) for l in range(len(wifpriv))])/(2**32)%(2**256)

def validwif(wifpriv):
 return numtowif(wiftonum(wifpriv))==wifpriv

keyPhrase = "test 1 2 3"
nonce = "asdf"
numAddresses = 10

for i in range(1,numAddresses):
    privKey = numtowif( int( "0x"+hashlib.sha256(keyPhrase).hexdigest(), 0 ) )
    print privKey
    print validwif(privKey)
    keyPhrase += nonce

