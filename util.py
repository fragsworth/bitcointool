#!/usr/bin/env python
# Joric/bitcoin-dev, june 2012, public domain
 
import hashlib
import ctypes
import ctypes.util
import sys
 
ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl') or 'libeay32')
 
def check_result (val, func, args):
    if val == 0: raise ValueError
    else: return ctypes.c_void_p (val)
 
ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
ssl.EC_KEY_new_by_curve_name.errcheck = check_result
 
class KEY:
    def __init__(self):
        NID_secp256k1 = 714
        self.k = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)
        self.compressed = False
        self.POINT_CONVERSION_COMPRESSED = 2
        self.POINT_CONVERSION_UNCOMPRESSED = 4
 
    def __del__(self):
        if ssl:
            ssl.EC_KEY_free(self.k)
        self.k = None
 
    def generate(self, secret=None):
        if secret:
            self.prikey = secret
            priv_key = ssl.BN_bin2bn(secret, 32, ssl.BN_new())
            group = ssl.EC_KEY_get0_group(self.k)
            pub_key = ssl.EC_POINT_new(group)
            ctx = ssl.BN_CTX_new()
            ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx)
            ssl.EC_KEY_set_private_key(self.k, priv_key)
            ssl.EC_KEY_set_public_key(self.k, pub_key)
            ssl.EC_POINT_free(pub_key)
            ssl.BN_CTX_free(ctx)
            return self.k
        else:
            return ssl.EC_KEY_generate_key(self.k)
 
    def get_pubkey(self):
        size = ssl.i2o_ECPublicKey(self.k, 0)
        mb = ctypes.create_string_buffer(size)
        ssl.i2o_ECPublicKey(self.k, ctypes.byref(ctypes.pointer(mb)))
        return mb.raw
 
    def get_secret(self):
        bn = ssl.EC_KEY_get0_private_key(self.k);
        bytes = (ssl.BN_num_bits(bn) + 7) / 8
        mb = ctypes.create_string_buffer(bytes)
        n = ssl.BN_bn2bin(bn, mb);
        return mb.raw.rjust(32, chr(0))
 
    def set_compressed(self, compressed):
        self.compressed = compressed
        if compressed:
            form = self.POINT_CONVERSION_COMPRESSED
        else:
            form = self.POINT_CONVERSION_UNCOMPRESSED
        ssl.EC_KEY_set_conv_form(self.k, form)

def wif_to_bin(s, version=0):
    ''' Returns binary representation of the private key '''
    pad = 0
    for c in s:
        if c == base58_chars[0]:
            pad += 1
        else:
            break
    h = '%x' % base58_decode(s)
    if len(h) % 2:
        h = '0' + h
    res = h.decode('hex')
    k = chr(0) * pad + res

    v0, data, check0 = k[0], k[1:-4], k[-4:]
    check1 = sha256_twice(v0 + data)[:4]
    if check0 != check1:
        raise BaseException('checksum error')
    if version != ord(v0):
        raise BaseException('version mismatch')
    return data
 
def sha256_twice(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()
 
def rhash(s):
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(s).digest())
    return h1.digest()
 
base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
 
def base58_encode(n):
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0,(base58_chars[r]))
    return ''.join(l)
 
def base58_decode(s):
    n = 0
    for ch in s:
        n *= 58
        digit = base58_chars.index(ch)
        n += digit
    return n
 
def base58_check_encode(s, version=0):
    vs = chr(version) + s
    check = sha256_twice(vs)[:4]
    return base58_encode_padded(vs + check)
 
def reencode(pkey,version=0):
    payload = wif_to_bin(pkey,128+version)
    secret = payload[:-1]
    payload = secret + chr(1)
    pkey = base58_check_encode(payload, 128+version)
    print get_addr(gen_eckey(pkey))
 
def test(otherversion):
    f = open("wallet.txt",'r')
    for row in f.readlines():
        if len(row) > 2:
            row = row.split(',')
            index = row[0]
            public = row[1].strip('"')
            private = row[2].strip().strip('"')
 
            calcpub, calcpriv = get_addr(gen_eckey(private))
 
            print index, calcpub == public, calcpriv == private
 
def get_addr(k,version=0):
    pubkey = k.get_pubkey()
    secret = k.get_secret()
    hash160 = rhash(pubkey)
    addr = base58_check_encode(hash160,version)
    payload = secret
    if k.compressed:
        payload = secret + chr(1)
    pkey = base58_check_encode(payload, 128+version)
    return addr, pkey
 
def gen_eckey(pkey):
    k = KEY()
    secret = wif_to_bin(pkey, 128)
    secret = secret[0:32]
    k.generate(secret)
    k.set_compressed(False)
    return k

def base58_encode_padded(s):
    res = base58_encode(int('0x' + s.encode('hex'), 16))
    pad = 0
    for c in s:
        if c == chr(0):
            pad += 1
        else:
            break
    return base58_chars[0] * pad + res

def int_to_wif(private_int):
    step1 = '80'+hex(private_int)[2:].strip('L').zfill(64)
    step2 = hashlib.sha256(binascii.unhexlify(step1)).hexdigest()
    step3 = hashlib.sha256(binascii.unhexlify(step2)).hexdigest()
    step4 = int(step1 + step3[:8] , 16)
    return ''.join([base58_chars[step4/(58**l)%58] for l in range(100)])[::-1].lstrip('1')

def wif_to_address(pkey):
    ''' '''

    # 714 is the identifier OpenSSL uses for the curve "NID_secp256k1".
    # Verify in the OpenSSL source file crypto/objects/obj_mac.h
    NID_secp256k1 = 714
    POINT_CONVERSION_UNCOMPRESSED = 4
    curve = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)

    secret = wif_to_bin(pkey, 128)

    priv_key_bignumber = ssl.BN_bin2bn(secret, 32, ssl.BN_new())
    group = ssl.EC_KEY_get0_group(curve)
    pub_key = ssl.EC_POINT_new(group)
    ctx = ssl.BN_CTX_new()
    ssl.EC_POINT_mul(group, pub_key, priv_key_bignumber, None, None, ctx)
    ssl.EC_KEY_set_private_key(curve, priv_key_bignumber)
    ssl.EC_KEY_set_public_key(curve, pub_key)
    ssl.EC_POINT_free(pub_key)
    ssl.BN_CTX_free(ctx)
    ssl.EC_KEY_set_conv_form(curve, POINT_CONVERSION_UNCOMPRESSED)
    size = ssl.i2o_ECPublicKey(curve, 0)
    mb = ctypes.create_string_buffer(size)
    ssl.i2o_ECPublicKey(curve, ctypes.byref(ctypes.pointer(mb)))
    pubkey = mb.raw

    # Step 2 - Perform SHA-256 hashing on the public key
    step2 = hashlib.sha256(pubkey).digest()

    # Step 3 - Perform RIPEMD-160 hashing on the result of SHA-256
    ripemd160_hasher = hashlib.new('ripemd160')
    ripemd160_hasher.update(step2)
    ripemd160 = ripemd160_hasher.digest()

    # Step 4 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
    base58_unencoded_address = add_version_and_checksum(ripemd160, chr(0))
    base58_encoded_address = bin_to_base58(base58_unencoded_address)

    return base58_encoded_address

def add_version_and_checksum( payload, version ):
    return version + payload + sha256_twice(version + payload)[:4]

def bin_to_base58( payload ):
    n = (int('0x' + payload.encode('hex'), 16))
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0,(base58_chars[r]))
    res = ''.join(l)
    pad = 0
    for c in payload:
        if c == chr(0):
            pad += 1
        else:
            break
    return base58_chars[0] * pad + res
   
def generate_from_privkey(key):
    #return get_addr(gen_eckey(pkey=key))
    return wif_to_address(key)
 
   
if False and __name__ == '__main__':
    import optparse
    parser = optparse.OptionParser(usage="%prog [options]")
    parser.add_option("--otherversion", dest="otherversion", default=0,
                    help="Generate address with different version number")
    (options, args) = parser.parse_args()
 
    test(int(options.otherversion))

print wif_to_address("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
print wif_to_address("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
print wif_to_address("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
print wif_to_address("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
print wif_to_address("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
print wif_to_address("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
print wif_to_address("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
print wif_to_address("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
print wif_to_address("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")









