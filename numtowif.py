#!/usr/bin/python

import hashlib, binascii
import ctypes
import ctypes.util

ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl') or 'libeay32')

def check_result (val, func, args):
    if val == 0:
        raise ValueError
    else:
        return ctypes.c_void_p (val)

ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
ssl.EC_KEY_new_by_curve_name.errcheck = check_result

base58_chars='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def wif_to_address(pkey):
    # 714 is the identifier OpenSSL uses for the curve "NID_secp256k1".
    # Verify in the OpenSSL source file crypto/objects/obj_mac.h
    NID_secp256k1 = 714
    POINT_CONVERSION_UNCOMPRESSED = 4
    curve = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)

    secret = wif_to_bin(pkey)
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
    ssl.EC_KEY_free(curve)

    # Step 2 - Perform SHA-256 hashing on the public key
    step2 = hashlib.sha256(pubkey).digest()

    # Step 3 - Perform RIPEMD-160 hashing on the result of SHA-256
    ripemd160_hasher = hashlib.new('ripemd160')
    ripemd160_hasher.update(step2)
    ripemd160 = ripemd160_hasher.digest()

    # Step 4 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
    hashed_twice = hashlib.sha256(hashlib.sha256(chr(0) + ripemd160).digest()).digest()
    address_bin = chr(0) + ripemd160 + hashed_twice[:4]

    address_hex = address_bin.encode('hex')
    address_int = int('0x' + address_hex, 16)

    # Convert to base58 using division and remainders
    base58_output = ""
    while address_int > 0:
        address_int, r = divmod(address_int, 58)
        base58_output = base58_chars[r] + base58_output

    # Pad the address with a '1' for every zero-byte ('00') in the unencoded address
    # as specified by the bitcoin protocol
    i = 0
    while address_hex[2*i:2*i+2] == "00":
        base58_output = base58_chars[0] + base58_output
        i += 1

    return base58_output

def int_to_wif(private_int):
    step1 = '80'+hex(private_int)[2:].strip('L').zfill(64)
    step2 = hashlib.sha256(binascii.unhexlify(step1)).hexdigest()
    step3 = hashlib.sha256(binascii.unhexlify(step2)).hexdigest()
    step4 = int(step1 + step3[:8] , 16)

    wif_bin = int_to_bin(step4)
    wif_hex = wif_bin.encode('hex')
    wif_int = int('0x' + wif_hex, 16)
    wif_base58 = ""

    while wif_int > 0:
        wif_int, r = divmod(wif_int, 58)
        wif_base58 = base58_chars[r] + wif_base58

    while len(wif_base58) < 51:
        wif_base58 = base58_chars[0] + wif_base58

    return wif_base58

def wif_to_int(private_wif):
    step1 = sum([base58_chars.index(private_wif[::-1][l])*(58**l) for l in range(len(private_wif))])
    step2 = step1 / (2**32)%(2**256)
    return step2

def int_to_bin(value):
    step1 = hex(value)[2:].strip('L')
    if len(step1) % 2:
        step1 = '0'+step1
    return binascii.unhexlify(step1)

def wif_to_bin(private_wif):
    wif_as_int = wif_to_int(private_wif)
    wif_as_hex = hex(wif_as_int)[2:].strip('L').zfill(64)
    return binascii.unhexlify(wif_as_hex)

def is_wif_valid(private_wif):
    return int_to_wif(wif_to_int(private_wif))==private_wif


key = int_to_wif(2309432908804230)

print key
print wif_to_address(key)
print wif_to_int(key)


