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
    base58_unencoded_address = add_version_and_checksum(ripemd160, chr(0))
    base58_encoded_address = bin_to_base58(base58_unencoded_address, 1)

    return base58_encoded_address, ripemd160

def add_version_and_checksum( payload, version ):
    hashed_twice = hashlib.sha256(hashlib.sha256(version + payload).digest()).digest()
    return version + payload + hashed_twice[:4]

def bin_to_base58( payload, pad_to_length ):
    payload_int = int('0x' + payload.encode('hex'), 16)
    base58_output = ""

    while payload_int > 0:
        payload_int, r = divmod(payload_int, 58)
        base58_output = base58_chars[r] + base58_output

    while len(base58_output) < pad_to_length:
        base58_output = base58_chars[0] + base58_output

    return base58_output

def int_to_wif(private_int):
    step1 = '80'+hex(private_int)[2:].strip('L').zfill(64)
    step2 = hashlib.sha256(binascii.unhexlify(step1)).hexdigest()
    step3 = hashlib.sha256(binascii.unhexlify(step2)).hexdigest()
    step4 = int(step1 + step3[:8] , 16)
    return bin_to_base58( int_to_bin(step4), 51 )

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



for i in range(1, 10000000):
    wif = int_to_wif(i)
    (addr, hex160) = wif_to_address(wif)

    if ( hex160.encode('hex')[0:5] == "00000" ):
        print i, wif, addr, hex160.encode('hex')

