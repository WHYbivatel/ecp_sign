"""Development-only independent check; pip install gostcrypto==1.2.5.

Run: node tests/gost-crosscheck.mjs | python3 tests/independent_gost.py
"""
import json
import sys
from gostcrypto import gosthash, gostsignature

vector = json.load(sys.stdin)
data = bytearray.fromhex(vector['data'])
digest = gosthash.new('streebog512', data=data).digest()
assert digest.hex() == vector['hash'], 'Independent Streebog hash differs'
public = bytes.fromhex(vector['public'])
public_be = public[:64][::-1] + public[64:][::-1]
signature = bytes.fromhex(vector['signature'])
signature_rs = signature[:64][::-1] + signature[64:][::-1]
engine = gostsignature.new(gostsignature.MODE_512,
    gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-12-512-paramSetA'])
assert engine.verify(bytearray(public_be), bytearray(digest[::-1]), bytearray(signature_rs)), 'Invalid GOST signature'
digest[0] ^= 1
assert not engine.verify(bytearray(public_be), bytearray(digest[::-1]), bytearray(signature_rs)), 'Tampering was accepted'
print('Independent Python check: Streebog-512 and GOST-512 signature PASS; tampering rejected.')
