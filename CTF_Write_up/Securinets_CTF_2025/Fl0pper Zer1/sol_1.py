from aes_gcm_forgery import *
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from fastecdsa.curve import P256 as EC
from fastecdsa.point import Point
import os, random, hashlib, json
from sage.all import *
from pwn import *

def get_connect():
    s = process(["sage", "chall.sage"])
    return s

s = get_connect()

def orcale_verify(msg, r, s_, px, py):
    s.recvuntil(b"Quit\n\n> ")
    tmp = {"option": "verify", "msg": msg, "r": r, "s": s_, "px": px, "py": py}
    s.sendline(json.dumps(tmp).encode())
    return eval(s.recvline().decode().strip())

def orcale_sign(msg, signkey):
    s.recvuntil(b"Quit\n\n> ")
    tmp = {"option": "sign", "msg": msg, "signkey": signkey}
    s.sendline(json.dumps(tmp).encode())
    return eval(s.recvline().decode().strip())

def orcale_generate_key():
    s.recvuntil(b"Quit\n\n> ")
    tmp = {"option": "generate_key"}
    s.sendline(json.dumps(tmp).encode())
    s.recvline()
    return eval(s.recvline().decode().strip())

def orcale_get_flag():
    s.recvuntil(b"Quit\n\n> ")
    tmp = {"option": "get_flag"}
    s.sendline(json.dumps(tmp).encode())
    return eval(s.recvline().decode().strip())

def lagrange_coeffs(x_values, order):
    coeffs = []
    for j in range(len(x_values)):
        num = 1
        denom = 1
        for i in range(len(x_values)):
            if i != j:
                num *= -x_values[i]
                denom *= (x_values[j] - x_values[i])
        coeff = (num * inverse_mod(denom, order)) % order
        coeffs.append(coeff)
    return coeffs

signature = [orcale_generate_key() for _ in range(2)]
G = Point(EC.gx, EC.gy, curve=EC)
pub = Point(int(signature[1]['pubkey']['x'], 16), int(signature[1]['pubkey']['y'], 16), curve=EC)
signkey_shares = signature[1]['signkey'] 
x_values = [1, 2, 3, 4] 
order = EC.q

lambda_coeffs = lagrange_coeffs(x_values, order)

H_x = None
for i in range(4):
    ct0, tag0 = bytes.fromhex(signature[0]['signkey'][i])[16:], bytes.fromhex(signature[0]['signkey'][i])[:16]
    ct1, tag1 = bytes.fromhex(signature[1]['signkey'][i])[16:], bytes.fromhex(signature[1]['signkey'][i])[:16]
    H_x = [i for i in recover_possible_auth_keys(b"", ct0, tag0, b"", ct1, tag1)][0]
    if H_x:
        break

recovered_shares = []
for j in range(4):  # 4 shares
    orig_ct = bytes.fromhex(signkey_shares[j])[16:]
    orig_tag = bytes.fromhex(signkey_shares[j])[:16]
    y_j_bits = ""
    for i in range(256):
        mask = long_to_bytes(1 << i)
        mask = b"\x00" * (32 - len(mask)) + mask  # Đảm bảo 32 byte
        new_ct = xor(orig_ct, mask)
        payload = forge_tag_from_ciphertext(H_x, b"", orig_ct, orig_tag, b"", new_ct) + new_ct
        new_signkey = signkey_shares[:j] + [payload.hex()] + signkey_shares[j+1:]
        
        sig = orcale_sign("00", new_signkey)
        delta = int((lambda_coeffs[j] * pow(2, i, order)) % order)
        Q_plus = pub + (delta * G)
        Q_minus = pub - (delta * G)
        
        v_plus = orcale_verify("00", sig["r"], sig["s"], hex(Q_plus.x)[2:], hex(Q_plus.y)[2:])
        v_minus = orcale_verify("00", sig["r"], sig["s"], hex(Q_minus.x)[2:], hex(Q_minus.y)[2:])
        
        if v_plus["result"] == "Success":
            y_j_bits += "0"
        elif v_minus["result"] == "Success":
            y_j_bits += "1"
        else:
            print(f"Error at share {j}, bit {i}")
            break

    recovered_shares.append((j + 1, int(y_j_bits[::-1], 2)))

from sage.all import *

P = PolynomialRing(GF(EC.q), 'x')
x = P.gen()
reconst_poly = P.lagrange_polynomial(recovered_shares)

privkey = int(reconst_poly(0))

flag_data = orcale_get_flag()
enc_flag = bytes.fromhex(flag_data["flag"])
key = hashlib.sha256(long_to_bytes(privkey)).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(enc_flag)
print("Flag:", flag)