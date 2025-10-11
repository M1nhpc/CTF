
import os, json


def get_json(username, password):
    json_data = {
        "username": username,
        "password": password,
        "admin": 0
    }
    str_data = json.dumps(json_data, ensure_ascii=False)
    return str_data

def get_block(a):
    return [a[i: i + 16] for i in range(0, len(a), 16)]


from pwn import *

def get_connect():
    s = process(["python", "chall.py"])
    # s = connect("xtasy.p2.securinets.tn", 6001)
    # context.log_level = "debug"
    return s

def check_admin(s, token):
    s.recvuntil(b'> ')
    s.recvuntil(b'> ')
    s.recvuntil(b'> ')
    s.recvuntil(b'> ')
    tmp = {}
    tmp['option'] = 'check_admin'
    tmp['token'] = token
    s.sendline(json.dumps(tmp).encode())
    token = s.recvline()
    token = eval(token.decode().strip())
    if "result" in token:
        return token
    else:
        return bytes.fromhex(token["error"][20:-1])

def get_token(s, username, password):
    s.recvuntil(b'> ')
    s.recvuntil(b'> ')
    s.recvuntil(b'> ')
    s.recvuntil(b'> ')
    tmp = {}
    tmp["option"] = 'get_token'
    tmp["username"] = username
    tmp["password"] = password
    s.sendline(json.dumps(tmp).encode())
    token = s.recvline()
    return bytes.fromhex(eval(token.decode().strip())["token"])

s = get_connect()

payload_1 = [b"a" * 8, b""]

for i in get_block(get_json(*["a" * 8, ""])):
    print(i)

c1 = get_block(get_token(s, payload_1[0].hex(), payload_1[1].hex()))

payload_2 = c1[0] + c1[1] + b"0" * (16) + c1[2] + b"0" * (2 * 16)
token_1 = (get_block(check_admin(s, payload_2.hex())))

payload_3 = [b"a" * (2 + 16 + 16) + b": 1}" + token_1[3][4:] + b"a" * 16, b""]

c2 = get_block(get_token(s, payload_3[0].hex(), payload_3[1].hex()))

for i in get_block(get_json(*["a" * (2 + 16 + 16) + ": 1}" + token_1[3][4:].decode('latin-1') + "a" * 16 , ""])):
    print(i)

payload_4 = c1[0] + c1[1] + c2[3] + c1[-1]

print(check_admin(s, payload_4.hex()))
