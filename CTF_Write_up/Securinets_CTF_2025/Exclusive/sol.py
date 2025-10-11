from pwn import *
from string import *
from tqdm import *

def get_connection():
    s = process(["python", "chall.py"])
    # context.log_level = "debug"
    # s = connect("exclusive.p2.securinets.tn", 6003)
    return s

def get_output(payload):
    for _ in payload:
        s.sendline(_.hex().encode())
    tmp = []
    for _ in range(len(payload)):
        s.recvuntil(b"Exclusive content : ")

        k = s.recvline()
        tmp.append(bytes.fromhex(k.decode()))
    return tmp


def get_block():
    s = get_connection()

    idx = 1
    flag = b""

    s.sendlineafter("> ", str(idx).encode())
    s.recvuntil(b"Your clue : ")

    enc_flag = bytes.fromhex(s.recvline().decode())
    print(len(enc_flag))
    for i in trange(15):
        
        tmp = get_output([enc_flag[16:] + enc_flag[:15 - i]])[0]

        payloads = []
        for candicate in range(256):
            payloads.append(enc_flag[16:] + enc_flag[:15 - i] + bytes([candicate]))
        output = get_output(payloads)
        for i in range(256):
            if tmp == output[i]:
                flag = bytes([i]) + flag

        print(flag)

    tmp = get_output([enc_flag[16:]])[0]

    payloads = []
    for candicate in range(256):
        payloads.append(bytes([candicate]) + flag + b"0" * 32)
    output = get_output(payloads)
    for i in range(256):
        if tmp == output[i][:16]:
            flag = bytes([i]) + flag

    print(flag)

def get_last_block():
    s = get_connection()

    idx = 2
    flag = b""

    s.sendlineafter("> ", str(idx).encode())
    s.recvuntil(b"Your clue : ")

    enc_flag = bytes.fromhex(s.recvline().decode())
    print(len(enc_flag))
    for i in trange(1, 15):
        
        tmp = get_output([enc_flag[:-i]])[0]

        payloads = []
        for candicate in range(256):
            payloads.append(enc_flag[:- i] + bytes([candicate]))
        output = get_output(payloads)
        for i in range(256):
            if tmp == output[i]:
                flag = bytes([i]) + flag

        print(flag)
