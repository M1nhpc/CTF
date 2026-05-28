#!/usr/bin/env python3
from Crypto.Util.number import bytes_to_long, getPrime
from random import SystemRandom
import os, signal

FLAG = open("flag.txt", "rb").read().strip()
TIME = 80

print("Welcome to my secret sharing scheme.")
print("You can get some samples, and try to recover the secret to get the flag.")
print(f"Here is your parameters, you have {TIME} seconds to solve it. Good luck!\n", flush=True)

MENU = """
MENU:
[1] get sample
[2] submit secret
[3] exit
"""

secret = "b2874ee2b4054fe6197c49ac4e2a729ee5ca3d03"
F = bytes_to_long(secret.encode())
n = 8 * len(secret)

q = getPrime(128)
p = getPrime(80)
B = 2**32
N = 2*n

rng = SystemRandom()
samples = []
for _ in range(N):
    M = rng.getrandbits(n)
    a = rng.randrange(1, q)
    e = rng.randint(-B, B)

    X = F ^ M
    Y = (a * X + e) % q
    Z = Y % p

    samples.append((a, M, Z))

print(f"{n = }")
print(f"{q = }")
print(f"{p = }")

def timeout(signum, frame):
    print("Timeout!")
    exit()

signal.signal(signal.SIGALRM, timeout)
signal.alarm(TIME)

for _ in range(N + 1):      # +1 for submitting secret
    print(MENU, flush=True)

    choice = input("> ").strip()

    if choice == "1":
        print(samples.pop(0), flush=True)

    elif choice == "2":
        guess = input("secret = ").strip()
        if guess == secret:
            print(FLAG.decode(), flush=True)
            exit()
        print("Wrong secret!", flush=True)

    elif choice == "3":
        exit()

    else:
        print("Invalid option!", flush=True)

print("No more rounds!", flush=True)