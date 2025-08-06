import os
os.environ["TERM"] = "xterm-256color"
from pwn import *
from Crypto.Util.number import *

proof.all(False)
s = process(["python3", "server.py"])

xs, ps = [], []
for i in range(16):
    while True:
        p = getPrime(64)
        if (p - 1) % 12 == 0:
            break
    ps.append(p)
    
    s.sendlineafter(">>> ", "1")
    s.sendlineafter(": ", str(p))
    x = GF(p)(1).nth_root(12, all = 1)
    s.sendlineafter("> ", ",".join(map(str, x)))
    s.recvuntil("Here are your shares : ")
    ys = (eval(s.recvline().strip().decode()))
    f_x = GF(p)["X"].lagrange_polynomial(list(zip(x, ys))).coefficients()
    xs.append(list(map(int, f_x[5:12])))
P = prod(ps)
# print(f"Primes: {ps}")
# print(f"Shares: {xs}")
cols = []
for xx, p in zip(xs, ps):
    Pi = P // p
    Pi_inv = int(pow(Pi, -1, p))
    cols += [int(Pi * Pi_inv * xi) for xi in xx]
    
M = block_matrix(ZZ, [
    [column_matrix(cols), 1],
    [P, 0]
])
w = diagonal_matrix([2 ** 641] + [1] * len(cols), sparse = 0)
M = (M / w).LLL() * w

for row in M:
    if len(set(row[1:])) == 2 and int(row[0]).bit_length() <= 641:
        print(f"Found row: {row}")
        s.sendlineafter(">>> ", "2")
        s.sendlineafter("Guess the secret : ", str(hex(row[0])[2:]))
        s.interactive()