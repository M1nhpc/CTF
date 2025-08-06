import os
os.environ["TERM"] = "xterm-256color"
from pwn import *
s = process(["python3", "chall.py"])
proof.all(0)
exec(s.recvline().strip().decode())
R, x = PolynomialRing(GF(p), 'x').objgen()
Ps = []
for i in range(3):
    s.sendlineafter(b"> ", b"1")
    s.recvline()
    exec(s.recvline().strip().decode().split(".")[1].replace("^", "**"))
    exec(s.recvline().strip().decode().split(".")[1].replace("^", "**"))
    Ps.append((U, V))

f = crt([V**2 for _, V in Ps], [U for U, _ in Ps])
C = HyperellipticCurve(f)
P = C.zeta_function().numerator()
s.sendlineafter(b"> ", b"2")
s.sendline(str(P(1)).encode())
s.interactive()