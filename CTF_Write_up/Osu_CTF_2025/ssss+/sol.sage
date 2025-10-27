import os
os.environ["TERM"] = "linux"

from pwn import *

# io = process(["python", "server.py"])
io = connect("ssssp.challs.sekai.team", 1337)
context.log_level = "debug"
io.recvline().decode().strip()
io.recvline().decode().strip()

k = 15
p = 2**255 - 19

deg = 12
xs = GF(p)(1).nth_root(deg, all = 1)
def evaluate_poly(f, x):
    return sum(c * pow(x, i) for i, c in enumerate(f))
def lcg(x, a, b):
    return (a * x + b)
F.<x> = PolynomialRing(Zmod(p))

P = []
for i in xs:
    io.sendline(str(i).encode())
    ouput = int(io.recvline().decode().strip())
    P.append([i, ouput])

f = F.lagrange_polynomial(P)

output = f.coefficients()[-5:]
output = [int(i) for i in output]

def lcg(x, a, b):
    return (a * x + b)

F.<a, b, x> = PolynomialRing(ZZ)

poly = [x]
while len(poly) != len(output): poly.append(lcg(poly[-1], a, b))

f = []
for _, __ in zip(output, poly):
    f.append(_ - __)
I = ideal(f)
G = I.groebner_basis()

p = int(G[-1])
a = (-G[0].coefficients()[-1]) % p
b = (-G[1].coefficients()[-1]) % p
x = (-G[2].coefficients()[-1]) % p

for i in range(7):
    x = ((x - b) * pow(a, -1, p)) % p
io.sendline(str(x).encode())
io.sendline(str(x).encode())
io.sendline(str(x).encode())
io.sendline(str(x).encode())

io.interactive()