

from collections.abc import Sequence
from typing import List, Tuple

from pwn import *

n = 320
N = 640

# s = process(["python", "server.py"])
s = connect("67.223.119.69", 3638)
ll = time.time()
banner = s.recvuntil(b"> ")
print(banner.decode(errors="ignore"))
def parse_params(data):
    txt = data.decode(errors="ignore")
    n = int(re.search(r"n\s*=\s*(\d+)", txt).group(1))
    q = int(re.search(r"q\s*=\s*(\d+)", txt).group(1))
    p = int(re.search(r"p\s*=\s*(\d+)", txt).group(1))
    return n, q, p
n, q, p = parse_params(banner)

total = 67
samples = []
payload = b"1\n" * total
s.send(payload)
for i in range(total):
    data = s.recvuntil(b"> ")

    txt = data.decode(errors="ignore")
    m = re.search(r"\((\d+),\s*(\d+),\s*(\d+)\)", txt)
    if not m:
        print("[!] Cannot parse sample at", i)
        print(txt)
        raise Exception("parse sample failed")

    a = int(m.group(1))
    M = int(m.group(2))
    Z = int(m.group(3))
    samples.append((a, M, Z))

from tqdm import *
m = []
F = PolynomialRing(Zmod(q), 'x', 200)

for i in range(40):
    t0, t1, t2, t3, t4 = F.gens()[5*i:5*i+5]
    m.extend([0, t0, 1, 1 - t0, t1, t2, t3, t4])

def xor(t1, t2):
    l1 = list(int(i) for i in format(t1, f'0{n}b'))[::-1]
    tmp = 0
    for i, (x1, x2) in enumerate(zip(l1, t2[::-1])):
        tmp += (1 << i) * (x1 + (1 - 2*x1) * x2)
    return ( tmp)

rows = []
targets = []
gens = F.gens()

for i, (a, M, Z) in enumerate(samples):
    X = xor(M, m)
    P = a * X - Z - ((q // p) // 2) * p

    row = [P.monomial_coefficient(g) for g in gens]
    const = P.constant_coefficient()

    rows.append(row)
    targets.append(const)

A = matrix(ZZ, [[ZZ(c.lift()) for c in row] for row in rows])
b = matrix(ZZ, 1, len(targets), [ZZ(t.lift()) for t in targets])

L = block_matrix(ZZ, [
    [A.T],
    [b],
    [p]
])

L = block_matrix(ZZ, [
    [L, 1],
    [q, 0]
])
# L = L[:, :total +]
kl = ((q // p) // 2)
w =  [kl // (1 << 32)] * total + [kl] * 201 + [kl // ((q // p) // 2)] * total
L *= (diagonal_matrix(w, sparse=0))
print("Before LLL:")
def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))
# L = L.LLL(algorithm='fpLLL:wrapper')

def flatter(M):
    from subprocess import check_output
    from re import findall
    import os

    env = os.environ.copy()
    cores = str(os.cpu_count() or 1)

    env["OMP_NUM_THREADS"] = cores
    env["OPENBLAS_NUM_THREADS"] = cores
    env["MKL_NUM_THREADS"] = cores
    env["NUMEXPR_NUM_THREADS"] = cores

    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode(), env=env)
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\d+", ret)))

L = flatter(L)
L /= ( diagonal_matrix(w, sparse=0))

secret = L[0, total : total + 200]

print(L[0,:])
print(secret)
row = list(L[0])

const_col = total + 200

if row[const_col] < 0:
    row = [-x for x in row]

secret = row[total : total + 200]

print(row)
print(secret)
print("[+] len secret =", len(secret))

ss = ""

for i in range(40):
    tmp = secret[5 * i : 5 * i + 5]
    assert len(tmp) == 5, (i, len(tmp), tmp)

    t0, t1, t2, t3, t4 = [int(x) for x in tmp]

    t0 = 1 if t0 > 0 else 0
    t1 = 1 if t1 > 0 else 0
    t2 = 1 if t2 > 0 else 0
    t3 = 1 if t3 > 0 else 0
    t4 = 1 if t4 > 0 else 0

    ch = 0
    ch |= 0 << 7
    ch |= t0 << 6
    ch |= 1 << 5
    ch |= (1 - t0) << 4
    ch |= t1 << 3
    ch |= t2 << 2
    ch |= t3 << 1
    ch |= t4

    ss += chr(ch)

print("[+] secret =", ss)
print(time.time() - ll)
# s.recvuntil("> ")
s.sendline("2")
s.sendline(ss)
s.interactive()