


## EaX

```python
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
```

Bài cho mình lấy các sample dạng (a, M, Z). Ở server, secret được đổi thành số nguyên F, sau đó mỗi sample được sinh như sau:

```python
X = F ^ M
Y = (a * X + e) % q
Z = Y % p
```

Ta có (a, M, Z) và n, p, q. Trong đó e rất nhỏ, chỉ nằm trong khoảng [-2^32, 2^32]. 

Secret là chuỗi hex dài 40 ký tự. Một ký tự hex lowercase chỉ có thể là 0-9 hoặc a-f, nên byte ASCII của nó có dạng khá đặc biệt:

digit 0-9: 0011xxxx

letter a-f: 0110xxxx

Vậy với mỗi ký tự, bit cao nhất luôn là 0, bit thứ 5 luôn là 1, còn bit 6 và bit 4 luôn ngược nhau. Vì thế thay vì coi mỗi byte có 8 bit chưa biết, ta chỉ cần 5 biến:

`[0, t0, 1, 1 - t0, t1, t2, t3, t4]`

40 ký tự cần 40 * 5 = 200 biến, nên code tạo polynomial ring với 200 biến.

Tiếp theo, vì M đã biết nên phép xor với F trở thành tuyến tính theo bit secret. 

Sau bước xor, X = F xor M trở thành một đa thức tuyến tính theo 200 biến secret.

Ta có:

`Y = (aX + e) mod q
Z = Y mod p`

Do Z = Y mod p, tồn tại một số nguyên k_i sao cho:

$Y = Z + k_i * p$

Mà Y cũng là aX + e sau khi giảm modulo q, nên có thêm một bội của q:

$aX + e = Z + k_ip + r_iq$

Chuyển vế:

$a * X - Z - k_i * p - r_i * q = -e$

Vế phải rất nhỏ vì e <= 2^32. Đây chính là vector ngắn mà ta muốn tìm bằng lattice.

```python

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
```

![image.png](attachment:b74770b5-0668-4419-ad65-a0bf80e32cd0:image.png)

## DLP

```python
#!/usr/bin/env python3
from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from secrets import randbelow

N = 184
LAMBDA = 512

def sample_safe_prime():
    while True:
        q = getPrime(LAMBDA)
        p = 2 * q + 1

        if isPrime(p):
            return p, q

def sample_generator(p, q):
    while True:
        a = 2 + randbelow(p - 3)
        g = pow(a, 2, p)

        if g != 1 and pow(g, q, p) == 1:
            return g

def sample_vector(ell):
    while True:
        x = [randbelow(1 << ell) for _ in range(N)]

        if max(xi.bit_length() for xi in x) == ell:
            return x

def main():
    flag = open("flag.txt", "rb").read().strip()

    s = bytes_to_long(flag[7:-1])
    ell = s.bit_length()

    p, q = sample_safe_prime()
    alpha = sample_generator(p, q)

    x = sample_vector(ell)
    y = [pow(alpha, xi ^ s, p) for xi in x]

    print(f"x = {x}")
    print(f"y = {y}")

if __name__ == "__main__":
    main()

```


Bài cho các giá trị public `x` và `y`, trong đó bản chất dữ liệu được sinh theo công thức:

$$
y_i = \alpha^{x_i \oplus s} \pmod p
$$

Với:

- $s$ là secret cần tìm.
- $x_i, y_i$ là dữ liệu public.
- $p = 2q + 1$ là safe prime.
- $\alpha$ là phần tử sinh trong subgroup bậc $q$.

Mục tiêu là khôi phục lại secret $s$ mà không cần giải discrete log.


Secret $s$ được biểu diễn theo bit:

$$
s = \sum_{j=0}^{\ell-1} m_j2^j
$$

Trong đó $m_j$ là bit thứ $j$ của secret.

Với một bit $x_{i,j}$ của $x_i$, ta có:

$$
x_{i,j} \oplus m_j =
x_{i,j} + (1 - 2x_{i,j})m_j
$$

Do đó:

$$
x_i \oplus s =
x_i +
\sum_{j=0}^{\ell-1}
2^j(1 - 2x_{i,j})m_j
$$

Như vậy, mặc dù XOR nhìn có vẻ phi tuyến, nhưng nếu coi từng bit của secret là biến thì $x_i \oplus s$ trở thành biểu thức tuyến tính theo các biến $m_j$.

Trong code, phần này được thực hiện bởi hàm:

```python
def xor(t1, t2):
    l1 = list(int(i) for i in format(t1, f'0{ell}b'))[::-1]
    tmp = 0
    for i, (x1, x2) in enumerate(zip(l1, t2[::-1])):
        tmp += (1 << i) * (x1 + (1 - 2*x1) * x2)
    return tmp
```

Hàm này không tính XOR thật, mà dựng biểu thức đại số của $x_i \oplus s$ theo các bit secret.



Mỗi biểu thức $x_i \oplus s$ có dạng:

$$
x_i \oplus s =
b_{i,0}m_0 + b_{i,1}m_1 + \cdots + b_{i,\ell-1}m_{\ell-1} + c_i
$$


```python
row = [f.monomial_coefficient(g) for g in ms]
const = f.constant_coefficient()
rows.append(row + [const])
```

Mỗi dòng `rows[i]` chứa các hệ số của biểu thức $x_i \oplus s$.



Ta cần tìm các hệ số nguyên $a_i$ sao cho:

$$
\sum_i a_i(x_i \oplus s) = 0
$$


$$
\prod_i y_i^{a_i} =
\alpha^{\sum_i a_i(x_i \oplus s)}=
\alpha^0=
1
\pmod p
$$

Code dựng lattice dạng:

$$
[A \mid I]
$$

bằng:

```python
M = matrix(ZZ, rows)

M = block_matrix([
    [M, 1]
])
```

Ở đây:

- Phần $A$ là ma trận hệ số của các biểu thức $x_i \oplus s$.
- Phần $I$ giúp giữ lại vector hệ số $a_i$.

Sau khi chạy LLL, code lọc các vector có phần đầu bằng 0:

```python
if all(x == 0 for x in i[:ell + 1]):
    a.append(i[ell + 1:])
```

Điều này tương ứng với việc tìm được:

$$
\sum_i a_i(x_i \oplus s)=0
$$


Với mỗi quan hệ:

$$
\sum_i a_i(x_i \oplus s)=0
$$

ta có:

$$
\prod_i y_i^{a_i} \equiv 1 \pmod p
$$

Nếu có hệ số âm, code tách thành hai vế:

```python
if _ < 0:
    v_2_1 *= yi ** (-_)
else:
    v_2_2 *= yi ** _
```

Tức là:

$$
\prod_{a_i>0} y_i^{a_i}
\equiv
\prod_{a_i<0} y_i^{-a_i}
\pmod p
$$

Suy ra hiệu hai vế chia hết cho $p$:

$$
p \mid
\left|
\prod_{a_i>0} y_i^{a_i} -
\prod_{a_i<0} y_i^{-a_i}
\right|
$$

Code lấy GCD của nhiều hiệu như vậy:

```python
k = abs(v_2_2 - v_2_1)
g = k if g == 0 else gcd(g, k)
```

Sau đó factor `g` để lấy lại $p$:

```python
p = int(factor(g)[-1][0])
q = int((p - 1) // 2)
```



Sau khi đã biết $p$, code tiếp tục tìm từng bit của secret.

Với bit thứ $i$, ta muốn tìm một quan hệ dạng:

$$
\sum_j a_j(x_j \oplus s) = \lambda m_i
$$

Khi đó:

$$
\prod_j y_j^{a_j} =
\alpha^{\lambda m_i}
\pmod p
$$

Nếu bit $m_i = 0$:

$$
\alpha^{\lambda m_i} = \alpha^0 = 1
$$

Nếu bit $m_i = 1$:

$$
\alpha^{\lambda m_i} = \alpha^\lambda \neq 1
$$

Vì vậy chỉ cần kiểm tra tích có bằng `1 mod p` hay không.

Trong code:

```python
v_2_2 = 1
for _, yi in zip(ai, y):
    v_2_2 *= pow(yi, _, p)

k = v_2_2 % p
flag += "0" if k == 1 else "1"
```

Nếu `k == 1`, bit đó là `0`.

Nếu `k != 1`, bit đó là `1`.

<img width="2559" height="1598" alt="image" src="https://github.com/user-attachments/assets/33e50bcd-46ee-4306-953d-ab8cf9ccfd87" />

## GUGUGAGA

<img width="2558" height="1598" alt="image" src="https://github.com/user-attachments/assets/0df9a1c0-1ba6-4c71-98d2-dc43155bbad2" />

Trong code server.js như sau:

```py
'use strict';

const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const { XorShift128Plus, hex64, hex51, chaoticHash } = require('./rng');

const app = express();
app.use(express.json());
app.use(cookieParser());

const PORT = Number(process.env.PORT || 3000);
const FLAG = process.env.FLAG || 'KMACTF{?????????????????????????????????????????}';

function rand64() { return BigInt('0x' + crypto.randomBytes(8).toString('hex')); }

function newSession() {
  let s0 = rand64(), s1 = rand64();
  if (s0 === 0n && s1 === 0n) s1 = 1n;
  return { rng: new XorShift128Plus(s0, s1), observed: false, redeemed: false };
}

const sessions = new Map();
function getSession(req, res) {
  let sid = req.cookies.sid;
  if (!sid || !sessions.has(sid)) {
    sid = crypto.randomBytes(16).toString('hex');
    sessions.set(sid, newSession());
    res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax' });
  }
  return sessions.get(sid);
}

app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/api/observe', (req, res) => {
  const sess = getSession(req, res);
  if (sess.observed) return res.status(403).json({ error: 'Promo window used' });
  sess.observed = true;

  const g0 = sess.rng.getGiftParts();
  const g1 = sess.rng.getGiftParts();
  const g2 = sess.rng.getGiftParts();

  const combo = (g0.secret << 13) | g1.secret;
  const comboSig = chaoticHash(combo);

  return res.json({
    combo_sig: comboSig,
    gifts: [
      { index: 0, gift_id: '0x' + hex51(g0.id) },
      { index: 1, gift_id: '0x' + hex51(g1.id) },
      { index: 2, gift_id: '0x' + hex51(g2.id) }
    ]
  });
});

app.post('/api/redeem', (req, res) => {
  const sess = getSession(req, res);
  if (sess.redeemed) return res.status(403).json({ error: 'Already redeemed' });

  const token = req.body && req.body.token;
  if (typeof token !== 'string' || !/^[0-9a-fA-F]{16}-[0-9a-fA-F]{16}$/.test(token)) {
    return res.status(400).json({ error: 'Invalid token format' });
  }

  const expected = `${hex64(sess.rng.next64())}-${hex64(sess.rng.next64())}`;
  if (token.toLowerCase() === expected) {
    sess.redeemed = true;
    return res.json({ ok: true, flag: FLAG });
  }
  return res.status(403).json({ ok: false, message: 'Wrong code' });
});

app.listen(PORT, () => console.log(`Running on :${PORT}`));
```

ta thấy có 2 api là get api/observe
<img width="2559" height="1596" alt="image" src="https://github.com/user-attachments/assets/dcee61f6-c0cc-4a1d-ab60-77677e6b9a22" />

và post api/reedem

<img width="2559" height="1599" alt="image" src="https://github.com/user-attachments/assets/e0434907-2c6d-4f84-a408-45a047fb9d67" />

với mỗi lần req tới api/observe ta có như sau:

```py
app.get('/api/observe', (req, res) => {
  const sess = getSession(req, res);
  if (sess.observed) return res.status(403).json({ error: 'Promo window used' });
  sess.observed = true;

  const g0 = sess.rng.getGiftParts();
  const g1 = sess.rng.getGiftParts();
  const g2 = sess.rng.getGiftParts();

  const combo = (g0.secret << 13) | g1.secret;
  const comboSig = chaoticHash(combo);

  return res.json({
    combo_sig: comboSig,
    gifts: [
      { index: 0, gift_id: '0x' + hex51(g0.id) },
      { index: 1, gift_id: '0x' + hex51(g1.id) },
      { index: 2, gift_id: '0x' + hex51(g2.id) }
    ]
  });
});
```

+ comboSig là hash từ conbo(26 bit)
+ các gift là một phần của 3 output liên tục từ XorShift128Plus

nên mục tiêu của ta sẽ là từ comboSig brute 26 bit để tìm được giá trị combo. Từ giá trị của combo ta có thể tìm được secret của g0, g1 dựa vào `const combo = (g0.secret << 13) | g1.secret;` với secret là 13 bit thấp của output hàm xorshift

```py
  getGiftParts() {
    const out = this.next64();
    return {
      id: out >> 13n,
      secret: Number(out & 0x1fffn)
    };
  }
```

phần còn lại thì ta viết lại biểu thức và đưa vào z3 để tính là dễ dàng có flag.
<img width="2559" height="1599" alt="image" src="https://github.com/user-attachments/assets/6395568a-30d9-464b-b5a0-5ae9ee6333eb" />


```py

from z3 import *
import subprocess
import shutil
import json

output = {"combo_sig":2930968119,"gifts":[{"index":0,"gift_id":"0x4870c15a48871"},{"index":1,"gift_id":"0x733b32b375809"},{"index":2,"gift_id":"0x5c36af3b56982"}]}



MASK64 = (1 << 64) - 1
MASK13 = (1 << 13) - 1

def brute_force_combo_sig(sig):
    node = shutil.which("node")
    print(node)
    js = r"""
const sig = Number(process.argv[1]) >>> 0;
function rotl32(x, k) {
  return ((x << k) | (x >>> (32 - k))) >>> 0;
}
function chaoticHash(combo) {
  let v0 = 0x12345678;
  let v1 = combo >>> 0;
  for (let i = 0; i < 16; i++) {
    v0 = (v0 + v1) >>> 0;
    v0 = rotl32(v0, v1 & 31);
    v0 = (v0 ^ 0x9e3779b9) >>> 0;
    v1 = (v1 + v0) >>> 0;
    v1 = rotl32(v1, v0 & 31);
    v1 = (v1 ^ 0x85ebca6b) >>> 0;
  }
  return v1 >>> 0;
}
const hits = [];
for (let combo = 0; combo < (1 << 26); combo++) {
  if (chaoticHash(combo) === sig) hits.push(combo);
}
console.log(JSON.stringify(hits));
"""
    
    out = subprocess.check_output([node, "-e", js, str(sig)], text=True)
    hits = json.loads(out)[0]
    return hits

combo = brute_force_combo_sig(output["combo_sig"])

"""
  next64() {
    let x = this.s0;
    const y = this.s1;
    this.s0 = y;
    x ^= u64(x << 23n);
    x ^= x >> 17n;
    x ^= y;
    x ^= y >> 26n;
    this.s1 = u64(x);
    return u64(this.s0 + this.s1);
  }
"""

def xs128p_step(s0, s1):
    x = s0
    y = s1
    ns0 = y
    x = x ^ (x << 23)
    x = x ^ LShR(x, 17)
    x = x ^ y
    x = x ^ LShR(y, 26)
    ns1 = x
    out = (ns0 + ns1) & MASK64
    return ns0, ns1, LShR(out, 13), out & MASK13

s0 = BitVec("s0", 64)
s1 = BitVec("s1", 64)

s = Solver()

s0_, s1_, gift1, secret1 = xs128p_step(s0, s1)
s0_, s1_, gift2, secret2 = xs128p_step(s0_, s1_)
s0_, s1_, gift3, secret3 = xs128p_step(s0_, s1_)

s.add(gift1 == int(output["gifts"][0]["gift_id"], 16))
s.add(gift2 == int(output["gifts"][1]["gift_id"], 16))
s.add(gift3 == int(output["gifts"][2]["gift_id"], 16))  
s.add(((secret1 << 13) | secret2) == combo)

class XorShift:
    def __init__(self, s0, s1):
        self.s0 = s0
        self.s1 = s1

    def next(self):
        x = self.s0
        y = self.s1
        self.s0 = y

        x = x ^ ((x << 23) & MASK64)
        x = x ^ (x >> 17)
        x = x ^ y
        x = x ^ (y >> 26)

        self.s1 = x & MASK64
        return (self.s0 + self.s1) & MASK64
        
if s.check() == sat:
    m = s.model()
    s0 = m[s0].as_long()
    s1 = m[s1].as_long()
    xorshift = XorShift(s0, s1)

    xorshift.next()
    xorshift.next()
    xorshift.next()

    print(f"{xorshift.next():016x}-{xorshift.next():016x}")
```
