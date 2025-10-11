
## KMACTF - Crypto

### 1. RAS

```py
from Crypto.Util.number import *
from math import prod
import random

class RAS(object):
    def __init__(self, arr):
        self.n = prod(arr)*prod(arr)
        
    def generate_e(self):
        e = random.getrandbits(4048)
        return e
    
    def encrypt(self, pt):
        e = self.generate_e()
        assert self.n.bit_length() == 4048
        c = [pow(m, e, self.n) for m in pt]
        return  c
        
flag = b'KMACTF{???????????????????????????????}'
flag1, flag2, flag3 = bytes_to_long(flag[:len(flag)//3]), bytes_to_long(flag[len(flag)//3:2*len(flag)//3]), bytes_to_long(flag[2*len(flag)//3:])

# shuffle it
m1 = flag3
m2 = 65537*flag1**2 + flag3*flag2**2 

menu = '''
Welcome to my RAS stolen from tvd2004
1. Send primes
2. Get encrypted flag
'''

while True : 
    print(menu)
    choose = input('> ')
    if choose == '1':
        
        try:
            count = int(input(f"Not 1, not 2, you can choose number prime in RSA system : "))
        except :
            exit()
            
        arr = []
        for i in range(count) :
            p = int(input(f"Prime {i} : "))
            arr.append(p)
        
        ras =  RAS(arr)
        
    elif choose == '2':
        
        print("Here is ciphertext :")
        print(ras.encrypt([m1,m2]))
        
    else:
        raise Exception("Invalid choice!!!")
```

Mỗi lần chọn 2 server sinh ngẫu nhiên e (4048-bit, không tiết lộ) và trả về [m1^e mod n, m2^e mod n]. Với m1, m2 được tính như sau:

+ n = $(\prod{p_i})^2$ (bình phương tích primes do người dùng nhập).
+ $m1 = flag3$

+ $m2 = 65537*flag1^2 + flag3*flag2^2$

![alt text](image.png)

với 2 hint như trên thì ta có thể dễ thấy việc ta cần làm bây giờ là tạo ra một số có giá trị Carmichael lamda nhỏ nhất có thể khi đó ta có thể brute giá trị `d` trong khoảng [1, $\lambda$] để tìm lại flag3 ban đầu.

Khi đó để làm cho giá trị hàm Carmichael $\lambda(n)$ nhỏ so với $n$, ý tưởng cơ bản là chọn các thừa số nguyên tố $p$ sao cho $p-1$  (và với lũy thừa $p^e$ thì là $p^{\,e-1}(p-1)$) chia hết cho một số nhỏ đã biết $L$.  

Khi đó:

$$
\lambda(n) = \operatorname{lcm}\!\bigl(\lambda(p_1^{e_1}), \lambda(p_2^{e_2}), \dots, \lambda(p_k^{e_k})\bigr)
$$

sẽ chia $L$ (hoặc một ước của $L$).  
Điều này có nghĩa là $\lambda(n)$ được chặn trên bởi $L$,  
dù cho $n$ có thể rất lớn (là tích của nhiều số nguyên tố nhỏ hơn $L+1$).

Nên ta có thể tạo `n` theo cách như sau:

+ Duyệt qua các cặp số mũ $(a,b)$.  

+ Tạo số: $p = 2^a \cdot 3^b + 1.$ Nếu $p$ là nguyên tố thì giữ lại.  

+ Lấy tích tất cả các số nguyên tố vừa được tính để tạo thành $n$.  

Nên $n$ rất lớn, nhưng $\lambda(n) \;=\; 2^{\max a}\cdot 3^{\max b},$ nhỏ hơn rất nhiều so với $n$.

Khi đó từ `c_0` ta có thể tính được `flag_3` và ta chỉ cần phải tìm lại flag_1 và flag_2 từ $c_2 = m_2 ^ e = (65537*flag1^2 + flag3*flag2^2) ^ e \pmod{n}$

do c2 và c1 được tính từ cùng 1 số `e` và ta đã có được flag_3 từ trên nên khi đó ta hướng tới như sau:

+ gửi một số $n = c^k$ với hệ số c nhỏ
+ Khi đó ta có $c_0 = flag_3 ^ e \pmod{c^k}$ như vậy ta có thể dễ dàng tìm lại được e bằng việc sử dụng `hensel_lift` để tính.
+ Vì đã có e nên ta có thể tính được m2 từ c2, mà do $c^k$ rất lớn (khoảng gần 2024 bit) so với $m2 = (65537*flag1^2 + flag3*flag2^2)$ (khoảng tối đa 600 bit) nên ta có thể coi như tìm được $m2 = (65537*flag1^2 + flag3*flag2^2)$ thay vì $m2 = (65537*flag1^2 + flag3*flag2^2) \pmod{c^k}$ 

từ $m2 = (65537*flag1^2 + flag3*flag2^2)$ ta có thể tìm lại flag bằng cách sau:
+ Dễ thấy flag có dạng flag = b'KMACTF{???????????????????????????????}', nên khi đó flag1 = b'KMACTF{' + 15 bytes = b'KMACTF{' + f1. Khi đó có thể thấy `f1` nhỏ hơn flag3. Thực hiện mod 2 vế cho flag3 ta được $m2 = 65537*({b'KMACTF\{'} + f_1)^2 \pmod{flag_3}$ khi này có thể sử tìm nghiệm phương trình này bằng có sẵn của sage là ta dễ dàng tìm lại được flag_1
+ Có được flag_1 ta chỉ cần thay vào ngược lại phương trình ban đầu dể lấy flag_2 và hoàn thành challenge.

Có 1 lưu ý nhỏ là `e` được chọn ngẫu nhiên nên ta sẽ gặp phải nhiều trường hợp lỗi không thể nghịch đảo nên phải chạy brute tới khi nào tìm được `e` đủ tốt.

Ngoài ra để giải phương trình $m2 = (65537*flag1^2 + flag3*flag2^2)$ mình có nghĩ ra một vài cách khác như sau:
+ đưa về dạng dạng Diophantine bậc hai (Pell-type equation) $a * x^2 + b * y^2 = c$.
+ đưa về sử dụng dạng phổ thông hơn là copper smith 2 ẩn bậc 2, cũng như coron method.

Tuy nhiên do flag ở đây khá lớn nên giải theo 2 cách này có vẻ không khả thi.

```py
from Crypto.Util.number import *
from string import ascii_letters, digits, punctuation
from tqdm import *
import os
import random

os.environ["TERM"] = "linux"

from pwn import process, connect

def reconnect():
	HOST, PORT = "165.22.55.200", 30001
	s = connect(HOST, PORT)

	# s = process(['python3', 'chall.py'])
	return s

def send_prime(p):
	s.sendline(b'1')
	s.sendline(b'1')
	s.recvuntil(b'Prime 0 : ')
	s.sendline(str(p).encode())

def get_cipher():
	s.sendline(b'2')
	s.recvuntil(b'Here is ciphertext :\n')
	c = eval(s.recvline().decode())
	return c

def d_log(k, base, p, r): 

	# solve k = base ^ x (mod p ^ r)
	R = Zp(p, prec = r)
	return (R(k).log() / R(base).log()).lift()

s = reconnect()

i = 16
j = 5

primes = []

for _ in range(1, i):
	for __ in range(1, j):
		p = 2**_ * 3**__ + 1
		if isPrime(int(p)):
			primes.append(p)
			
p = prod(primes)
padding_prime_bit = 2026 - p.bit_length()


k_bits = int(log(1 << padding_prime_bit, 5))
q = 5 ** k_bits
n = p * q

assert (n ** 2).bit_length() == 4048

p_order = carmichael_lambda(p)
alphabet = ascii_letters + digits + "{}_" + punctuation + " "

send_prime(n)
c = get_cipher()

for d in trange(1, p_order):
	tmp = pow(c[0], d, p)

	flag3 = long_to_bytes(tmp)
	if all([chr(x) in alphabet for x in flag3]):
		print(f"{flag3}")

		while 1:
			try:

				s = reconnect()
				base = 103
				k_bits = int(log(1 << 2024, base))
				q = base ** k_bits
				padding_bit = 2026 - q.bit_length()
				n = q
				while (n ** 2).bit_length() != 4048:
					p = random.getrandbits(padding_bit)
					n = q * p

				send_prime(n)
				c = get_cipher()
				s.close()
				e = d_log(c[0], tmp, base,  k_bits)
				d = pow(e, -1, euler_phi(q))
				ff = (int(pow(int(c[1]), (d), q)))
				print(ff)
				if ff.bit_length() < 600:
					break
			except:
				pass
		from gmpy2 import iroot
		F.<x> = PolynomialRing(Zmod(tmp))
		f = 65537*(bytes_to_long(b"KMACTF{") * (256 ** 15) + x)**2  - ff
		for i in (f.roots(multiplicities=False)):
			
			flag1 = long_to_bytes(int(i))
			flag2 = long_to_bytes(iroot(int(ff - 65537*(bytes_to_long(b"KMACTF{") * (256 ** 15) + int(i))**2) // tmp, 2)[0])
			print(b"KMACTF{" + flag1 + flag2 + flag3)
		break
```

### 2. Chatgpt

```py
from Crypto.Cipher import AES
from Crypto.Util import Counter
import secrets, sys
import random
from hashlib import sha256 


BLOCK = 16  
R_POLY = 0xE1000000000000000000000000000000 
KEY_SIZE_BITS = 256
MAX_INT = 1 << KEY_SIZE_BITS
MOD = MAX_INT - 189  
SEED = MAX_INT // 6

def xor_bytes(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))

def pad16(b: bytes) -> bytes:
    if len(b) % BLOCK == 0:
        return b
    return b + b"\x00" * (BLOCK - (len(b) % BLOCK))

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes(16, "big")

def gf_mul(X: int, Y: int) -> int:
    Z = 0
    V = X
    for i in range(128):
        if (Y >> (127 - i)) & 1:
            Z ^= V
        lsb = V & 1
        V >>= 1
        if lsb:
            V ^= R_POLY
    return Z & ((1 << 128) - 1)

def ghash(H: bytes, data: bytes) -> bytes:
    assert len(H) == 16
    H_int = int_from_bytes(H)
    data = pad16(data)
    y = 0
    for i in range(0, len(data), BLOCK):
        Xi = int_from_bytes(data[i:i+BLOCK])
        y = gf_mul(y ^ Xi, H_int)
    return int_to_bytes(y)

class GHASH:
    def __init__(self, aes_key_for_H: bytes):
        cipher = AES.new(aes_key_for_H, AES.MODE_ECB)
        self.H = cipher.encrypt(b"\x00"*16) 
    def h(self, X: bytes, T: bytes) -> bytes:
        return ghash(self.H, pad16(X) + pad16(T))

class AESBlock:
    def __init__(self, key: bytes):
        self.key = key
    def enc(self, block: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(block)
    def dec(self, block: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.decrypt(block)

class StreamAESCTR:
    def __init__(self, key: bytes):
        self.key = key
    def keystream(self, S: bytes, length: int) -> bytes:
        init_val = int.from_bytes(S, "big")
        ctr = Counter.new(128, initial_value=init_val)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        return cipher.encrypt(b"\x00" * length)

class Encryptor:
    def __init__(self, key_e: bytes, key_d: bytes, key_c: bytes, key_for_H: bytes):
        self.e = AESBlock(key_e)
        self.d = AESBlock(key_d)
        self.h1 = GHASH(key_for_H)
        self.h2 = GHASH(key_for_H)
        self.c = StreamAESCTR(key_c)
        
    def encrypt(self, T: bytes, plaintext: bytes) -> bytes:
        assert len(T) == BLOCK and len(plaintext) >= BLOCK
        A = plaintext[:BLOCK]; B = plaintext[BLOCK:]
        U = self.e.enc(A)
        S = xor_bytes(U, self.h1.h(B, T))
        keystream = self.c.keystream(S, len(B))
        E = xor_bytes(B, keystream) if len(B) > 0 else b""
        V = xor_bytes(S, self.h2.h(E, T))
        G = self.d.enc(V)
        return G + E
    
    def decrypt(self, T: bytes, ciphertext: bytes) -> bytes:
        assert len(T) == BLOCK and len(ciphertext) >= BLOCK
        G = ciphertext[:BLOCK]; E = ciphertext[BLOCK:]
        V = self.d.dec(G)
        S = xor_bytes(V, self.h2.h(E, T))
        keystream = self.c.keystream(S, len(E))
        B = xor_bytes(E, keystream) if len(E) > 0 else b""
        U = xor_bytes(S, self.h1.h(B, T))
        A = self.e.dec(U)
        return A + B
    
class Newbie_Stager:
    def __init__(self, alice_private_key: int, bob_key_private: int):
        self.alice_private_key = alice_private_key
        self.bob_key_private = bob_key_private
        
    def key_exchange(self, seed, exponents):
        result = seed
        exp = 1
        while exponents > 0:
            if exponents % 2 == 1:
                mult = 1
                for i in range(exp):
                    result = (3 * result * mult) % MOD
                    mult <<= 1
            exponents >>= 1
            exp += 1
        return result
    
    def get_shared_key(self): 
        A = self.key_exchange(SEED, self.alice_private_key)
        B = self.key_exchange(SEED, self.bob_key_private)
        shared_key_A = self.key_exchange(B, self.alice_private_key)
        share_key_B = self.key_exchange(A, self.bob_key_private)
        assert shared_key_A == share_key_B
        return shared_key_A , A, B


# Setup
m_blocks = 12
key_e = secrets.token_bytes(16)
key_d = secrets.token_bytes(16)
key_c = secrets.token_bytes(16)
key_for_H = secrets.token_bytes(16)
encryptor = Encryptor(key_e, key_d, key_c, key_for_H)

# Encrypt 
total_len = m_blocks * BLOCK
plaintext = secrets.token_bytes(total_len)
T = secrets.token_bytes(BLOCK)
ciphertext = encryptor.encrypt(T, plaintext)

# Encrypt but for newbie
alice_private = random.getrandbits(256)
bob_private = random.getrandbits(256)
shared_key, A, B = Newbie_Stager(alice_private, bob_private).get_shared_key()
shared_key = sha256(str(shared_key).encode()).digest()[:16]
newbie_aes = AESBlock(shared_key) 
cipher_enc = newbie_aes.enc(ciphertext)

print("Newbie cant see my ciphertext !!!")
print("Here is your ciphertext:", cipher_enc.hex())
print("Here is your T (hex):", newbie_aes.enc(T).hex())
print("Here is your A:", A) 
print("Here is your B:", B)

coint = 10
menu = """
1) Decrypt
2) Encrypt
3) Get Flag
"""
while coint > 0: 
    
    print(menu)
    print(f"You have {coint} coins left")
    choice = input("Your choice: ").strip()
    
    if choice == "1": 
        try:
            hex_ct = input("Ciphertext (hex): ").strip()
            T = bytes.fromhex(input("T (hex): ").strip())
            
            if len(T) != BLOCK:
                print("Invalid T length")
                continue
            
            ciphertext_ = bytes.fromhex(hex_ct)
            if len(ciphertext_) < BLOCK:
                print("Ciphertext too short")
                continue
            
            control = 0
            for i in range(0, len(ciphertext_), BLOCK):
                block = ciphertext_[i:i+BLOCK]
                if block in ciphertext :
                    control +=1 
            
            if control > 2 :
                print("You are not allowed to repeat blocks more than 2 times")
                exit()
            
            pt = encryptor.decrypt(T, ciphertext_)
            print("Plaintext (hex):", pt.hex())
            coint -= 3
        except Exception as e:
            print("Error:", e)
            continue
                
    if choice == "2":
        try:
            hex_pt = input("Plaintext (hex): ").strip()
            T = bytes.fromhex(input("T (hex): ").strip())
            if len(T) != BLOCK:
                print("Invalid T length")
                continue
            plaintext_ = bytes.fromhex(hex_pt)
            
            if len(plaintext_) < BLOCK:
                print("Plaintext too short")
                continue
            
            control = 0
            for i in range(0, len(plaintext_), BLOCK):
                block = plaintext_[i:i+BLOCK]
                if block in ciphertext :
                    control +=1 
            
            if control > 2 :
                print("You are not allowed to repeat blocks more than 2 times")
                exit()
                
            ct = encryptor.encrypt(T, plaintext_)
            print("Ciphertext (hex):", ct.hex())
            coint -= 4
        except Exception as e:
            print("Error:", e)
            continue
        
    if choice == "3":
        
        plaintext_ = bytes.fromhex(input("Plaintext (hex): ").strip())
        if plaintext_ == plaintext[BLOCK:]:
            print("Here is your flag: KMACTF{????????????????????????????????}")
            exit()
        else:
            print("Nope")
            print(plaintext[BLOCK:].hex().encode())
            print(T)
            coint -= 5
    
```

`Newbie_Stager.key_exchange(seed, exponents)` là hàm nhân phối theo dạng key_exchange(seed, e) = seed * F(e) mod MOD (với F(e) chỉ phụ thuộc vào exponents), do đó

`A = SEED * F(a)`

`B = SEED * F(b)`

⇒ shared = SEED * F(a) * F(b).

Từ đó shared = A * B * inv(SEED) (mod MOD) — đó là lý do phép nhân đơn giản A * B * inv(SEED) cho ra đúng shared_int.

Khi này ta đã có T và ciphertext nên việc còn lại ta cần làm là tìm lại M với chức năng encrypt và decrypt của chương trình (Nhưng ta payload ta gửi không được trùng quá 2 block so với ciphertext).


Với hint như sau:
![alt text](image-1.png)

Mình có tìm kiếm các kiểu operation của AES, thì có thể đây là mã hóa dạng XCB block. Khi tìm kiếm XCB attack thì ta có thể thấy được 2 doc sau đây:
+ https://eprint.iacr.org/2024/1527.pdf
+ https://eprint.iacr.org/2024/1554.pdf

Trong doc `Breaking the IEEE Encryption Standard – XCB-AES in Two Queries`, có thể thấy ta có thể sử dụng được cách đã được miêu tả trong đây để giải quyết bài này.


**Một vài định nghĩa**

- $C = C_L \parallel C_R$ (ciphertext): trong code `C = G || E`, $C_L = C[:16]$, $C_R = C[16:]$.

- $M = M_L \parallel M_R$ (plaintext): trong code `M = A || B`, $M_L = A$, $M_R = B$.

- $E_{K_e}(\cdot), E_{K_d}(\cdot)$ là AES-ECB với hai key khác nhau (các hàm `self.e.enc`, `self.d.enc/dec`).

- $G_{K_c}(\cdot)$ là hàm sinh keystream CTR (trong code: `self.c.keystream(S, len(B))`).

- $H_1(K_h,T,\cdot), H_2(K_h,T,\cdot), H_{\text{sum}}(\cdot)$ là các hàm GHASH-derived  
  (trong code: `self.h1.h(...,T)`, `self.h2.h(...,T)`).  
  Tất cả đều tuyến tính theo XOR trên các khối dữ liệu đầu vào.

Trong doc ta có được giới thiệu tính chất cơ bản của Hash trong XCB như sau:

$$
\forall X,Y:\quad \mathrm{GHASH}(X \oplus Y) = \mathrm{GHASH}(X) \oplus \mathrm{GHASH}(Y).
$$

Do đó các hàm $H_1,H_2,H_{\text{sum}}$ thoả quan hệ tuyến tính qua XOR khi input bị XOR với $\Delta$.

Lưu ý: $G_{K_c}(\cdot)$ không cần tuyến tính cho tấn công — ta chỉ cần ép đối số của $G_K$ bằng nhau, thì output cũng bằng nhau.

---

Gọi $T$ là tweak cố định. Ta có:
Ta có bốn quan hệ:

$$
C_L \;=\; G_{K_c,m-n}\!\bigl(E_{K_e}(M_R) \oplus H_1(K_h,T,M_L)\bigr) \;\oplus\; M_L, \tag{1}
$$

$$
C_R \;=\; E_{K_d}^{-1}\!\Bigl(E_{K_e}(M_R) \oplus H_1(K_h,T,M_L) \oplus H_2(K_h,T,C_L)\Bigr), \tag{2}
$$

$$
M_L \;=\; G_{K_c,m-n}\!\bigl(E_{K_d}(C_R) \oplus H_2(K_h,T,C_L)\bigr) \;\oplus\; C_L, \tag{3}
$$

$$
M_R \;=\; E_{K_e}^{-1}\!\Bigl(E_{K_d}(C_R) \oplus H_2(K_h,T,C_L) \oplus H_1(K_h,T,M_L)\Bigr). \tag{4}
$$


$$
M_L \oplus C_L = G_{K_c}\bigl(E_{K_d}(C_R) \oplus H_2(K_h,T,C_L)\bigr) 
$$

và quan hệ phụ:

$$
E_{K_e}(M_R) \oplus E_{K_d}(C_R) = H_{\text{sum}}(K_h,T,M_L,C_L) = H_1(K_h,T,M_L) \oplus H_2(K_h,T,C_L)\Bigr.
$$

$$
\begin{aligned}
&\text{Gửi } (C_L \oplus \Delta)\parallel C_R \;\text{cho server giải mã ta được } M'_L \parallel M'_R, \\
& \\
&\text{Gửi } (M'_L \oplus \Delta)\parallel M'_R \;\text{cho server mã hóa ta có có được } C'_L \parallel C'_R, \\
\end{aligned}
$$

Khi đó ta có:

$$
\begin{aligned}

& M_L \oplus C_L = GK_c\bigl(EK_d(C_R) \oplus H_2(K_h,T,C_L)\bigr) \\ \to 
& EKe(M_R) \oplus EKd(C_R) = H_{\mathrm{sum}}(K_h,T,M_L,C_L).
\end{aligned}
$$


$$
(C_L \oplus \Delta)\parallel C_R \; \text{ trả về } M' = M'_L \parallel M'_R:

M'_L \oplus (C_L \oplus \Delta) = GK_c\bigl(EK_d(C_R) \oplus H_2(K_h,T,C_L \oplus \Delta)\bigr) 


\to EKe(M'_R) \oplus EKd(C_R) = H_{\mathrm{sum}}(K_h,T,M'_L,C_L \oplus \Delta).
$$


$$
(M'_L \oplus \Delta)\parallel M'_R \; \text{ trả về } C' = C'_L \parallel C'_R: 

 (M'_L \oplus \Delta) \oplus C'_L = GK_c\bigl(EKe(M'_R) \oplus H_1(K_h,T,M'_L \oplus \Delta)\bigr)
$$

Từ đó ta có:

$$
\begin{aligned}
& (M'_L \oplus \Delta) \oplus C'_L \oplus M_L \oplus C_L \oplus GK_{c,m-n}\bigl(EK_d(C_R) \oplus H_2(K_h,T,C_L)\bigr)\\
&\quad= GK_{c,m-n}\bigl(EK_e(M'_R) \oplus H_1(K_h,T,M'_L \oplus \Delta)\bigr)\\
&\quad= GK_{c,m-n}\bigl(EK_e(M'_R) \oplus H_2(K_h,T,C_L) \oplus H_{\mathrm{sum}}(K_h,T,M'_L \oplus \Delta, C_L)\bigr)\\
&\quad= GK_{c,m-n}\bigl(EK_e(M'_R) \oplus H_2(K_h,T,C_L) \oplus H_{\mathrm{sum}}(K_h,T,M'_L, C_L \oplus \Delta)\bigr)\\
&\quad= GK_{c,m-n}\bigl(EK_d(C_R) \oplus H_2(K_h,T,C_L)\bigr).
\end{aligned}
$$

Vậy $M_L \; = \; (C_L \oplus M'_L \oplus C'_L \oplus \Delta)$


Khi đó ta có thể dễ dàng tìm được M chỉ với 2 query, và dễ dàng kiếm được flag.


```py


from pwn import *
from Crypto.Cipher import AES
from hashlib import sha256
import re
import sys
import secrets
context.log_level = 'info'
BLOCK = 16
KEY_SIZE_BITS = 256
MAX_INT = 1 << KEY_SIZE_BITS
MOD = MAX_INT - 189
SEED = MAX_INT // 6


def xor_bytes(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))

def pad16(b: bytes) -> bytes:
    if len(b) % BLOCK == 0:
        return b
    return b + b"\x00" * (BLOCK - (len(b) % BLOCK))

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes(16, "big")

def gf_mul(X: int, Y: int) -> int:
    Z = 0
    V = X
    for i in range(128):
        if (Y >> (127 - i)) & 1:
            Z ^= V
        lsb = V & 1
        V >>= 1
        if lsb:
            V ^= R_POLY
    return Z & ((1 << 128) - 1)

def ghash(H: bytes, data: bytes) -> bytes:
    assert len(H) == 16
    H_int = int_from_bytes(H)
    data = pad16(data)
    y = 0
    for i in range(0, len(data), BLOCK):
        Xi = int_from_bytes(data[i:i+BLOCK])
        y = gf_mul(y ^ Xi, H_int)
    return int_to_bytes(y)

class GHASH:
    def __init__(self, aes_key_for_H: bytes):
        cipher = AES.new(aes_key_for_H, AES.MODE_ECB)
        self.H = cipher.encrypt(b"\x00"*16) 
    def h(self, X: bytes, T: bytes) -> bytes:
        return ghash(self.H, pad16(X) + pad16(T))

class AESBlock:
    def __init__(self, key: bytes):
        self.key = key
    def enc(self, block: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(block)
    def dec(self, block: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.decrypt(block)

class StreamAESCTR:
    def __init__(self, key: bytes):
        self.key = key
    def keystream(self, S: bytes, length: int) -> bytes:
        init_val = int.from_bytes(S, "big")
        ctr = Counter.new(128, initial_value=init_val)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        return cipher.encrypt(b"\x00" * length)

class Encryptor:
    def __init__(self, key_e: bytes, key_d: bytes, key_c: bytes, key_for_H: bytes):
        self.e = AESBlock(key_e)
        self.d = AESBlock(key_d)
        self.h1 = GHASH(key_for_H)
        self.h2 = GHASH(key_for_H)
        self.c = StreamAESCTR(key_c)
        
    def encrypt(self, T: bytes, plaintext: bytes) -> bytes:
        assert len(T) == BLOCK and len(plaintext) >= BLOCK
        A = plaintext[:BLOCK]; B = plaintext[BLOCK:]
        U = self.e.enc(A)
        S = xor_bytes(U, self.h1.h(B, T))
        keystream = self.c.keystream(S, len(B))
        E = xor_bytes(B, keystream) if len(B) > 0 else b""
        V = xor_bytes(S, self.h2.h(E, T))
        G = self.d.enc(V)
        return G + E
    
    def decrypt(self, T: bytes, ciphertext: bytes) -> bytes:
        assert len(T) == BLOCK and len(ciphertext) >= BLOCK
        G = ciphertext[:BLOCK]; E = ciphertext[BLOCK:]
        V = self.d.dec(G)
        S = xor_bytes(V, self.h2.h(E, T))
        keystream = self.c.keystream(S, len(E))
        B = xor_bytes(E, keystream) if len(E) > 0 else b""
        U = xor_bytes(S, self.h1.h(B, T))
        A = self.e.dec(U)
        return A + B
    
class Newbie_Stager:
    def __init__(self, alice_private_key: int, bob_key_private: int):
        self.alice_private_key = alice_private_key
        self.bob_key_private = bob_key_private
        
    def key_exchange(self, seed, exponents):
        result = seed
        exp = 1
        while exponents > 0:
            if exponents % 2 == 1:
                mult = 1
                for i in range(exp):
                    result = (3 * result * mult) % MOD
                    mult <<= 1
            exponents >>= 1
            exp += 1
        return result
    
    def get_shared_key(self): 
        A = self.key_exchange(SEED, self.alice_private_key)
        B = self.key_exchange(SEED, self.bob_key_private)
        shared_key_A = self.key_exchange(B, self.alice_private_key)
        share_key_B = self.key_exchange(A, self.bob_key_private)
        assert shared_key_A == share_key_B
        return shared_key_A , A, B


def aes_ecb_decrypt(key16: bytes, data: bytes) -> bytes:
    cipher = AES.new(key16, AES.MODE_ECB)
    return cipher.decrypt(data)

def derive_shared_key_from_AB(A: int, B: int):
    # shared = A * B * inv(SEED) mod MOD
    inv_seed = pow(SEED, -1, MOD)
    shared_int = (A * B * inv_seed) % MOD
    shared_key = sha256(str(shared_int).encode()).digest()[:16]
    return shared_key, shared_int

def parse_initial_output(data: str):
    # parse hex ciphertext (the newbie-encrypted ciphertext)
    re_ct = re.search(r"Here is your ciphertext: *([0-9a-fA-F]+)", data)
    re_t = re.search(r"Here is your T \(hex\): *([0-9a-fA-F]+)", data)
    re_A = re.search(r"Here is your A: *([0-9]+)", data)
    re_B = re.search(r"Here is your B: *([0-9]+)", data)
    if not re_ct or not re_t or not re_A or not re_B:
        raise ValueError("Failed to parse service initial output")
    ct_enc_hex = re_ct.group(1).strip()
    t_enc_hex = re_t.group(1).strip()
    A = int(re_A.group(1).strip())
    B = int(re_B.group(1).strip())
    return bytes.fromhex(ct_enc_hex), bytes.fromhex(t_enc_hex), A, B

def interact_and_get_plaintext(io, ciphertext_hex: str, T_hex: str):
    # choose menu option 1 (Decrypt)
    io.recvuntil(b"Your choice: ")
    io.sendline(b"1")
    io.recvuntil(b"Ciphertext (hex): ")
    io.sendline(ciphertext_hex.encode())
    io.recvuntil(b"T (hex): ")
    io.sendline(T_hex.encode())
    # read response lines until Plaintext (hex):
    data = io.recvuntil(b"\n", timeout=2)  # maybe the server prints error or plaintext
    # We're going to read until we see "Plaintext (hex):"
    full = data
    try:
        more = io.recvrepeat(timeout=0.2)
        full += more
    except Exception:
        pass
    s = full.decode(errors='ignore')
    m = re.search(r"Plaintext \(hex\): *([0-9a-fA-F]+)", s)
    if not m:
        raise ValueError("Did not obtain plaintext from decrypt response; got:\n" + s)
    return m.group(1).strip()

def get_flag_by_submit(io, tail_hex: str):
    # menu again
    io.recvuntil(b"Your choice: ")
    io.sendline(b"3")

    io.recvuntil(b"Plaintext (hex): ")
    io.sendline(tail_hex.encode())
    res = io.recvline(timeout=2)
    if res is None:
        res = io.recvrepeat(timeout=1)
    return res.decode(errors='ignore')

def main():

    io = remote("165.22.55.200", 30002)
    # io = process(["python3", "chall.py"])  # adjust if needed to spawn local process
    initial = io.recvuntil(b"Here is your B:", timeout=5)
    initial += io.recvuntil(b"\n", timeout=1)
    try:
        initial += io.recvuntil(b"Your choice:", timeout=2)
    except Exception:
        # maybe menu printed later, but we already have the key lines
        pass
    initial_str = initial.decode(errors='ignore')

    ct_enc, t_enc, A, B = parse_initial_output(initial_str)

    shared_key, shared_int = derive_shared_key_from_AB(A, B)
    newbie_aes = AESBlock(shared_key) 
    T = newbie_aes.dec(t_enc)
    ciphertext = newbie_aes.dec(ct_enc)
    C = ciphertext
    CL, CR = C[:16], C[16:]
    delta = secrets.token_bytes(len(C) - len(CL))

    query1 = CL + xor(CR, delta)
    io.sendline(b"1")
    io.recvuntil(b"Ciphertext (hex): ")
    io.sendline((query1).hex().encode())
    io.recvuntil(b"T (hex): ")
    io.sendline(T.hex().encode())
    io.recvuntil(b"Plaintext (hex): ")
    A1 = io.recvline().strip().decode()
    M1 = bytes.fromhex(A1)
    M1L, M1R = M1[:16], M1[16:]


    query2 = M1L + xor(M1R, delta)
    io.sendline(b"2")
    io.recvuntil(b"Plaintext (hex): ")
    io.sendline((query2).hex().encode())
    io.recvuntil(b"T (hex): ")
    io.sendline(T.hex().encode())
    io.recvuntil(b"Ciphertext (hex):")
    A2 = io.recvline().strip().decode()
    C1 = bytes.fromhex(A2)
    C1L, C1R = C1[:16], C1[16:]

    M = xor(CR, M1R, C1R, delta)

    io.sendline(b"3")
    io.sendline(M.hex().encode())
    io.interactive()
if __name__ == "__main__":
    main()
```