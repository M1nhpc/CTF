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

		# print(coron(f, 256 ** 15, 256 ** 22, k = 7))
		for i in (f.roots(multiplicities=False)):
			
			flag1 = long_to_bytes(int(i))
			flag2 = long_to_bytes(iroot(int(ff - 65537*(bytes_to_long(b"KMACTF{") * (256 ** 15) + int(i))**2) // tmp, 2)[0])
			print(b"KMACTF{" + flag1 + flag2 + flag3)
		break


