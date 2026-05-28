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
