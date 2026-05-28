#!/usr/bin/env python3
import math
import re
import sys
from ast import literal_eval

import sympy as sp


try:
    sys.set_int_max_str_digits(0)
except AttributeError:
    pass


def parse_output(path="output.txt"):
    text = open(path, "r", encoding="utf-8").read()
    x = literal_eval(re.search(r"x = (\[.*?\])\ny = ", text, re.S).group(1))
    y = literal_eval(re.search(r"y = (\[.*\])", text, re.S).group(1))
    return x, y


def short_kernel_relations(rows):
    n = len(rows[0])
    r = len(rows)
    scale = 1 << 20

    basis = []
    for i in range(n):
        row = [0] * (n + r)
        row[i] = 1
        for j in range(r):
            row[n + j] = scale * rows[j][i]
        basis.append(row)

    reduced = sp.Matrix(basis).lll(delta=sp.Rational(3, 4))
    rels = []
    for i in range(reduced.rows):
        coeffs = [int(v) for v in reduced.row(i)[:n]]
        tail = [int(v) for v in reduced.row(i)[n:]]
        if all(v == 0 for v in tail):
            rels.append(coeffs)
    return rels


def recover_p(x, y, ell):
    n = len(x)

    # These relations force sum a_i = 0 and sum a_i * bit_k(x_i) = 0.
    # Then sum a_i * (x_i xor s) = 0 for every possible secret s.
    rows = [[1] * n] + [[(xi >> k) & 1 for xi in x] for k in range(ell)]
    rels = short_kernel_relations(rows)
    print(rels)
    g = 0
    for idx, rel in enumerate(rels):
        lhs = 1
        rhs = 1
        for ai, yi in zip(rel, y):
            if ai > 0:
                lhs *= yi**ai
            elif ai < 0:
                rhs *= yi ** (-ai)

        diff = abs(lhs - rhs)
        g = diff if g == 0 else math.gcd(g, diff)
        if idx == 0:
            continue
        print(g)
        factors = sp.factorint(g, limit=1_000_000)
        for factor in factors:
            factor = int(factor)
            if factor > max(y) and sp.isprime(factor) and sp.isprime((factor - 1) // 2):
                return factor

    raise RuntimeError("failed to recover p")


def rref_mod(matrix, mod):
    rows = [row[:] for row in matrix]
    h = len(rows)
    w = len(rows[0])
    transform = [[1 if i == j else 0 for j in range(h)] for i in range(h)]
    pivots = []
    r = 0

    for c in range(w):
        pivot = next((i for i in range(r, h) if rows[i][c] % mod), None)
        if pivot is None:
            continue

        rows[r], rows[pivot] = rows[pivot], rows[r]
        transform[r], transform[pivot] = transform[pivot], transform[r]

        inv = pow(rows[r][c], -1, mod)
        rows[r] = [(v * inv) % mod for v in rows[r]]
        transform[r] = [(v * inv) % mod for v in transform[r]]

        for i in range(h):
            if i == r:
                continue
            factor = rows[i][c] % mod
            if factor:
                rows[i] = [(rows[i][j] - factor * rows[r][j]) % mod for j in range(w)]
                transform[i] = [
                    (transform[i][j] - factor * transform[r][j]) % mod for j in range(h)
                ]

        pivots.append(c)
        r += 1
        if r == h:
            break

    return rows, transform, pivots


def recover_secret(x, y, p, ell):
    q = (p - 1) // 2
    n = len(x)

    # x_i xor s = x_i + sum_j s_j * 2^j * (1 - 2*bit_j(x_i)).
    v = [[1 if ((xi >> k) & 1) == 0 else q - 1 for xi in x] for k in range(ell)]
    rref, transform, pivots = rref_mod(v, q)
    if len(pivots) != ell:
        raise RuntimeError("bit matrix did not have full rank")

    free_cols = [i for i in range(n) if i not in set(pivots)]

    def z_of(items):
        acc = 1
        for idx, coeff in items:
            coeff %= q
            if coeff:
                acc = (acc * pow(y[idx], coeff, p)) % p
        return acc

    def known_exp(items):
        return sum((coeff % q) * x[idx] for idx, coeff in items) % q

    # A kernel vector c has V*c = 0, so its exponent is independent of s.
    for free in free_cols:
        c_items = [(free, 1)]
        for row, pivot_col in enumerate(pivots):
            coeff = (-rref[row][free]) % q
            if coeff:
                c_items.append((pivot_col, coeff))

        c_exp = known_exp(c_items)
        if c_exp:
            break
    else:
        raise RuntimeError("could not find useful kernel vector")

    zc = z_of(c_items)
    secret = 0

    for bit in range(ell):
        # d_bit is supported on pivot columns and satisfies V*d_bit = e_bit.
        d_items = [
            (pivot_col, transform[row][bit])
            for row, pivot_col in enumerate(pivots)
            if transform[row][bit] % q
        ]
        zd = z_of(d_items)
        d_base_exp = known_exp(d_items)

        ok = []
        for guess in (0, 1):
            guessed_exp = (d_base_exp + guess * (1 << bit)) % q
            ok.append(pow(zc, guessed_exp, p) == pow(zd, c_exp, p))

        if ok == [True, False]:
            pass
        elif ok == [False, True]:
            secret |= 1 << bit
        else:
            raise RuntimeError(f"ambiguous bit {bit}: {ok}")

    return secret


def main():
    x, y = parse_output()
    ell = max(x).bit_length()
    p = recover_p(x, y, ell)
    secret = recover_secret(x, y, p, ell)
    inner = secret.to_bytes((secret.bit_length() + 7) // 8, "big")
    print((b"KMACTF{" + inner + b"}").decode())


if __name__ == "__main__":
    main()
