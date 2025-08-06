import sys
import os
os.environ['TERM'] = 'xterm-256color'

from tqdm import *
from pwn import *

limit = 0xe5db6a6d765b1ba6e727aa7a87a792c49bb9ddeb2bad999f5ea04f047255d5a72e193a7d58aa8ef619b0262de6d25651085842fd9c385fa4f1032c305f44b8a4f92b16c8115d0595cebfccc1c655ca20db597ff1f01e0db70b9073fbaa1ae5e489484c7a45c215ea02db3c77f1865e1e8597cb0b0af3241cd8214bd5b5c1491f


s = connect("catch.chal.idek.team", 1337)
for _ in trange(20):
    s.recvuntil("Co-location: ")
    start_pos = eval(s.recvline().strip().decode())
    s.recvuntil(b"Cat's hidden mind: ")
    mind = bytes.fromhex(s.recvline().strip().decode())
    s.recvuntil(b"Cat now at: ")
    end_pos = eval(s.recvline().strip().decode())
    step = [mind[i:i+8] for i in range(0, 1000, 8)]
    F = GF(limit)


    def walking(x, y, part):
        # Each step is guided by a fragment of the cat's own secret mind.
        epart = [int.from_bytes(part[i:i+2], "big") for i in range(0, len(part), 2)]
        e = matrix(F, 2, 2, [
            epart[0], epart[1],
            epart[2], epart[3]
        ])

        xx, yy = (e ^-1) * vector(F, [x, y])
        return xx, yy

    w = []
    now = end_pos

    for i in range(30):
        for step_ in (step):
            tmp = walking(now[0], now[1], step_)
            if tmp[0] <= now[0] and tmp[1] <= now[1]:
                w.append(step_)
                now = tmp
                break

    payload = b"".join(w[::-1])
    s.sendline(payload.hex().encode())
    
s.interactive()
