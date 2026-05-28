
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
