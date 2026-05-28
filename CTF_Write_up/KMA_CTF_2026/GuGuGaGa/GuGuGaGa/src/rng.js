'use strict';

const MASK64 = (1n << 64n) - 1n;

function u64(x) { return x & MASK64; }
function hex64(x) { return u64(x).toString(16).padStart(16, '0'); }
function hex51(x) { return x.toString(16).padStart(13, '0'); }


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
  return v1;
}

class XorShift128Plus {
  constructor(s0, s1) {
    this.s0 = u64(s0);
    this.s1 = u64(s1);
    if ((this.s0 | this.s1) === 0n) this.s1 = 1n;
  }

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

  getGiftParts() {
    const out = this.next64();
    return {
      id: out >> 13n,
      secret: Number(out & 0x1fffn)
    };
  }
}

module.exports = {
  XorShift128Plus,
  hex64,
  hex51,
  chaoticHash,
  u64
};