#!/usr/bin/env python3
import argparse
import http.cookiejar
import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

from z3 import BitVec, BitVecVal, LShR, Or, Solver, sat


MASK13 = (1 << 13) - 1


def invert_combo_sig(sig):
    node = shutil.which("node")
    if not node:
        raise RuntimeError("node is required to brute-force combo_sig")

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
    hits = json.loads(out)
    if not hits:
        raise RuntimeError(f"no low-bit combo matched combo_sig={sig}")
    return hits


def xs128p_step(s0, s1):
    x = s0
    y = s1
    ns0 = y
    x = x ^ (x << 23)
    x = x ^ LShR(x, 17)
    x = x ^ y
    x = x ^ LShR(y, 26)
    ns1 = x
    return ns0, ns1, ns0 + ns1


def recover_token(observe):
    gifts = sorted(observe["gifts"], key=lambda g: g["index"])
    ids = [int(g["gift_id"], 16) for g in gifts]
    combo_sigs = invert_combo_sig(int(observe["combo_sig"]))

    for combo in combo_sigs:
        low0 = combo >> 13
        low1 = combo & MASK13
        out0 = (ids[0] << 13) | low0
        out1 = (ids[1] << 13) | low1

        s0 = BitVec("s0", 64)
        s1 = BitVec("s1", 64)
        a, b, z3_out0 = xs128p_step(s0, s1)
        c, d, z3_out1 = xs128p_step(a, b)
        e, f, z3_out2 = xs128p_step(c, d)
        g, h, z3_out3 = xs128p_step(e, f)
        i, j, z3_out4 = xs128p_step(g, h)

        solver = Solver()
        solver.add(z3_out0 == BitVecVal(out0, 64))
        solver.add(z3_out1 == BitVecVal(out1, 64))
        solver.add(LShR(z3_out2, 13) == BitVecVal(ids[2], 64))

        if solver.check() != sat:
            continue

        model = solver.model()
        pred3 = model.eval(z3_out3).as_long()
        pred4 = model.eval(z3_out4).as_long()

        solver.add(Or(z3_out3 != BitVecVal(pred3, 64), z3_out4 != BitVecVal(pred4, 64)))
        if solver.check() == sat:
            raise RuntimeError("ambiguous RNG prediction; need another constraint")

        return f"{pred3:016x}-{pred4:016x}"

    raise RuntimeError("could not recover a valid RNG state")


def request_json(opener, req):
    with opener.open(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def exploit(base_url):
    base_url = base_url.rstrip("/")
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))

    observe = request_json(opener, urllib.request.Request(f"{base_url}/api/observe"))
    token = recover_token(observe)

    body = json.dumps({"token": token}).encode()
    req = urllib.request.Request(
        f"{base_url}/api/redeem",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return token, request_json(opener, req)


def main():
    parser = argparse.ArgumentParser(description="Exploit GuGuGaGa xorshift128+ token prediction")
    parser.add_argument("url", nargs="?", help="challenge base URL, for example http://localhost:3000")
    parser.add_argument("--observe-json", help="solve from a saved /api/observe JSON response")
    args = parser.parse_args()

    if args.observe_json:
        observe = json.loads(args.observe_json)
        print(recover_token(observe))
        return

    if not args.url:
        parser.error("provide a URL or --observe-json")

    token, result = exploit(args.url)
    print(f"token: {token}")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as e:
        sys.stderr.write(e.read().decode(errors="replace") + "\n")
        raise
