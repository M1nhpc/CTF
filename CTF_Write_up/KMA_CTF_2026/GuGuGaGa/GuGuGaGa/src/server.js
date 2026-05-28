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