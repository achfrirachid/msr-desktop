const crypto = require('crypto');

function base32Decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(s || '').replace(/=/g, '').replace(/\s/g, '').toUpperCase();
  let bits = 0, buf = 0;
  const out = [];
  for (const ch of clean) {
    const v = A.indexOf(ch);
    if (v < 0) continue;
    buf = (buf << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((buf >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// RFC 6238: HMAC-SHA1, 30s step, 6 digits (same as Google Authenticator)
function totp(secret, nowMs = Date.now()) {
  const key = base32Decode(secret);
  if (!key.length) return '';
  let counter = Math.floor(nowMs / 1000 / 30);
  const cb = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) {
    cb[i] = counter & 0xff;
    counter = Math.floor(counter / 256);
  }
  const h = crypto.createHmac('sha1', key).update(cb).digest();
  const o = h[h.length - 1] & 0xf;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(bin % 1000000).padStart(6, '0');
}

module.exports = { totp, base32Decode };
