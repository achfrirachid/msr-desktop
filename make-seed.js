// يُشغَّل وقت البناء فقط: TOTP_SECRET=... node scripts/make-seed.js  → ينتج seed.bin (ما يتدفعش للريبو)
const fs = require('fs');
const crypto = require('crypto');
const sec = String(process.env.TOTP_SECRET || '').replace(/[\s-]/g, '').toUpperCase();
if (!/^[A-Z2-7]{16,}$/.test(sec)) { console.error('TOTP_SECRET missing or invalid'); process.exit(1); }
const key = crypto.createHash('sha256').update('massar-seed-v1').digest();
const b = Buffer.from(sec, 'utf8');
for (let i = 0; i < b.length; i++) b[i] ^= key[i % key.length];
fs.writeFileSync('seed.bin', b.toString('base64'));
console.log('seed.bin written');
