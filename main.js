const { app, BrowserWindow, WebContentsView, session, ipcMain, Menu, safeStorage, powerMonitor, net } = require('electron');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ====== الإعدادات ======
const START_URL = 'https://massar.men.gov.ma';
const LOCK_TIMEOUT_MS = 5 * 60 * 1000;            // 5 دقائق فالخلفية بلا استعمال = القفل
let TOTP_SECRET = null;                            // كيتحمل مشفر من جهازك، ما كاينش فالكود
const SESSION_DAYS = 3650;                        // مدة بقاء الدخول محفوظ
const PARTITION = 'persist:massar';

if (process.env.APPIMAGE) app.commandLine.appendSwitch('no-sandbox');

let win = null;
let lockWin = null;
let loginAttempts = 0;
let lastActive = Date.now();
const ACT_FILE = () => path.join(app.getPath('userData'), 'last-active.json');
function saveLastActive() {
  try { fs.writeFileSync(ACT_FILE(), JSON.stringify({ t: lastActive })); } catch (e) {}
}
function lockNeededAtStart() {
  try {
    const d = JSON.parse(fs.readFileSync(ACT_FILE(), 'utf8'));
    return !d.t || (Date.now() - d.t) >= LOCK_TIMEOUT_MS;
  } catch (e) { return true; }
}
let unlocked = false;


// ====== المفتاح السري ديال TOTP: مخزن مشفر فجهازك فقط (ماشي فالكود ولا فالريبو) ======
const SECRET_FILE = () => path.join(app.getPath('userData'), 'totp.bin');
function normalizeSecret(v) {
  const t = String(v || '').replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
  return /^[A-Z2-7]{16,}$/.test(t) ? t : null;
}
function saveSecret(sec) {
  try {
    const enc = safeStorage.isEncryptionAvailable();
    const data = enc ? safeStorage.encryptString(sec) : Buffer.from(sec, 'utf8');
    fs.writeFileSync(SECRET_FILE(), JSON.stringify({ enc, d: data.toString('base64') }), { mode: 0o600 });
  } catch (e) {}
}
function loadSecret() {
  try {
    const j = JSON.parse(fs.readFileSync(SECRET_FILE(), 'utf8'));
    const buf = Buffer.from(j.d, 'base64');
    return normalizeSecret(j.enc ? safeStorage.decryptString(buf) : buf.toString('utf8'));
  } catch (e) { return null; }
}

// المفتاح المدمج وقت البناء (من GitHub Secret) — ماشي مكتوب فالريبو
function loadBundledSecret() {
  try {
    const b = Buffer.from(fs.readFileSync(path.join(__dirname, 'seed.bin'), 'utf8').trim(), 'base64');
    const key = crypto.createHash('sha256').update('massar-seed-v1').digest();
    const out = Buffer.alloc(b.length);
    for (let i = 0; i < b.length; i++) out[i] = b[i] ^ key[i % key.length];
    return normalizeSecret(out.toString('utf8'));
  } catch (e) { return null; }
}
// أول تشغيل فقط: نافذة صغيرة تلصق فيها المفتاح مرة وحدة، ومن بعد كيتحفظ مشفر
function askSecret() {
  return new Promise((resolve) => {
    const w = new BrowserWindow({
      width: 520, height: 300, resizable: false, title: 'إعداد مسار', autoHideMenuBar: true,
      webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true }
    });
    const html = `<!DOCTYPE html><html dir="rtl"><meta charset="utf-8"><body style="font-family:sans-serif;padding:24px;background:#204832;color:#fff">
      <h3 style="margin-top:0">الصق المفتاح السري ديال Authenticator (مرة وحدة)</h3>
      <input id="s" type="password" autocomplete="off" spellcheck="false" style="width:100%;padding:10px;font-size:18px;direction:ltr;box-sizing:border-box">
      <div id="e" style="color:#ff9d9d;height:22px;margin-top:8px"></div>
      <button id="b" style="padding:10px 36px;font-size:16px">حفظ</button>
      <script>
        const i=document.getElementById('s');
        function go(){ window.__secret=i.value; }
        document.getElementById('b').onclick=go;
        i.addEventListener('keydown',e=>{if(e.key==='Enter')go();});
      </script></body></html>`;
    w.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
    let done = false;
    const finish = (v) => { if (done) return; done = true; clearInterval(t); try { w.destroy(); } catch (e) {} resolve(v); };
    const t = setInterval(async () => {
      if (w.isDestroyed()) return finish(null);
      const v = await w.webContents.executeJavaScript('(function(){var v=window.__secret;window.__secret=null;return v||null;})()').catch(() => null);
      if (!v) return;
      const n = normalizeSecret(v);
      if (n) return finish(n);
      w.webContents.executeJavaScript(`document.getElementById('e').textContent='المفتاح غير صحيح، عاود'; document.getElementById('s').value='';`).catch(() => {});
    }, 400);
    w.on('closed', () => finish(null));
  });
}

// ====== TOTP (RFC 6238) ======
function base32Decode(s) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    const i = alpha.indexOf(c);
    if (i >= 0) bits += i.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
let timeOffset = 0;
let clockSynced = false;
let syncFailLogged = false;   // فرق الساعة بين الحاسوب وسيرفر مسار (ms)
function nowMs() { return Date.now() + timeOffset; }
function syncClock() {
  try {
    const r = net.request({ method: 'HEAD', url: START_URL });
    r.on('response', (res) => {
      const d = res.headers && res.headers['date'];
      const t = d ? Date.parse(Array.isArray(d) ? d[0] : d) : NaN;
      if (!isNaN(t)) {
        timeOffset = t - Date.now(); clockSynced = true;
        mfaLog('clock drift vs server: ' + Math.round(timeOffset / 1000) + 's (auto-corrected)');
      }
    });
    r.on('error', (e) => mfaLog('clock sync failed: ' + (e && e.message)));
    r.end();
  } catch (e) {}
}
function totp() {
  if (!TOTP_SECRET) return null;
  const counter = Math.floor(nowMs() / 30000);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', base32Decode(TOTP_SECRET)).update(buf).digest();
  const o = h[h.length - 1] & 0xf;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1000000).padStart(6, '0');
}

// ====== جعل الدخول دائم (حتى ما يطلب منك الكود كل مرة) ======
function keepSessionCookies(ses) {
  ses.cookies.on('changed', (_e, cookie, _cause, removed) => {
    if (removed || !cookie.session) return;
    const host = cookie.domain.replace(/^\./, '');
    if (!/(^|\.)(men\.gov\.ma|taalim\.ma)$/.test(host)) return;
    const details = {
      url: (cookie.secure ? 'https://' : 'http://') + host + (cookie.path || '/'),
      name: cookie.name,
      value: cookie.value,
      path: cookie.path || '/',
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite,
      expirationDate: Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400
    };
    if (cookie.domain.startsWith('.')) details.domain = cookie.domain;
    ses.cookies.set(details).catch(() => {});
  });
}

// ====== حفظ الباسورد (يُحفظ مرة واحدة بعد أول دخول ناجح يدوي) ======
const CRED_FILE = () => path.join(app.getPath('userData'), 'creds.json');
let pending = null;          // آخر باسورد كتبتيه يدويا (ما تحفظش حتى يتأكد الدخول)
let autoSubmittedAt = 0;     // وقت آخر دخول تلقائي
let autoTried = 0;           // محاولة تلقائية وحدة فقط فكل تشغيل
let mfaTried = 0;
let mfaCodeSeenAt = 0;       // أول مرة بانت فيها خانة الكود (باش نتسناو قبل التعبئة)
let mfaLastAttemptAt = 0;    // وقت آخر محاولة تعبئة/إرسال للكود
let blockedUntil = 0;        // إلى كاين حظر، ما نحاولوش قبل هاد الوقت
const MFA_MIN_WAIT_MS = 10000;   // تسناو 10 ثواني من بعد ما تبان الخانة قبل أول محاولة
const MFA_RETRY_GAP_MS = 15000;  // ما بين محاولة ومحاولة
const BLOCK_COOLDOWN_MS = 13 * 60 * 1000; // إلا تبلوكا، نتسناو 13 دقيقة قبل ما نعاودو

function saveCreds(d) {
  try {
    const enc = safeStorage.isEncryptionAvailable();
    const p = enc ? safeStorage.encryptString(d.p).toString('base64') : Buffer.from(d.p, 'utf8').toString('base64');
    fs.writeFileSync(CRED_FILE(), JSON.stringify({ u: d.u || '', p, enc }), { mode: 0o600 });
  } catch (e) {}
}
function loadCreds() {
  try {
    const d = JSON.parse(fs.readFileSync(CRED_FILE(), 'utf8'));
    const buf = Buffer.from(d.p, 'base64');
    const p = d.enc ? safeStorage.decryptString(buf) : buf.toString('utf8');
    return p ? { u: d.u, p } : null;
  } catch (e) { return null; }
}
function deleteCreds() { try { fs.unlinkSync(CRED_FILE()); } catch (e) {} }
ipcMain.on('pw-captured', (_e, d) => { if (d && d.p) pending = { u: String(d.u || ''), p: String(d.p) }; });

// ====== تعبئة كود MFA (6 أرقام) تلقائيا — حلقة سريعة مستقلة ======
const MFA_LOG = () => path.join(app.getPath('userData'), 'mfa-log.txt');
function mfaLog(m) { try { fs.appendFileSync(MFA_LOG(), new Date().toISOString() + ' ' + m + '\n'); } catch (e) {} }
let mfaBusy = false;
let mfaLoggedMax = false;
async function mfaStep(contents) {
  if (mfaBusy) return;
  mfaBusy = true;
  try {
    if (!contents || contents.isDestroyed()) return;
    if (!/men\.gov\.ma|taalim\.ma/i.test(contents.getURL())) return;
    if (blockedUntil && Date.now() < blockedUntil) return;
    const found = await contents.executeJavaScript(`(function(){
      if (document.querySelector('input[type="password"]')) return false;
      var t=(document.body&&document.body.innerText)||'';
      var mfaPage = /mfa/i.test(location.href) || /deux étapes|two-step|Authenticator|Vérification MFA/i.test(t);
      var els = document.querySelectorAll('input[name="Code"],input#Code,input[autocomplete="one-time-code"],input[name*="code" i],input[id*="code" i],input[placeholder*="code" i],input[name*="otp" i]');
      for (var i=0;i<els.length;i++){ var e=els[i]; if (e.type!=='hidden' && e.type!=='password' && e.offsetParent!==null && (mfaPage || e.name==='Code' || e.id==='Code')) return true; }
      return false;
    })()`).catch(() => false);
    if (!found) {
      mfaCodeSeenAt = 0;
      if (mfaTried > 0 && mfaLastAttemptAt && Date.now() - mfaLastAttemptAt > 60000) mfaTried = 0;
      return;
    }
    if (!mfaCodeSeenAt) { mfaCodeSeenAt = Date.now(); mfaLog('MFA field detected'); }
    if (Date.now() - mfaCodeSeenAt < 3000) return;
    if (mfaTried >= 2) { if (!mfaLoggedMax) { mfaLoggedMax = true; mfaLog('stopped: 2 attempts used'); } return; }
    if (mfaLastAttemptAt && Date.now() - mfaLastAttemptAt < MFA_RETRY_GAP_MS) return;
    if (30 - (Math.floor(nowMs() / 1000) % 30) < 4) return; // نتسناو الكود الجديد
    if (!clockSynced) {
      // نجيبو الوقت الحقيقي من سيرفر مسار نفسو (من داخل الصفحة)
      const d = await contents.executeJavaScript(`fetch(location.href,{method:'HEAD',cache:'no-store'}).then(function(r){return r.headers.get('date');}).catch(function(){return null;})`).catch(() => null);
      const t = d ? Date.parse(d) : NaN;
      if (!isNaN(t)) {
        timeOffset = t - Date.now(); clockSynced = true;
        mfaLog('clock drift vs server (page): ' + Math.round(timeOffset / 1000) + 's (auto-corrected)');
      } else {
        if (!syncFailLogged) { syncFailLogged = true; mfaLog('cannot read server time; not attempting (to protect the account)'); }
        return;
      }
    }
    const code = totp();
    if (!code) { mfaLog('no TOTP secret loaded'); return; }
    mfaLastAttemptAt = Date.now();
    mfaTried++;
    const res = await contents.executeJavaScript(`(function(){
      var els = document.querySelectorAll('input[name="Code"],input#Code,input[autocomplete="one-time-code"],input[name*="code" i],input[id*="code" i],input[placeholder*="code" i],input[name*="otp" i]');
      var el=null; for (var i=0;i<els.length;i++){ if(els[i].type!=='hidden'&&els[i].type!=='password'&&els[i].offsetParent!==null){ el=els[i]; break; } }
      if(!el) return 'no-input';
      el.focus(); el.select();
      try { document.execCommand('insertText', false, '${code}'); } catch(e) {}
      if (el.value !== '${code}') {
        var setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
        setter.call(el,'${code}');
        el.dispatchEvent(new Event('input',{bubbles:true}));
        el.dispatchEvent(new Event('change',{bubbles:true}));
      }
      var kept = (el.value === '${code}');
      var f = el.form;
      var b = (f && f.querySelector('button[type="submit"],input[type="submit"],button:not([type])')) || document.querySelector('button[type="submit"],input[type="submit"]');
      if(!b){ var all=document.querySelectorAll('button,input[type="button"],a'); for(var j=0;j<all.length;j++){ var tx=(all[j].innerText||all[j].value||''); if(/valider|vérifier|verifier|submit|confirmer/i.test(tx)){ b=all[j]; break; } } }
      setTimeout(function(){
        if(b) b.click();
        else if(f && f.requestSubmit) f.requestSubmit();
        else el.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',code:'Enter',keyCode:13,which:13,bubbles:true}));
      }, 700);
      return (b ? 'filled+click' : 'filled+submit') + (kept ? ' value-ok' : ' VALUE-NOT-KEPT');
    })()`).catch((e) => 'error:' + (e && e.message));
    mfaLog('attempt ' + mfaTried + ' code=' + code + ' : ' + res);
  } finally { mfaBusy = false; }
}

// ====== دخول تلقائي + تعبئة كود MFA ======
function autoFillMfa(contents) {
  const run = async (source) => {
    const url = contents.getURL();
    if (!/men\.gov\.ma|taalim\.ma/i.test(url)) return;
    const st = await contents.executeJavaScript(`(function(){
      var t=(document.body&&document.body.innerText)||'';
      return { pw: !!document.querySelector('input[type="password"]'),
        code: !!document.querySelector('input[name="Code"],input#Code,input[autocomplete="one-time-code"]') || /mfa/i.test(location.href),
        blocked: /bloqu|Trop de tentatives|محظور/i.test(t) };
    })()`).catch(() => null);
    if (!st) return;

    // تأكيد حفظ الباسورد: إلا ما بقاش حقل الباسورد = الدخول نجح
    if (pending && !st.pw && !st.blocked) { saveCreds(pending); pending = null; }
    if (pending && st.pw && source === 'load') pending = null;

    // الموقع بلوكا الحساب: نوقفو تماما لمدة، ما نعاودوش نحاولو حتى يفوت الوقت
    if (st.blocked) {
      if (!blockedUntil) blockedUntil = Date.now() + BLOCK_COOLDOWN_MS;
      return;
    }
    if (blockedUntil && Date.now() < blockedUntil) return; // مازال فالتسنية
    blockedUntil = 0;

    // الباسورد المحفوظ فشل: نحيدوه ونوقفو (باش ما يتبلوكاش الحساب)
    if (st.pw && autoSubmittedAt && Date.now() - autoSubmittedAt > 5000) { deleteCreds(); autoSubmittedAt = 0; return; }
    if (!st.pw) autoSubmittedAt = 0;
    if (!st.code) mfaCodeSeenAt = 0; // خانة الكود ماشي حاضرة، رجّع العداد

    if (st.pw && !st.code) {
      if (autoTried >= 1) return;
      const c = loadCreds();
      if (!c) return;                       // ما كاين والو محفوظ: دخل الباسورد بيدك أول مرة
      const sent = await contents.executeJavaScript(`(function(){
        var pw = document.querySelector('input[type="password"]');
        if(!pw || window.__loginSent) return false;
        var form = pw.form || document;
        var user = form.querySelector('input[type="text"],input[type="email"],input:not([type])');
        var setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
        function put(el,v){ el.focus(); setter.call(el,v); el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true})); }
        if(user && ${JSON.stringify(c.u)} && !user.value) put(user, ${JSON.stringify(c.u)});
        put(pw, ${JSON.stringify(c.p)});
        if(pw.value !== ${JSON.stringify(c.p)}) return false;
        var b = (pw.form && pw.form.querySelector('button[type="submit"],input[type="submit"],button:not([type])')) || document.querySelector('button[type="submit"],input[type="submit"]');
        if(b){ window.__loginSent = true; setTimeout(function(){ b.click(); }, 800); return true; }
        return false;
      })();`).catch(() => false);
      if (sent) { autoTried++; autoSubmittedAt = Date.now(); }
      return;
    }

  };
  contents.on('did-finish-load', () => run('load'));
  contents.on('did-navigate-in-page', () => run('nav'));
  setInterval(() => run('tick'), 25000);
  setInterval(() => mfaStep(contents), 1500);
}

// ====== القفل بكود الحماية (PIN) ======
// الكود كيتحدد أول مرة كيتفتح التطبيق، وكيتخزن مشفر (hash) فجهازك فقط — ماشي فالكود ولا فالريبو.
const LOCK_FILE = () => path.join(app.getPath('userData'), 'lock.json');
let failCount = 0;
let lockedOutUntil = 0;
let lockLevel = 0;
const LOCK_PIN = 'v';   // كود القفل الثابت (حرف واحد) — بدّلو هنا إلا بغيتي
function hasPin() { return true; }
function validPin(p) { return /^[a-z0-9]{1,20}$/.test(p); }
function savePin() {}
function checkPin(pin) {
  const a = crypto.createHash('sha256').update(String(pin)).digest();
  const b = crypto.createHash('sha256').update(LOCK_PIN).digest();
  return crypto.timingSafeEqual(a, b);
}

function resetIdle() { lastActive = Date.now(); }
function startIdleWatcher() {
  setInterval(() => {
    if (!win || lockWin) return;
    const away = win.isMinimized() || !win.isVisible() || !win.isFocused();
    const sysIdle = powerMonitor.getSystemIdleTime() * 1000;
    if (!away && sysIdle < LOCK_TIMEOUT_MS) { lastActive = Date.now(); return; }
    // التطبيق فالخلفية، ولا الحاسوب ما كيتستعملش 5 دقائق = القفل
    if (away) { if (Date.now() - lastActive >= LOCK_TIMEOUT_MS) showLock(); }
    else showLock();
  }, 5000);
  powerMonitor.on('lock-screen', showLock);
  powerMonitor.on('suspend', showLock);
}
function fitLock() {
  if (!win || !lockWin) return;
  const [w, h] = win.getContentSize();
  lockWin.setBounds({ x: 0, y: 0, width: w, height: h });
}
function showLock() {
  if (lockWin || !win) return;
  unlocked = false;
  lockWin = new WebContentsView({
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false }
  });
  win.contentView.addChildView(lockWin);
  fitLock();
  lockWin.webContents.loadFile(path.join(__dirname, 'lock.html'));
  lockWin.webContents.once('did-finish-load', () => lockWin && lockWin.webContents.focus());
}
function hideLock() {
  if (!lockWin) return;
  try { win.contentView.removeChildView(lockWin); lockWin.webContents.close(); } catch (e) {}
  lockWin = null;
  if (win) win.webContents.focus();
}
ipcMain.handle('lock-state', () => ({ hasPin: hasPin(), wait: Math.max(0, lockedOutUntil - Date.now()) }));
ipcMain.handle('set-pin', (_e, pin) => {
  pin = String(pin || '').trim().toLowerCase();
  if (hasPin() || !validPin(pin)) return false;
  try { savePin(pin); } catch (e) { return false; }
  unlocked = true; hideLock(); resetIdle();
  return true;
});
ipcMain.handle('unlock', (_e, code) => {
  const wait = lockedOutUntil - Date.now();
  if (wait > 0) return { ok: false, wait };
  if (checkPin(String(code || '').trim().toLowerCase())) {
    failCount = 0; lockLevel = 0; unlocked = true; hideLock(); resetIdle();
    return { ok: true, wait: 0 };
  }
  failCount++;
  if (failCount >= 5) { lockLevel++; failCount = 0; lockedOutUntil = Date.now() + Math.min(60000 * lockLevel, 300000); }
  return { ok: false, wait: Math.max(0, lockedOutUntil - Date.now()) };
});
ipcMain.on('quit-app', () => app.quit());

// ====== النافذة الرئيسية ======
function createWindow() {
  const ses = session.fromPartition(PARTITION);
  keepSessionCookies(ses);

  win = new BrowserWindow({
    width: 1280, height: 800, title: 'مسار', icon: path.join(__dirname, 'icon.png'),
    show: false,
    webPreferences: { partition: PARTITION, contextIsolation: true, nodeIntegration: false, preload: path.join(__dirname, 'login-capture.js') }
  });
  Menu.setApplicationMenu(null);
  win.loadURL(START_URL);
  win.once('ready-to-show', () => { win.show(); resetIdle(); showLock(); startIdleWatcher(); });
  // القفل مفعل: كيتطلب الكود عند الفتح، وبعد 5 دقائق بلا استعمال/فالخلفية.

  // أي رابط جديد يتفتح في نفس النافذة (ما يخرجش للمتصفح)
  win.webContents.setWindowOpenHandler(({ url }) => { win.loadURL(url); return { action: 'deny' }; });
  win.webContents.on('before-input-event', resetIdle);
  win.webContents.on('did-navigate', resetIdle);
  autoFillMfa(win.webContents);

  win.on('resize', fitLock);
  win.on('closed', () => { win = null; });
}

app.whenReady().then(async () => {
  TOTP_SECRET = loadBundledSecret() || loadSecret();
  if (!TOTP_SECRET) {
    // خيار بديل: متغير بيئة مرة وحدة (MASSAR_TOTP_SECRET)، وإلا نافذة الإعداد
    TOTP_SECRET = normalizeSecret(process.env.MASSAR_TOTP_SECRET) || await askSecret();
    if (!TOTP_SECRET) return app.quit();
    saveSecret(TOTP_SECRET);
  }
  mfaLog('app started; secret loaded: ' + !!TOTP_SECRET);
  syncClock();
  createWindow();
});
app.on('before-quit', () => {
  if (win && win.isFocused()) { lastActive = Date.now(); }
  saveLastActive();
  const ses = session.fromPartition(PARTITION);
  ses.flushStorageData();
  ses.cookies.flushStore();
});
app.on('window-all-closed', () => app.quit());
