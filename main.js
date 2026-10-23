const { app, BrowserWindow, WebContentsView, session, ipcMain, Menu, safeStorage } = require('electron');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ====== الإعدادات ======
const START_URL = 'https://massar.men.gov.ma';
const LOCK_CODES = ['v'];                          // كود الحماية
const LOCK_TIMEOUT_MS = 5 * 60 * 1000;            // 5 دقائق فالخلفية بلا استعمال = القفل
const TOTP_SECRET = '4RO2NWBPUAPF3CMEGWKZKHQP6MI67SIM';
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
function totp() {
  const counter = Math.floor(Date.now() / 30000);
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

    if (st.code) {
      if (mfaTried >= 3) return;
      if (!mfaCodeSeenAt) mfaCodeSeenAt = Date.now();
      // تسناو 10 ثواني من أول ظهور للخانة، وعلى الأقل 15 ثانية بين محاولة ومحاولة
      if (Date.now() - mfaCodeSeenAt < MFA_MIN_WAIT_MS) return;
      if (mfaLastAttemptAt && Date.now() - mfaLastAttemptAt < MFA_RETRY_GAP_MS) return;
      if (30 - (Math.floor(Date.now() / 1000) % 30) < 4) await new Promise(r => setTimeout(r, 4500));
      mfaLastAttemptAt = Date.now();
      const code = totp();
      const ok = await contents.executeJavaScript(`(function(){
        var el = document.querySelector('input[name="Code"],input#Code,input[autocomplete="one-time-code"]')
              || document.querySelector('input[type="text"],input[type="tel"],input[type="number"]');
        if(!el || window.__mfaSent) return false;
        el.focus();
        var setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
        setter.call(el,'${code}');
        el.dispatchEvent(new Event('input',{bubbles:true}));
        el.dispatchEvent(new Event('change',{bubbles:true}));
        var f = el.form;
        var b = (f && f.querySelector('button[type="submit"],input[type="submit"],button:not([type])')) || document.querySelector('button[type="submit"],input[type="submit"]');
        if(b){ window.__mfaSent = true; setTimeout(function(){ b.click(); }, 800); return true; }
        return false;
      })();`).catch(() => false);
      if (ok) mfaTried++;
    }
  };
  contents.on('did-finish-load', () => run('load'));
  contents.on('did-navigate-in-page', () => run('nav'));
  setInterval(() => run('tick'), 25000);
}

// ====== القفل ======
function resetIdle() { lastActive = Date.now(); }
function startIdleWatcher() {
  setInterval(() => {
    if (!win || lockWin) return;
    // كاين الاستعمال: النافذة مفتوحة وقدامك
    if (win.isFocused() && !win.isMinimized()) { lastActive = Date.now(); saveLastActive(); return; }
    if (Date.now() - lastActive >= LOCK_TIMEOUT_MS) showLock();
  }, 5000);
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
  lockWin.setBackgroundColor('#00000000');
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
ipcMain.handle('unlock', (_e, code) => {
  if (LOCK_CODES.includes(String(code || '').trim())) {
    unlocked = true;
    hideLock();
    resetIdle();
    return true;
  }
  return false;
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
  win.once('ready-to-show', () => { win.show(); resetIdle(); });
  // ملاحظة: قفل التطبيق بالكود تحيد (startIdleWatcher ما كيتشغلش) باش التطبيق
  // يتفتح تلقائيا بلا ما يطلب حتى حاجة، والدخول + كود الـMFA كيتعبيو وحدهم فالخلفية.

  // أي رابط جديد يتفتح في نفس النافذة (ما يخرجش للمتصفح)
  win.webContents.setWindowOpenHandler(({ url }) => { win.loadURL(url); return { action: 'deny' }; });
  win.webContents.on('before-input-event', resetIdle);
  win.webContents.on('did-navigate', resetIdle);
  autoFillMfa(win.webContents);

  win.on('resize', fitLock);
  win.on('closed', () => { win = null; });
}

app.whenReady().then(createWindow);
app.on('before-quit', () => {
  if (win && win.isFocused()) { lastActive = Date.now(); }
  saveLastActive();
  const ses = session.fromPartition(PARTITION);
  ses.flushStorageData();
  ses.cookies.flushStore();
});
app.on('window-all-closed', () => app.quit());
