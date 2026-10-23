const { app, BrowserWindow, WebContentsView, session, ipcMain, Menu } = require('electron');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ====== الإعدادات ======
const START_URL = 'https://massar.men.gov.ma';
const LOCK_CODES = ['v'];                          // كود الحماية
const LOCK_TIMEOUT_MS = 5 * 60 * 1000;            // 5 دقائق فالخلفية بلا استعمال = القفل
const LOGIN_ID = '193464@TAALIM.MA';
const MASSAR_PASSWORD = 'Achfri@1982.';   // الباسورد ديال مسار
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

// ====== تعبئة كود MFA تلقائيا ======
function autoFillMfa(contents) {
  const run = () => {
    const url = contents.getURL();
    if (!/mfa/i.test(url)) {
      if (!/men\.gov\.ma|taalim\.ma/i.test(url)) return;
      if (loginAttempts >= 3) return;   // حماية: ما يعاودش بزاف إلى كان الباسورد غالط
      contents.executeJavaScript(`(function(){
        var pw = document.querySelector('input[type="password"]');
        if(!pw || window.__loginSent) return false;
        var form = pw.form || document;
        var user = form.querySelector('input[type="text"],input[type="email"],input:not([type])');
        if(!user) return false;
        var setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
        function put(el,v){ setter.call(el,v); el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true})); }
        put(user,'${LOGIN_ID}');
        put(pw,'${MASSAR_PASSWORD}');
        var b = (pw.form && pw.form.querySelector('button[type="submit"],input[type="submit"],button:not([type])')) || document.querySelector('button[type="submit"],input[type="submit"]');
        if(b){ window.__loginSent = true; setTimeout(function(){ b.click(); }, 800); return true; }
        return false;
      })();`).then(sent => { if (sent) loginAttempts++; }).catch(() => {});
      return;
    }
    const code = totp();
    contents.executeJavaScript(`(function(){
      var el = document.querySelector('input[name="Code"],input#Code,input[autocomplete="one-time-code"]')
            || document.querySelector('input[type="text"],input[type="tel"],input[type="number"]');
      if(!el || el.value === '${code}') return;
      el.focus();
      var setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
      setter.call(el,'${code}');
      el.dispatchEvent(new Event('input',{bubbles:true}));
      el.dispatchEvent(new Event('change',{bubbles:true}));
      var f = el.form;
      var b = (f && f.querySelector('button[type="submit"],input[type="submit"],button:not([type])')) || document.querySelector('button[type="submit"],input[type="submit"]');
      if(b && !window.__mfaSent){ window.__mfaSent = true; setTimeout(function(){ b.click(); }, 800); }
    })();`).catch(() => {});
  };
  contents.on('did-finish-load', run);
  contents.on('did-navigate-in-page', run);
  setInterval(run, 25000);
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
    webPreferences: { partition: PARTITION, contextIsolation: true, nodeIntegration: false }
  });
  Menu.setApplicationMenu(null);
  win.loadURL(START_URL);
  win.once('ready-to-show', () => { win.show(); resetIdle(); startIdleWatcher(); if (lockNeededAtStart()) showLock(); });

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
