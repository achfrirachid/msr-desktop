const { app, BrowserWindow, Menu, ipcMain, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const inject = require('./inject');
const { totp } = require('./totp');

const DEFAULT_URL = 'https://massar.men.gov.ma';
const TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes of inactivity -> lock

let win = null, lockWin = null, settingsWin = null;
let locked = true;
let sess = null;          // { pw, data } - only in memory while unlocked
let lastActive = Date.now();
let lastUrl = '', mfaTried = false, cardAttempts = 0, cardAt = 0;

// ---------- config + encrypted vault (AES-256-GCM, key from app password via scrypt) ----------
const cfgFile = () => path.join(app.getPath('userData'), 'config.json');
function loadCfg() { try { return JSON.parse(fs.readFileSync(cfgFile(), 'utf8')); } catch (e) { return {}; } }
function saveCfg(c) { fs.mkdirSync(path.dirname(cfgFile()), { recursive: true }); fs.writeFileSync(cfgFile(), JSON.stringify(c, null, 2), { mode: 0o600 }); }
let cfg = {};

const kdf = (pw, salt) => crypto.scryptSync(pw, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
function encryptVault(obj, pw) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', kdf(pw, salt), iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return Buffer.concat([salt, iv, c.getAuthTag(), ct]).toString('base64');
}
function decryptVault(b64, pw) {
  const b = Buffer.from(b64, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', kdf(pw, b.subarray(0, 16)), b.subarray(16, 28));
  d.setAuthTag(b.subarray(28, 44));
  return JSON.parse(Buffer.concat([d.update(b.subarray(44)), d.final()]).toString('utf8'));
}

// ---------- windows ----------
function siteUrl() { return cfg.url || DEFAULT_URL; }

function createMain() {
  win = new BrowserWindow({
    width: 1200, height: 800, title: 'مسار',
    icon: path.join(__dirname, 'icon.png'),
    webPreferences: { contextIsolation: true, sandbox: true },
  });
  const wc = win.webContents;
  wc.setUserAgent(wc.getUserAgent().replace(/ Electron\/[\d.]+/, '').replace(/ massar-desktop\/[\d.]+/, ''));
  wc.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\/([^/]+\.)?men\.gov\.ma(\/|$)/i.test(url)) return { action: 'allow' };
    shell.openExternal(url);
    return { action: 'deny' };
  });
  wc.on('did-finish-load', () => handleUrl(true));
  wc.on('did-navigate-in-page', () => handleUrl(true));
  wc.on('console-message', (e, level, message) => { if (message === '__massar_active__') lastActive = Date.now(); });
  wc.on('before-input-event', () => { lastActive = Date.now(); });
  win.on('closed', () => { win = null; app.quit(); });
  wc.loadURL(siteUrl());
}

function showLock() {
  if (!win || lockWin) return;
  locked = true; sess = null;
  if (settingsWin) settingsWin.close();
  const b = win.getBounds();
  lockWin = new BrowserWindow({
    parent: win, modal: true, frame: false, x: b.x, y: b.y, width: b.width, height: b.height,
    resizable: false, minimizable: false, closable: false, backgroundColor: '#103820',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true },
  });
  lockWin.setMenu(null);
  lockWin.loadFile(path.join(__dirname, 'lock.html'));
  lockWin.on('closed', () => { lockWin = null; });
}

function unlockWith(pw, data, firstRun) {
  sess = { pw, data };
  locked = false;
  lastActive = Date.now();
  if (lockWin) { lockWin.destroy(); lockWin = null; }
  lastUrl = '';
  handleUrl(true);
  if (firstRun || !data.login) openSettings();
}

function openSettings() {
  if (locked || !win) return;
  if (settingsWin) { settingsWin.focus(); return; }
  settingsWin = new BrowserWindow({
    parent: win, width: 480, height: 680, title: 'الإعدادات', autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true },
  });
  settingsWin.setMenu(null);
  settingsWin.loadFile(path.join(__dirname, 'settings.html'));
  settingsWin.on('closed', () => { settingsWin = null; });
}

// ---------- auto login / MFA / card (runs only while unlocked) ----------
function handleUrl(force) {
  if (!win || locked || !sess) return;
  const wc = win.webContents;
  const url = wc.getURL();
  if (!url) return;
  if (!force && url === lastUrl) return;
  lastUrl = url;
  const u = url.toLowerCase();
  const isMfa = u.includes('mfa'), isSetup = u.includes('setup');
  const isLogin = u.includes('idprovider') && !isMfa;
  const run = (js) => wc.executeJavaScript(js).catch(() => {});
  const d = sess.data;

  run(inject.activity());
  if (!isMfa) {
    mfaTried = false;
    run(inject.email(d.login));
    run(inject.login(d.massarPw));
  } else if (!isSetup && !mfaTried && d.totp) {
    mfaTried = true; // one attempt per MFA page (avoid burning attempts)
    const rem = 30 - (Math.floor(Date.now() / 1000) % 30);
    const go = () => { const code = totp(sess && sess.data.totp); if (code) run(inject.mfa(code)); };
    if (rem <= 4) setTimeout(go, (rem + 1) * 1000); else go();
  }
  if (isMfa || isLogin) { cardAttempts = 0; cardAt = 0; }
  else if (!isSetup && (d.card || 'tam') !== 'off' && cardAttempts < 4 && Date.now() - cardAt > 25000) {
    cardAttempts++; cardAt = Date.now();
    run(inject.card(d.card || 'tam'));
  }
}

// ---------- IPC ----------
ipcMain.handle('lock:state', () => ({ setup: !cfg.vault }));

ipcMain.handle('lock:setup', (e, pw) => {
  if (cfg.vault || typeof pw !== 'string' || pw.length < 4) return { ok: false };
  cfg.vault = encryptVault({}, pw);
  saveCfg(cfg);
  unlockWith(pw, {}, true);
  return { ok: true };
});

ipcMain.handle('lock:unlock', (e, pw) => {
  try {
    const data = decryptVault(cfg.vault, String(pw || ''));
    unlockWith(String(pw), data, false);
    return { ok: true };
  } catch (err) { return { ok: false }; }
});

ipcMain.handle('settings:get', () => {
  if (locked || !sess) return null;
  const d = sess.data;
  return { login: d.login || '', url: cfg.url || '', defaultUrl: DEFAULT_URL, card: d.card || 'tam', hasPw: !!d.massarPw, hasTotp: !!d.totp };
});

ipcMain.handle('settings:save', (e, s) => {
  if (locked || !sess || !s) return { ok: false, error: 'locked' };
  const d = sess.data;
  if (typeof s.login === 'string') d.login = s.login.trim();
  if (s.massarPw) d.massarPw = String(s.massarPw);
  if (s.totp) {
    const clean = String(s.totp).replace(/\s/g, '').toUpperCase();
    if (clean.length < 16) return { ok: false, error: 'سر التحقق (TOTP) ناقص' };
    d.totp = clean;
  }
  if (['off', 'lead', 'tam', 'fin'].includes(s.card)) d.card = s.card;
  if (s.newAppPw) {
    if (String(s.newAppPw).length < 4) return { ok: false, error: 'باسورد التطبيق قصير' };
    sess.pw = String(s.newAppPw);
  }
  let urlChanged = false;
  const url = (s.url || '').trim();
  if (url && !/^https:\/\//i.test(url)) return { ok: false, error: 'الرابط خاصو يبدا بـ https://' };
  if ((url || '') !== (cfg.url || '')) { cfg.url = url || undefined; urlChanged = true; }
  cfg.vault = encryptVault(d, sess.pw);
  saveCfg(cfg);
  if (urlChanged && win) win.webContents.loadURL(siteUrl());
  return { ok: true };
});

ipcMain.handle('settings:close', () => { if (settingsWin) settingsWin.close(); });

// ---------- app ----------
function buildMenu() {
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: 'مسار', submenu: [
      { label: 'الإعدادات', accelerator: 'CmdOrCtrl+,', click: openSettings },
      { label: 'قفل الآن', accelerator: 'CmdOrCtrl+L', click: showLock },
      { type: 'separator' },
      { label: 'خروج', role: 'quit' },
    ] },
    { label: 'تصفح', submenu: [
      { label: 'رجوع', accelerator: 'Alt+Left', click: () => { if (win && win.webContents.canGoBack()) win.webContents.goBack(); } },
      { label: 'إعادة تحميل', accelerator: 'F5', click: () => { if (win) win.webContents.reload(); } },
      { label: 'ملء الشاشة', role: 'togglefullscreen' },
    ] },
  ]));
}

if (!app.requestSingleInstanceLock()) { app.quit(); }
else {
  app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
  app.whenReady().then(() => {
    cfg = loadCfg();
    buildMenu();
    createMain();
    showLock();
    setInterval(() => {
      if (!locked && Date.now() - lastActive >= TIMEOUT_MS) showLock();
      else handleUrl(false);
    }, 10000);
  });
  app.on('window-all-closed', () => app.quit());
}
