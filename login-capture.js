// يلتقط الباسورد اللي كتبتي بيدك فصفحة الدخول (يتحفظ فقط بعد نجاح الدخول)
const { ipcRenderer } = require('electron');
function grab() {
  const pw = document.querySelector('input[type="password"]');
  if (!pw || !pw.value) return;
  const form = pw.form || document;
  const user = form.querySelector('input[type="text"],input[type="email"],input:not([type])');
  ipcRenderer.send('pw-captured', { u: user ? user.value : '', p: pw.value });
}
document.addEventListener('click', e => { if (e.isTrusted && e.target.closest && e.target.closest('button,input[type="submit"]')) grab(); }, true);
document.addEventListener('submit', grab, true);
document.addEventListener('keydown', e => { if (e.isTrusted && e.key === 'Enter') grab(); }, true);
