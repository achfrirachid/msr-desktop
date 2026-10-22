// JS snippets injected into the Massar pages (ported from MainActivity.java)
const COMMON = String.raw`
function setValue(el,val){var d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value');if(d&&d.set){d.set.call(el,val);}else{el.value=val;}el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));}
`;

exports.activity = () => String.raw`(function(){
if(window.__massarAct)return;window.__massarAct=1;var last=0;
function p(){var n=Date.now();if(n-last>5000){last=n;console.debug('__massar_active__');}}
['mousemove','mousedown','keydown','scroll','touchstart'].forEach(function(e){document.addEventListener(e,p,true);});
})();`;

exports.email = (login) => String.raw`(function(){
${COMMON}
var L=${JSON.stringify(login || '')};if(!L)return;
var inputs=document.querySelectorAll('input'),f=null,i,el,t;
for(i=0;i<inputs.length;i++){el=inputs[i];t=(el.getAttribute('type')||'').toLowerCase();
 if(t==='password'||t==='hidden'||el.offsetParent===null)continue;
 var ph=(el.getAttribute('placeholder')||'').toLowerCase();
 if(ph.indexOf('identifiant')>-1||ph.indexOf('معرف')>-1||ph.indexOf('دخول')>-1){f=el;break;}}
if(!f){for(i=0;i<inputs.length;i++){el=inputs[i];t=(el.getAttribute('type')||'').toLowerCase();
 if(el.offsetParent!==null&&(t===''||t==='text'||t==='email')){f=el;break;}}}
if(f&&!f.value){setValue(f,L);}
})();`;

exports.login = (pw) => String.raw`(function(){
if(!${JSON.stringify(!!pw)})return;
if(window.__massarLoginTimer||window.__massarLoginDone)return;
${COMMON}
var PW=${JSON.stringify(pw || '')};
function recent(){try{var a=JSON.parse(localStorage.getItem('massarAutoClicks')||'[]');var n=Date.now();return a.filter(function(x){return n-x<180000;});}catch(e){return [];}}
function saveClick(){try{var a=recent();a.push(Date.now());localStorage.setItem('massarAutoClicks',JSON.stringify(a));}catch(e){}}
function ok(b){return b&&!b.disabled&&b.getAttribute('aria-disabled')!=='true'&&b.offsetParent!==null;}
function findBtn(pass){
 var btns=document.querySelectorAll('button,input[type=submit],input[type=button],[role=button],a.btn'),i,b,t;
 var re=/connecter|login|sign in|دخول/i;
 for(i=0;i<btns.length;i++){b=btns[i];if(!ok(b))continue;t=((b.textContent||'')+' '+(b.value||'')).trim();if(re.test(t))return b;}
 var pr=pass.getBoundingClientRect(),best=null,bt=1e9;
 for(i=0;i<btns.length;i++){b=btns[i];if(!ok(b))continue;t=((b.textContent||'')+' '+(b.value||'')).trim();
  if(!t||/oubli|forgot|نسيت/i.test(t))continue;
  var r=b.getBoundingClientRect();if(r.width>60&&r.top>=pr.bottom-2&&r.top<bt){bt=r.top;best=b;}}
 if(best)return best;
 if(pass.form){var s=pass.form.querySelector('button[type=submit],input[type=submit]');if(ok(s))return s;}
 return null;
}
var tries=0;
window.__massarLoginTimer=setInterval(function(){
 tries++;
 if(tries>80){clearInterval(window.__massarLoginTimer);window.__massarLoginTimer=null;return;}
 var pass=document.querySelector('input[type=password]');
 if(!pass||pass.offsetParent===null)return;
 if(!pass.value){setValue(pass,PW);}
 if(recent().length>=3){clearInterval(window.__massarLoginTimer);window.__massarLoginTimer=null;window.__massarLoginDone=1;return;}
 var b=findBtn(pass);if(!b)return;
 clearInterval(window.__massarLoginTimer);window.__massarLoginTimer=null;window.__massarLoginDone=1;
 saveClick();setTimeout(function(){b.click();},500);
},500);
})();`;

exports.mfa = (code) => String.raw`(function(){
${COMMON}
var CODE=${JSON.stringify(code)};
function findField(){
 var inputs=document.querySelectorAll('input'),cands=[],i,el,t;
 for(i=0;i<inputs.length;i++){el=inputs[i];t=(el.getAttribute('type')||'').toLowerCase();
  if(/password|hidden|checkbox|radio|submit|button/.test(t))continue;
  if(el.offsetParent===null)continue;
  var combo=((el.getAttribute('placeholder')||'')+' '+(el.getAttribute('name')||'')+' '+(el.id||'')+' '+(el.getAttribute('aria-label')||'')).toLowerCase();
  if(combo.indexOf('code')>-1||combo.indexOf('otp')>-1||combo.indexOf('totp')>-1)return el;
  cands.push(el);}
 for(i=0;i<cands.length;i++){var c=cands[i],ml=parseInt(c.getAttribute('maxlength')||'0',10),ct=(c.getAttribute('type')||'').toLowerCase(),md=(c.getAttribute('inputmode')||'').toLowerCase();
  if((ml>0&&ml<=8)||ct==='number'||ct==='tel'||md==='numeric')return c;}
 if(cands.length)return cands[cands.length-1];
 return null;
}
function clickSubmit(){
 var els=document.querySelectorAll('button,input[type=submit],input[type=button]');
 var re=/valider|vérifier|verifier|verify|confirmer|confirm|activer|continuer|continue|submit|connecter|login|signin|^\s*ok\s*$|تأكيد|تحقق|دخول|متابعة/i;
 for(var i=0;i<els.length;i++){var b=els[i];if(b.disabled||b.offsetParent===null)continue;
  var t=((b.textContent||'')+' '+(b.value||'')).trim();if(re.test(t)){b.click();return true;}}
 var fs=document.querySelector('form button[type=submit],form input[type=submit]');
 if(fs&&!fs.disabled&&fs.offsetParent!==null){fs.click();return true;}
 return false;
}
var tries=0;
var timer=setInterval(function(){
 tries++;var f=findField();
 if(f){setValue(f,CODE);clearInterval(timer);
  var ct=0;var ci=setInterval(function(){ct++;if(clickSubmit()||ct>=20)clearInterval(ci);},450);}
 else if(tries>=30){clearInterval(timer);}
},500);
})();`;

exports.card = (choice) => {
  const re = choice === 'lead' ? 'القيادة|pilotage'
    : choice === 'fin' ? 'التدبير المالي|financi'
    : 'التمدرس|scolaris|scolarit';
  return String.raw`(function(){
var WANT=new RegExp(${JSON.stringify(re)},'i'),LEAD=/القيادة|pilotage/i,FIN=/التدبير المالي|financi/i;
var tries=0;
var iv=setInterval(function(){
 tries++;
 var txt=(document.body&&document.body.innerText)||'';
 if(LEAD.test(txt)&&FIN.test(txt)&&WANT.test(txt)){
  var all=document.querySelectorAll('a,button,div,span,h1,h2,h3,h4,p'),best=null,bl=1e9;
  for(var i=0;i<all.length;i++){var e=all[i];if(e.offsetParent===null)continue;
   var t=(e.innerText||'').trim();if(!t||t.length>60||!WANT.test(t))continue;
   if(t.length<bl){bl=t.length;best=e;}}
  if(best){clearInterval(iv);best.click();return;}
 }
 if(tries>=40)clearInterval(iv);
},500);
})();`;
};
