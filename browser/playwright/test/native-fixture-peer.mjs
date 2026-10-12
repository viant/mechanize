// Test-only native-protocol peer. It never connects to a user browser/profile.
import {chromium} from 'playwright-core';
import {createServer} from 'node:https';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createInterface} from 'node:readline';
import {webcrypto,randomBytes} from 'node:crypto';
import vm from 'node:vm';
import {pageEvents} from '../relay.mjs';

const executable=process.env.MECHANIZE_FIXTURE_CHROMIUM||'/tmp/agently-mcp-apps-audit-browsers/chromium_headless_shell-1223/chrome-headless-shell-mac-arm64/chrome-headless-shell';
const temp=await mkdtemp(join(tmpdir(),'mechanize-playwright-fixture-'));
const cert=join(temp,'cert.pem'),key=join(temp,'key.pem');
if(spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'}).status!==0)throw Error('Fixture TLS generation unavailable');
const html=`<!doctype html><html><body><section id="login"><input type="password" id="password" data-mechanize-secret><button id="sign-in">Sign in</button></section><main id="app" hidden><p id="ready">Loading</p><label>Record filter<input id="filter" aria-label="Record filter"></label><section id="results"></section><button id="review">Review selected</button><p id="review-result"></p></main><script>
let selected=[];const rows=[['group-blue','Record A'],['group-blue','Record B'],['group-green','Record C']];
document.querySelector('#sign-in').onclick=()=>{document.querySelector('#login').remove();document.querySelector('#app').hidden=false;setTimeout(()=>{document.querySelector('#ready').textContent='SPA ready';render()},80)};
function render(){const target=document.querySelector('#results');target.innerHTML='';for(const [group,label] of rows.filter(r=>r[0].includes(document.querySelector('#filter').value))){const id=label.at(-1),box=document.createElement('section');box.innerHTML='<button><span style="display:block">Expand</span><span>current row</span></button><div role="region" aria-label="Expanded record" hidden>'+label+' '+group+' <button>Select current row</button></div>';box.querySelector('button').onclick=()=>{box.querySelector('div').hidden=!box.querySelector('div').hidden};box.querySelector('div button').onclick=()=>{selected.push(label);box.querySelector('div button').disabled=true};target.append(box)}}
document.querySelector('#filter').oninput=render;document.querySelector('#review').onclick=()=>{document.querySelector('#review-result').textContent='Review: '+selected.join(', ')+'; total 2 items'};
</script></body></html>`;
const server=createServer({key:await readFile(key),cert:await readFile(cert)},(_,res)=>{res.setHeader('content-type','text/html');res.end(html);});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin=`https://127.0.0.1:${server.address().port}`;
const browser=await chromium.launch({executablePath:executable,headless:true});
const context=await browser.newContext({ignoreHTTPSErrors:true}),page=await context.newPage();await page.goto(origin);
for(const name of ['protocol','accessibility-provider','dom','secure-input'])await page.addScriptTag({content:await readFile(new URL('../../../extension/chrome/'+name+'.js',import.meta.url),'utf8')});
const scope=vm.createContext({crypto:webcrypto,TextEncoder,URL,Date,setTimeout,clearTimeout,btoa:v=>Buffer.from(v,'binary').toString('base64')});
for(const name of ['protocol','fingerprint','secure-input','cdp-transport','playwright-target','playwright-relay','playwright-worker'])vm.runInContext(await readFile(new URL('../../../extension/chrome/'+name+'.js',import.meta.url),'utf8'),scope);
const identity={profileChannel:'fixture',browserInstance:'isolated',tabId:1,frameId:0,documentId:'fixture-document',documentGeneration:1};
const document={...identity,origin,mutationFingerprintVersion:2};
const saved={},unknown=new Set(),events=new Set(),detaches=new Set();
let privateReady=false,rendererReady=false,privacyCommitted=false,rendererFence,cdp,busy=false,stopping=false,inputCount=0,attachCount=0,loseNextInput=false,maxNativeFrameBytes=0;
let delayedTargetArmed=false,timerArmed=false,timerPublisher,timerPending=Promise.resolve(),timerPublications=0,replaceOnMove=false,sensitiveOnPin=false;
const emit=value=>{const encoded=JSON.stringify(value);maxNativeFrameBytes=Math.max(maxNativeFrameBytes,Buffer.byteLength(encoded));if(Buffer.byteLength(encoded)>512*1024)throw Error('Fixture frame exceeds cap');process.stdout.write(encoded+'\n');};
const port={postMessage:emit};
const redactions=scope.MechanizeSecureInput.redactionVariants(['fixture-private-value']);
const renderer=message=>page.evaluate(message=>globalThis.__fixtureRendererMessage(message),message);
const publish=()=>emit({type:'documents',documents:[document],truncated:false,mutationFingerprintVersion:2,playwrightRelayVersion:1});
async function bindRenderer(c){
  rendererFence={brokerEpoch:c.brokerEpoch,channelEpoch:c.channelEpoch,scopeHash:c.scopeHash};
  if(!privacyCommitted){
    const permitId=randomBytes(16).toString('hex'),base={identity:c.identity,...rendererFence,deadlineUnixMs:Date.now()+3000,origin,permitId};
    const bound=await renderer({type:'credentialPrivacyBind',requestId:randomBytes(16).toString('hex'),...base,redactions:[...redactions]});
    if(!bound.ready||!bound.redactionReady)throw Error('Fixture private redactor unavailable');
    const committed=await renderer({type:'credentialPrivacyCommit',requestId:randomBytes(16).toString('hex'),...base});
    if(!committed.ready)throw Error('Fixture private redactor commit unavailable');
    privacyCommitted=true;
  }
  return renderer({type:'bind',binding:{identity:c.identity,...rendererFence,leaseRequired:true,mutationFingerprintVersion:2}});
}
async function observeRenderer(fence=rendererFence){
  if(!fence)throw Error('Fixture renderer fence unavailable');
  const proof=await renderer({requestId:'fixture-observe',action:'executor.validate',identity,...fence,deadlineUnixMs:Date.now()+3000});
  if(proof.error||!proof.identity)throw Error('Fixture renderer observation unavailable');
  Object.assign(identity,proof.identity);Object.assign(document,proof.identity);publish();return proof;
}
async function initializeRenderer(){
  if(rendererReady)return;
  await page.evaluate(()=>{
    const handlers=[];globalThis.chrome=globalThis.chrome||{};
    chrome.runtime={id:'a'.repeat(32),getManifest:()=>({permissions:['debugger']}),onMessage:{addListener:fn=>handlers.push(fn)},sendMessage:async()=>({})};
    globalThis.__fixtureRendererMessage=message=>new Promise((resolve,reject)=>{
      let resolved=false;const reply=result=>{resolved=true;resolve(result);};
      for(const handler of handlers)handler(message,{id:chrome.runtime.id,url:'chrome-extension://'+chrome.runtime.id+'/worker.js'},reply);
      if(!resolved&&handlers.length===0)reject(Error('Fixture renderer unavailable'));
    });
  });
  for(const name of ['fingerprint','recorder','content'])await page.addScriptTag({content:await readFile(new URL('../../../extension/chrome/'+name+'.js',import.meta.url),'utf8')});
  rendererReady=true;
}
async function startTimer(){
  if(!timerArmed)return;timerArmed=false;
  await page.evaluate(()=>{const node=document.createElement('aside');node.id='fixture-decoration';document.body.append(node);let tick=0;globalThis.__fixtureTimer=setInterval(()=>{node.textContent='Decoration '+(++tick)},20)});
  timerPublisher=setInterval(()=>{timerPending=timerPending.then(async()=>{await observeRenderer(rendererFence);timerPublications++;}).catch(()=>{});},40);
}
async function stopTimer(){clearInterval(timerPublisher);timerPublisher=undefined;await timerPending;await page.evaluate(()=>clearInterval(globalThis.__fixtureTimer));await observeRenderer(rendererFence);}
const api={
  tabs:{get:async id=>({id,windowId:9})},
  windows:{get:async id=>{const {bounds}=await cdp.send("Browser.getWindowForTarget");return {id,type:"normal",state:bounds.windowState||"normal",left:bounds.left,top:bounds.top,width:bounds.width,height:bounds.height};}},
  storage:{local:{setAccessLevel:async()=>{},get:async key=>({[key]:saved[key]}),set:async value=>Object.assign(saved,structuredClone(value))},session:{get:async keys=>typeof keys==='string'?{[keys]:saved[keys]}:structuredClone(saved),set:async value=>Object.assign(saved,structuredClone(value))}},
  webNavigation:{getAllFrames:async()=>[{frameId:0,documentId:identity.documentId,url:page.url()}]},
  debugger:{onEvent:{addListener:f=>events.add(f)},onDetach:{addListener:f=>detaches.add(f)},
    async attach(){attachCount++;cdp=await context.newCDPSession(page);for(const method of pageEvents)cdp.on(method,params=>{for(const listener of events)listener({tabId:1},method,params)});},
    async sendCommand(target,method,params){
      if(target.tabId!==1||target.sessionId!==undefined)throw Error('Fixture foreign target');
      const actual=method==='Input.insertText'||method==='Input.dispatchMouseEvent'&&params?.type==='mousePressed'||method==='Input.dispatchKeyEvent'&&['rawKeyDown','keyDown'].includes(params?.type);
      if(actual)inputCount++;
      const result=await cdp.send(method,params);
      if(replaceOnMove&&method==='Input.dispatchMouseEvent'&&params?.type==='mouseMoved'){
        replaceOnMove=false;await page.locator('#review').evaluate(el=>el.replaceWith(el.cloneNode(true)));
      }
      if(sensitiveOnPin&&method==='Runtime.callFunctionOn'&&scope.MechanizePlaywrightTarget.pinnedObject(params,result)){
        sensitiveOnPin=false;await page.locator('#filter').evaluate(el=>{el.type='password';el.setAttribute('data-mechanize-secret','')});
      }
      if(actual&&loseNextInput){loseNextInput=false;throw Error('Fixture lost input acknowledgement');}
      return result;
    },
    async detach(){await cdp?.detach();for(const listener of detaches)listener({tabId:1},'target_closed');},
  },
};
const worker=scope.MechanizePlaywrightWorker.create(api,{
  port:()=>port,
  async acquire(held){
    if(busy||!privateReady||unknown.size)throw Error('Fixture authority unavailable');busy=true;
    const c=held.command;
    const bind=await bindRenderer(c);
    if(bind.error||bind.identity.documentGeneration!==c.identity.documentGeneration)throw Error('Fixture renderer binding changed');
    if(held.mutation){
      const acquired=await renderer({requestId:c.requestId+'-acquire',action:'executor.acquire',identity:c.identity,brokerEpoch:c.brokerEpoch,channelEpoch:c.channelEpoch,scopeHash:c.scopeHash,deadlineUnixMs:c.deadlineUnixMs,controlLease:c.controlLease});
      if(acquired.error||!acquired.controlLease)throw Error('Fixture renderer lease unavailable');
    }
    await startTimer();
    if(delayedTargetArmed){delayedTargetArmed=false;await page.evaluate(()=>{const targets=[...document.querySelectorAll('#results > section > button')];for(const target of targets)target.hidden=true;setTimeout(()=>{for(const target of targets)target.hidden=false;},250);});}

  },
  release(held){
    busy=false;
    if(held.inputCrossed&&held.observedIdentity){Object.assign(identity,held.observedIdentity);Object.assign(document,held.observedIdentity);publish();}
  },
  async current(held){
    const c=held.command;
    if(!privateReady||held.closed||held.originalPort!==port||held.identity.documentId!==identity.documentId||held.origin!==origin||![...unknown].every(a=>a===c.attemptId)||!await page.evaluate(origin=>MechanizeSecureInput.privacyReady(document,origin),origin))return false;
    const proof=await renderer({requestId:c.requestId,action:'executor.validate',identity:c.identity,brokerEpoch:c.brokerEpoch,channelEpoch:c.channelEpoch,scopeHash:c.scopeHash,deadlineUnixMs:c.deadlineUnixMs});
    if(proof.error||proof.validated!==true||proof.identity.documentId!==identity.documentId||proof.identity.documentGeneration<c.identity.documentGeneration)return false;
    if(!held.observedIdentity||proof.identity.documentGeneration>held.observedIdentity.documentGeneration)held.observedIdentity=proof.identity;return true;
  },
  unknown:(id,value)=>value?unknown.add(id):unknown.delete(id),
  redact:value=>scope.MechanizeSecureInput.redact(value,redactions),
});
async function stop(){
  if(stopping)return;stopping=true;clearInterval(timerPublisher);worker.invalidate();await timerPending;await browser.close();await new Promise(resolve=>server.close(resolve));await rm(temp,{recursive:true,force:true});
}
const lines=createInterface({input:process.stdin,crlfDelay:Infinity});
let lane=Promise.resolve();
lines.on('line',line=>{
  if(Buffer.byteLength(line)>512*1024){void stop();return;}
  let message;try{message=JSON.parse(line);}catch{return;}
  lane=lane.then(async()=>{
    if(message.type==='fixture.private-login'){
      await page.locator('#password').fill('fixture-private-value');await page.locator('#sign-in').click();await page.locator('#ready').getByText('SPA ready',{exact:true}).waitFor();
      privateReady=await page.evaluate(origin=>MechanizeSecureInput.privacyReady(document,origin),origin);
      await initializeRenderer();
      emit({type:'fixture.private-ready',document,privacyReady:privateReady});return;
    }
    if(message.type==='fixture.reflect'){
      await page.locator('#review-result').evaluate(el=>{el.textContent+=' fixture-private-value'});
      await observeRenderer(rendererFence);
      emit({type:'fixture.reflected',identity:{...identity}});return;
    }
    if(message.type==='fixture.observe'){
      const fence=message.brokerEpoch&&message.channelEpoch&&message.scopeHash?{brokerEpoch:message.brokerEpoch,channelEpoch:message.channelEpoch,scopeHash:message.scopeHash}:rendererFence;
      await observeRenderer(fence);emit({type:'fixture.observed',document});return;
    }
    if(message.type==='fixture.lose-next-input'){loseNextInput=true;emit({type:'fixture.input-reply-armed'});return;}
    if(message.type==='fixture.arm-delayed-target'){delayedTargetArmed=true;timerArmed=true;emit({type:'fixture.delayed-target-armed'});return;}
    if(message.type==='fixture.arm-timer'){timerArmed=true;emit({type:'fixture.timer-armed'});return;}
    if(message.type==='fixture.stop-timer'){await stopTimer();emit({type:'fixture.timer-stopped',timerPublications});return;}
    if(message.type==='fixture.arm-target-replacement'){replaceOnMove=true;emit({type:'fixture.target-replacement-armed'});return;}
    if(message.type==='fixture.arm-sensitive-switch'){sensitiveOnPin=true;emit({type:'fixture.sensitive-switch-armed'});return;}
    if(message.type==='fixture.restore-filter'){await page.locator('#filter').evaluate(el=>{el.type='text';el.removeAttribute('data-mechanize-secret')});await observeRenderer(rendererFence);emit({type:'fixture.filter-restored'});return;}
    if(message.type==='fixture.peek'){emit({type:'fixture.state',privacyReady:privateReady,inputCount,attachCount,maxNativeFrameBytes,unknownCount:unknown.size,timerPublications,reviewMatched:(await page.locator('#review-result').textContent()).startsWith('Review: Record A, Record B; total 2 items')});return;}
    if(message.type==='fixture.stop'){await stop();lines.close();return;}
    if(message.type?.startsWith('playwright.')){await worker.receive(message,port);return;}
    if(message.action==='receipt.query'){const result=await worker.query(message);emit(result||{requestId:message.requestId,receiptAvailable:false,dispatchState:'notDispatched',effectState:'none'});return;}
    if(['observe','executor.validate','executor.acquire','executor.retire'].includes(message.action)){
      const bind=await bindRenderer(message);if(bind.error){emit({...bind,requestId:message.requestId});return;}
      const reply=await renderer(message);emit(reply);return;
    }
    emit({requestId:message.requestId,error:{code:'fixtureUnsupportedAction',message:'Test fixture supports only private Playwright and receipt commands',dispatchState:'notDispatched',effectState:'none'}});
  }).catch(()=>emit({type:'fixture.error',errorCode:'fixtureUnavailable'}));
});
lines.on('close',()=>{void stop();});
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>{void stop().finally(()=>process.exit());});
emit({type:'fixture.ready',document,privacyReady:false,playwrightRelayVersion:1});
