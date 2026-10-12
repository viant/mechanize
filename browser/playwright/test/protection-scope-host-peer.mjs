// Disposable production-worker bridge for the real Host/durable Prepare test.
// Fixture controls are test-only; replies contain synthetic identity/closed state.
import {chromium} from 'playwright-core';
import {createServer} from 'node:https';
import {mkdtemp,cp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';
import {spawnSync} from 'node:child_process';import {createInterface} from 'node:readline';
const directory=await mkdtemp(join(tmpdir(),'mechanize-host-scope-')),heldResponses=new Set();
let context,server,worker,page,target,publicPage,origin,original,stopped=false,provisional,extension;
const emit=v=>process.stdout.write(JSON.stringify(v)+'\n');
async function stop(){if(stopped)return;stopped=true;clearTimeout(watchdog);await context?.close();for(const response of heldResponses)response.destroy();server?.closeAllConnections();if(server)await new Promise(r=>server.close(r));await rm(directory,{recursive:true,force:true});}
const watchdog=setTimeout(()=>stop().finally(()=>process.exit(1)),85000);
async function init(){
 const key=join(directory,'key.pem'),cert=join(directory,'cert.pem');if(spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'}).status!==0)throw Error();
 server=createServer({key:await readFile(key),cert:await readFile(cert)},(req,res)=>{
  if(req.url.startsWith('/stall')||req.url==='/hold'){heldResponses.add(res);res.on('close',()=>heldResponses.delete(res));return;}
  res.setHeader('content-type','text/html');
  if(req.url.startsWith('/ad')){res.end('<p>Decorative frame</p>');return;}
  res.end(req.url==='/public'?'<title>Public fixture</title><h1>Independent public fixture</h1>':req.url.startsWith('/slow')?'<title>Committed synthetic history</title><img src="/stall"><iframe src="/ad"></iframe><script>let n=0;setInterval(()=>{document.querySelector("iframe").src="/ad?n="+(++n)},35)</script>':'<title>Synthetic sign-in</title><form><input autocomplete="username"><input type="password"><button>Sign in</button></form>');
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));origin='https://127.0.0.1:'+server.address().port;
 extension=join(directory,'extension');await cp(new URL('../../../extension/chrome',import.meta.url),extension,{recursive:true,filter:p=>!p.includes('/test')&&!p.includes('/node_modules')});
 const manifest=JSON.parse(await readFile(join(extension,'manifest.json'),'utf8'));manifest.host_permissions=[origin+'/*'];await writeFile(join(extension,'manifest.json'),JSON.stringify(manifest));
 const source=await readFile(join(extension,'worker.js'),'utf8');
 const boot=`const fixtureFrames=[];chrome.runtime.connectNative=()=>({onMessage:{addListener(){}},onDisconnect:{addListener(){}},disconnect(){},postMessage:f=>fixtureFrames.push(f)});const seeded=chrome.storage.local.set({enrollment:{profileChannel:'profile',browserInstance:'browser',origins:[${JSON.stringify(origin)}]}});const get=chrome.storage.local.get.bind(chrome.storage.local);chrome.storage.local.get=async(...args)=>{await seeded;return get(...args);};`;
 const probe=`
 const fixtureNativeSend=chrome.tabs.sendMessage.bind(chrome.tabs),fixtureNativeScript=chrome.scripting.executeScript.bind(chrome.scripting);
 const fixtureNativeTabUpdate=chrome.tabs.update.bind(chrome.tabs),fixtureNativeWindowUpdate=chrome.windows.update.bind(chrome.windows);
 globalThis.fixtureReady=true;let fixtureSource,fixtureTarget,fixturePublic,fixtureOrigin,fixtureForbidden=0;const fixtureTrace=[];
 const originalRespond=protectionScopes.respond;protectionScopes.respond=async(q,...rest)=>{const r=await originalRespond(q,...rest);fixtureTrace.push({mode:q.mode,reason:r?.reason||'noReply'});return r;};
 const metadata=async tab=>{const f=(await chrome.webNavigation.getAllFrames({tabId:tab.id})).find(f=>f.frameId===0);return {profileChannel:'profile',browserInstance:'browser',tabId:tab.id,frameId:0,documentId:f.documentId,documentGeneration:1};};
 globalThis.fixtureInit=async origin=>{
  fixtureOrigin=origin;await receive({type:'processQualified',brokerEpoch:'fixture-broker',channelEpoch:'fixture-channel',scopeHash:'a'.repeat(64),scopeQualified:true,profileQualified:true,executorQualified:false,fixtureOnly:false,executorChallenge:'fixture-challenge',mutationFingerprintVersion:2});
  const tabs=await chrome.tabs.query({url:origin+'/*'});fixtureSource=tabs.find(t=>new URL(t.url).pathname==='/source');fixtureTarget=tabs.find(t=>new URL(t.url).pathname==='/target');fixturePublic=tabs.find(t=>new URL(t.url).pathname==='/public');
  for(const [obj,key]of [[chrome.tabs,'sendMessage'],[chrome.scripting,'executeScript'],[chrome.tabs,'update'],[chrome.tabs,'remove'],[chrome.debugger,'sendCommand']])obj[key]=async()=>{fixtureForbidden++;throw Error('forbidden')};
  return {sourceIdentity:await metadata(fixtureSource),targetIdentity:await metadata(fixtureTarget),publicIdentity:await metadata(fixturePublic)};
 };
 globalThis.fixtureVisibilityUnknown=async(input={})=>{
  const blocked=chrome.tabs.update;let updates=0,focuses=0;
  chrome.tabs.update=async(...args)=>{updates++;return fixtureNativeTabUpdate(...args);};
  chrome.windows.update=async(...args)=>{focuses++;await fixtureNativeWindowUpdate(...args);throw Error('fixture-lost-focus-ack');};
  const attempt=input.browserAttemptID||'e'.repeat(64),selected=input.targetIdentity?([fixtureSource,fixtureTarget,fixturePublic].find(t=>t.id===input.targetIdentity.tabId)):fixtureTarget;if(!/^[a-f0-9]{64}$/.test(attempt)||!selected)throw Error();if(input.targetIdentity&&(await metadata(selected)).documentId!==input.targetIdentity.documentId)throw Error();fixtureFrames.length=0;
  try{await receive({type:'browser.activateTab',requestId:'f'.repeat(64),attemptId:attempt,origin:fixtureOrigin,...setupFence,deadlineUnixMs:Date.now()+2000,tabId:selected.id});}
  finally{chrome.tabs.update=blocked;chrome.windows.update=fixtureNativeWindowUpdate;}
  const result=fixtureFrames.find(f=>f.type==='browser.activateTabResult');
  const retained=(await chrome.storage.session.get('browserReceipt:'+attempt))['browserReceipt:'+attempt];
  return {receiptRetained:retained?.dispatchState==='unknown',activationUnknown:result?.dispatchState==='unknown'&&retained?.dispatchState==='unknown',unknownCount:unknownAttempts.size,activationUpdates:updates,activationFocus:focuses,forbidden:fixtureForbidden};
 };
 globalThis.fixturePublicRead=async()=>{
  const originalSend=chrome.tabs.sendMessage,originalScript=chrome.scripting.executeScript;
  const actual=await metadata(fixturePublic),identity=documents.get(actual.tabId+':'+actual.documentId)||actual;fixtureFrames.length=0;
  chrome.tabs.sendMessage=fixtureNativeSend;chrome.scripting.executeScript=fixtureNativeScript;
  try{await receive({requestId:'public-read-'+crypto.randomUUID(),action:'observe',identity,brokerEpoch:grant?.brokerEpoch,channelEpoch:grant?.channelEpoch,scopeHash:grant?.scopeHash,deadlineUnixMs:Date.now()+2000});}
  finally{chrome.tabs.sendMessage=originalSend;chrome.scripting.executeScript=originalScript;}
  const result=fixtureFrames.find(f=>f.requestId?.startsWith('public-read-')),encoded=JSON.stringify(result||{});
  return {readReason:result?.error?.code||(result?'none':'noReply'),setupAttention:connectionAttention,grantAvailable:!!grant,available:!!result&&!result.error,containsFixture:encoded.includes('Independent public fixture'),publicIdentity:identity,readCalls:1,forbidden:fixtureForbidden};
 };
 globalThis.fixtureState=async original=>{const tab=await chrome.tabs.get(fixtureSource.id),frames=await chrome.webNavigation.getAllFrames({tabId:fixtureSource.id});return {loading:tab.status==='loading',pending:Boolean(tab.pendingUrl),sourcePresent:frames.some(f=>f.documentId===original.documentId),activeRoot:frames.some(f=>f.frameId===0&&f.documentLifecycle==='active'),sourceIdentity:await metadata(tab)};};
 globalThis.fixtureRun=async input=>{
  const s=input.scope,i=s.identity,q={type:'credentialScope',requestId:'b'.repeat(64),mode:input.op,preparationId:s.preparationId,sourceIdentity:i,sourceOrigin:s.origin,loginRouteSHA256:s.loginRouteSHA256||'',brokerEpoch:setupFence.brokerEpoch,channelEpoch:setupFence.channelEpoch,scopeHash:setupFence.scopeHash,deadlineUnixMs:Date.now()+2000,targetTabId:0,targetOrigin:''};
  if(input.op==='capture'){const actual=await metadata(await chrome.tabs.get(i.tabId));if(actual.documentId!==i.documentId)throw Error();q.controlLease=input.controlLease||{id:'fixture-lease',generation:1};privateAdmission={port,identity:i};documentControlLeases.set(i.tabId+':'+i.documentId,q.controlLease);}
  if(input.op==='disjoint'){const target=input.targetIdentity||await metadata(fixtureTarget);q.targetTabId=target.tabId;q.targetOrigin=fixtureOrigin;}
  fixtureFrames.length=0;await receive(q);const r=fixtureFrames.find(f=>f.type==='credentialScopeResult');if(!r)throw Error();
  const records=(await chrome.storage.local.get(MechanizeProtectionScopes.KEY))[MechanizeProtectionScopes.KEY]?.records||[];
  return {ok:r.ready,reason:r.reason,loginRouteSHA256:r.loginRouteSHA256,retired:records.find(v=>v.preparationId===s.preparationId)?.retired||false,trace:fixtureTrace.splice(0),forbidden:fixtureForbidden};
 };
 globalThis.fixtureRestore=async original=>{const state=await fixtureState(original);const tab=await chrome.tabs.get(fixtureSource.id);const frames=await chrome.webNavigation.getAllFrames({tabId:fixtureSource.id});const root=frames.find(f=>f.frameId===0);return {...state,routeRestored:new URL(root.url).pathname==='/source'&&new URL(tab.url).pathname==='/source',originalRestored:state.sourcePresent,protected:protectionScopes.protects(tab.url,state.sourceIdentity)};};`;
 await writeFile(join(extension,'worker.js'),boot+'\n'+source+'\n'+probe);
 const state=await launch();original=state.sourceIdentity;return state;
}
async function processState(){const cdp=await context.browser().newBrowserCDPSession();try{const result=await cdp.send('SystemInfo.getProcessInfo');const browser=result.processInfo.filter(p=>p.type==='browser');if(browser.length!==1||!Number.isSafeInteger(browser[0].id))throw Error();return {processPID:browser[0].id};}finally{await cdp.detach();}}
async function launch(){
 context=await chromium.launchPersistentContext(join(directory,'profile'),{executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,ignoreHTTPSErrors:true,ignoreDefaultArgs:['--disable-extensions','--disable-back-forward-cache'],args:['--enable-unsafe-extension-debugging']});
 page=await context.newPage();await page.goto(origin+'/source');target=await context.newPage();await target.goto(origin+'/target');publicPage=await context.newPage();await publicPage.goto(origin+'/public');
 const cdp=await context.browser().newBrowserCDPSession(),next=context.waitForEvent('serviceworker',{timeout:10000});await cdp.send('Extensions.loadUnpacked',{path:extension});worker=await next;
 await worker.evaluate(async()=>{for(let i=0;i<200&&!globalThis.fixtureReady;i++)await new Promise(r=>setTimeout(r,10));await new Promise(r=>setTimeout(r,50));});
 const state=await worker.evaluate(origin=>fixtureInit(origin),origin);return {origin,...state,...await processState()};
}
async function waitState(predicate){for(let i=0;i<100;i++){const state=await worker.evaluate(original=>fixtureState(original),original);if(predicate(state))return state;await new Promise(r=>setTimeout(r,20));}throw Error();}
const lines=createInterface({input:process.stdin,crlfDelay:Infinity});let lane=Promise.resolve();
lines.on('line',line=>{lane=lane.then(async()=>{let q;try{
 q=JSON.parse(line);let result={ok:true};
 if(q.op==='init')result={...result,...await init()};
 else if(q.op==='visibilityUnknown'||q.op==='activationUnknown')result={...result,...await worker.evaluate(q=>fixtureVisibilityUnknown(q),q)};
 else if(q.op==='publicRead')result={...result,...await worker.evaluate(()=>fixturePublicRead())};
 else if(q.op==='processState')result={...result,...await processState()};
 else if(q.op==='stopChrome'){await context.close();context=null;for(const response of heldResponses)response.destroy();result={...result,chromeStopped:true};}
 else if(q.op==='launchChrome'){if(context)throw Error();result={...result,...await launch()};}
 else if(q.op==='restartChrome'){await context.close();context=null;for(const response of heldResponses)response.destroy();const state=await launch();result={...result,...state};}
 else if(q.op==='loadingProvisional'){provisional=page.goto(origin+'/hold',{waitUntil:'commit',timeout:15000}).catch(()=>{});result={...result,...await waitState(s=>s.loading&&s.sourcePresent)};}
 else if(q.op==='loadingCommitted'){await page.goto(origin+'/slow-source',{waitUntil:'commit'});await provisional;result={...result,...await waitState(s=>s.loading&&!s.sourcePresent&&s.activeRoot)};}
 else if(q.op==='state')result={...result,...await worker.evaluate(original=>fixtureState(original),original)};
 else if(q.op==='restoreSource'){
  // The aborted provisional navigation may itself occupy a history entry.
  // Restore the exact synthetic source entry, never the adjacent pending URL.
  const historySession=await context.newCDPSession(page),history=await historySession.send('Page.getNavigationHistory');
  const entry=history.entries.slice(0,history.currentIndex).find(e=>e.url===origin+'/source');if(!entry)throw Error();
  await historySession.send('Page.navigateToHistoryEntry',{entryId:entry.id});await historySession.detach();
  let restored;for(let i=0;i<200;i++){restored=await worker.evaluate(original=>fixtureRestore(original),original);if(restored.routeRestored)break;await new Promise(r=>setTimeout(r,20));}
  if(!restored?.routeRestored)throw Error();result={...result,...restored};
 }
 else if(['capture','absent','retire','disjoint'].includes(q.op))result=await worker.evaluate(input=>fixtureRun(input),q);
 else if(q.op==='stop'){await stop();emit({id:q.id,ok:true,phase:q.op,reason:'none'});lines.close();process.exit(0);}
 else throw Error();
 emit({id:q.id,phase:q.op,reason:'none',...result});
 }catch{emit({id:q?.id,ok:false,phase:q?.op,reason:'fixtureUnavailable'});}});});
lines.on('close',()=>lane.finally(()=>stop()).finally(()=>process.exit(0)));
