// Real disposable Chrome API evidence only. Native transport/process trust use
// fixture adapters; no user profile, installed host, website or credential input.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {createServer} from 'node:https';
import {mkdtemp,cp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

test('real Chrome loading source retirement uses committed document absence while target stays strict',{timeout:30000},async()=>{
 const directory=await mkdtemp(join(tmpdir(),'mechanize-source-loading-')),cert=join(directory,'cert.pem'),key=join(directory,'key.pem');
 let context,server;const heldResponses=new Set();let heldRequest;
 const pendingRequest=new Promise(resolve=>{heldRequest=resolve;});
 try{
  assert.equal(spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'}).status,0);
  server=createServer({key:await readFile(key),cert:await readFile(cert)},(req,res)=>{
   if(req.url==='/hold'||req.url.startsWith('/stall')){heldResponses.add(res);res.on('close',()=>heldResponses.delete(res));if(req.url==='/hold')heldRequest();return;}
   res.setHeader('content-type','text/html');res.end(req.url.startsWith('/slow')?'<title>Synthetic loading document</title><img src="/stall"><p>Public fixture</p>':req.url==='/public'?'<title>Public fixture</title><p>History fixture</p>':'<title>Synthetic source</title><input type="password" value="PRIVATE-CANARY">');
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='https://127.0.0.1:'+server.address().port;
  const extension=join(directory,'extension');await cp(new URL('../../../extension/chrome',import.meta.url),extension,{recursive:true,filter:p=>!p.includes('/test')&&!p.includes('/node_modules')});
  const manifest=JSON.parse(await readFile(join(extension,'manifest.json'),'utf8'));manifest.host_permissions=[origin+'/*'];await writeFile(join(extension,'manifest.json'),JSON.stringify(manifest));
  const source=await readFile(join(extension,'worker.js'),'utf8');
  const boot=`const fixtureFrames=[];chrome.runtime.connectNative=()=>({onMessage:{addListener(){}},onDisconnect:{addListener(){}},disconnect(){},postMessage:f=>fixtureFrames.push(f)});const seeded=chrome.storage.local.set({enrollment:{profileChannel:'fixture',browserInstance:'isolated',origins:[${JSON.stringify(origin)}]}});const get=chrome.storage.local.get.bind(chrome.storage.local);chrome.storage.local.get=async(...args)=>{await seeded;return get(...args);};`;
  const probe=`
   globalThis.fixtureReady=true;let fixtureSource,fixtureTarget,fixtureBase,fixtureForbidden=0;
   globalThis.fixtureInit=async origin=>{
    await receive({type:'processQualified',brokerEpoch:'fixture-broker',channelEpoch:'fixture-channel',scopeHash:'a'.repeat(64),scopeQualified:true,profileQualified:true,executorQualified:false,fixtureOnly:false,executorChallenge:'fixture-challenge',mutationFingerprintVersion:2});
    const tabs=await chrome.tabs.query({url:origin+'/*'});fixtureSource=tabs.find(t=>new URL(t.url).pathname==='/source');fixtureTarget=tabs.find(t=>new URL(t.url).pathname==='/target');
    const frame=(await chrome.webNavigation.getAllFrames({tabId:fixtureSource.id})).find(f=>f.frameId===0);
    fixtureBase={type:'credentialScope',requestId:'b'.repeat(64),preparationId:'c'.repeat(64),sourceIdentity:{profileChannel:'fixture',browserInstance:'isolated',tabId:fixtureSource.id,frameId:0,documentId:frame.documentId,documentGeneration:1},sourceOrigin:origin,loginRouteSHA256:'',brokerEpoch:setupFence.brokerEpoch,channelEpoch:setupFence.channelEpoch,scopeHash:setupFence.scopeHash,targetTabId:0,targetOrigin:''};
    const lease={id:'fixture-lease',generation:1};privateAdmission={port,identity:fixtureBase.sourceIdentity};documentControlLeases.set(fixtureSource.id+':'+frame.documentId,lease);
    fixtureFrames.length=0;await receive({...fixtureBase,mode:'capture',controlLease:lease,deadlineUnixMs:Date.now()+2000});const r=fixtureFrames.find(f=>f.type==='credentialScopeResult');
    if(!r?.ready)throw Error('fixture capture unavailable');fixtureBase.loginRouteSHA256=r.loginRouteSHA256;
    await chrome.storage.session.set({'receipt:fixture-retained':{dispatchState:'unknown',attemptId:'fixture-retained'}});unknownAttempts.add('fixture-retained');
    for(const [obj,key]of [[chrome.tabs,'sendMessage'],[chrome.scripting,'executeScript'],[chrome.tabs,'update'],[chrome.tabs,'remove'],[chrome.debugger,'sendCommand']])obj[key]=async()=>{fixtureForbidden++;throw Error('forbidden')};
    return {captured:true};
   };
   globalThis.fixtureState=async()=>{const tab=await chrome.tabs.get(fixtureSource.id),frames=await chrome.webNavigation.getAllFrames({tabId:fixtureSource.id});return {loading:tab.status==='loading',pending:Boolean(tab.pendingUrl),original:frames.some(f=>f.documentId===fixtureBase.sourceIdentity.documentId),activeRoot:frames.some(f=>f.frameId===0&&f.documentLifecycle==='active')};};
   globalThis.fixtureProof=async mode=>{
    const q={...fixtureBase,mode,deadlineUnixMs:Date.now()+2000};
    if(mode==='target'){const f=(await chrome.webNavigation.getAllFrames({tabId:fixtureTarget.id})).find(f=>f.frameId===0);q.sourceIdentity={...q.sourceIdentity,tabId:fixtureTarget.id,documentId:f.documentId};q.targetTabId=fixtureTarget.id;q.targetOrigin=q.sourceOrigin;}
    if(mode==='capture')q.controlLease={id:'fixture-lease',generation:1};
    fixtureFrames.length=0;await receive(q);const r=fixtureFrames.find(f=>f.type==='credentialScopeResult');if(!r)throw Error('fixture proof unavailable');
    const stored=await chrome.storage.local.get(MechanizeProtectionScopes.KEY),receipt=(await chrome.storage.session.get('receipt:fixture-retained'))['receipt:fixture-retained'];
    return {ready:r.ready,reason:r.reason,retired:stored[MechanizeProtectionScopes.KEY].records[0].retired,unknownRetained:unknownAttempts.has('fixture-retained')&&receipt?.dispatchState==='unknown',originalStillProtected:protectionScopes.protects(q.sourceOrigin+'/source',fixtureBase.sourceIdentity),forbidden:fixtureForbidden};
   };`;
  await writeFile(join(extension,'worker.js'),boot+'\n'+source+'\n'+probe);
  context=await chromium.launchPersistentContext(join(directory,'profile'),{executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,ignoreHTTPSErrors:true,ignoreDefaultArgs:['--disable-extensions'],args:['--enable-unsafe-extension-debugging']});
  const page=await context.newPage();await page.goto(origin+'/source');const target=await context.newPage();await target.goto(origin+'/target');
  const cdp=await context.browser().newBrowserCDPSession(),next=context.waitForEvent('serviceworker',{timeout:10000});await cdp.send('Extensions.loadUnpacked',{path:extension});const worker=await next;
  await worker.evaluate(async()=>{for(let i=0;i<200&&!globalThis.fixtureReady;i++)await new Promise(r=>setTimeout(r,10));await new Promise(r=>setTimeout(r,50));});
  assert.equal((await worker.evaluate(origin=>fixtureInit(origin),origin)).captured,true);
  const waitState=async predicate=>{for(let i=0;i<100;i++){const state=await worker.evaluate(()=>fixtureState());if(predicate(state))return state;await new Promise(r=>setTimeout(r,20));}throw Error('fixture navigation metadata did not settle');};
  const provisional=page.goto(origin+'/hold',{waitUntil:'commit',timeout:15000}).catch(()=>{});await pendingRequest;
  await waitState(s=>s.loading&&s.original);const old=await worker.evaluate(()=>fixtureProof('absent'));assert.equal(old.ready,false);assert.equal(old.reason,'scopeSourcePresent');assert.equal(old.retired,false);
  await page.goto(origin+'/slow-source',{waitUntil:'commit'});await provisional;await waitState(s=>s.loading&&!s.original&&s.activeRoot);
  const absent=await worker.evaluate(()=>fixtureProof('absent'));assert.equal(absent.ready,true);assert.equal(absent.retired,false);
  const capture=await worker.evaluate(()=>fixtureProof('capture'));assert.equal(capture.ready,false);assert.equal(capture.reason,'scopeInventoryUnavailable');
  await target.goto(origin+'/slow-target',{waitUntil:'commit'});const denied=await worker.evaluate(()=>fixtureProof('target'));assert.equal(denied.ready,false);assert.equal(denied.reason,'scopeInventoryUnavailable');
  const retired=await worker.evaluate(()=>fixtureProof('retire'));assert.equal(retired.ready,true);assert.equal(retired.retired,true);
  // The same login route in a different tab remains private after retirement;
  // a public route on the same origin is independently available.
  await target.goto(origin+'/source');const reopened=await worker.evaluate(()=>fixtureProof('target'));assert.equal(reopened.ready,false);assert.equal(reopened.reason,'scopeTargetProtected');
  await target.goto(origin+'/public');const publicTarget=await worker.evaluate(()=>fixtureProof('target'));assert.equal(publicTarget.ready,true);
  for(const result of [old,absent,capture,denied,retired,reopened,publicTarget]){assert.equal(result.unknownRetained,true);assert.equal(result.originalStillProtected,true);assert.equal(result.forbidden,0);assert.ok(!JSON.stringify(result).includes('CANARY'));}
 }finally{await context?.close();for(const response of heldResponses)response.destroy();server?.closeAllConnections();if(server)await new Promise(r=>server.close(r));await rm(directory,{recursive:true,force:true});}
});
