// Disposable real Chrome APIs/content/production worker. Native signature and
// Datly snapshot transport are fixture adapters here and are tested in Go.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {createServer} from 'node:http';
import {mkdtemp,cp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

test('real Chrome reconnect keeps ordinary tabs and original journal while requiring exact source absence',{timeout:60000},async()=>{
 const directory=await mkdtemp(join(tmpdir(),'mechanize-reconnect-current-'));let context,server;
 try{
  server=createServer((req,res)=>{if(req.url==='/broken-child'){req.socket.destroy();return;}res.setHeader('content-type','text/html');res.end('<!doctype html><button id="public">Public fixture</button><aside id="clock"></aside><script>window.inputs=0;document.querySelector("button").onclick=()=>window.inputs++;setInterval(()=>document.querySelector("aside").textContent=String(Date.now()),20)</script>');});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
  const extension=join(directory,'extension');await cp(new URL('../../../extension/chrome',import.meta.url),extension,{recursive:true,filter:p=>!p.includes('/test')&&!p.includes('/node_modules')});
  const manifest=JSON.parse(await readFile(join(extension,'manifest.json'),'utf8'));manifest.host_permissions=[origin+'/*'];await writeFile(join(extension,'manifest.json'),JSON.stringify(manifest));
  const source=await readFile(join(extension,'worker.js'),'utf8');
  const boot=`
   const fixtureFrames=[];let fixtureRows=[],fixtureOriginal;
   chrome.runtime.connectNative=()=>({onMessage:{addListener(){}},onDisconnect:{addListener(){}},disconnect(){},postMessage:frame=>{
    fixtureFrames.push(frame);
    if(frame.type==='reconnectBindings')void(async()=>{const hash=async v=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(v)))),b=>b.toString(16).padStart(2,'0')).join('');await receive({type:'reconnectBindingsResult',requestId:frame.requestId,pendingDigest:await hash(frame.pending),bindingsDigest:await hash(fixtureRows),total:fixtureRows.length,offset:0,nextOffset:fixtureRows.length,bindings:fixtureRows});})();
    if(frame.type==='reconnectBindingsDone'&&frame.complete)queueMicrotask(()=>receive({type:'reconnectBindingsCommitReady',requestId:frame.requestId,complete:true}));
   }});
   const seeded=chrome.storage.local.set({enrollment:{profileChannel:'fixture',browserInstance:'isolated',origins:[${JSON.stringify(origin)}]}});const get=chrome.storage.local.get.bind(chrome.storage.local);chrome.storage.local.get=async(...args)=>{await seeded;return get(...args);};
  `;
  const probe=`
   globalThis.fixtureReady=true;
   const fixtureChromeFrames=chrome.webNavigation.getAllFrames.bind(chrome.webNavigation);let fixtureInactiveChild=null;
   chrome.webNavigation.getAllFrames=async query=>(await fixtureChromeFrames(query))?.map(f=>fixtureInactiveChild&&f.documentId===fixtureInactiveChild.id?{...f,documentLifecycle:fixtureInactiveChild.lifecycle,...(fixtureInactiveChild.type?{frameType:fixtureInactiveChild.type}:{}),...(fixtureInactiveChild.type==='outermost_frame'?{parentFrameId:-1,parentDocumentId:undefined}:{})}:f);
   globalThis.fixtureDormantChild=async(lifecycle,type)=>{
    const enrollment=await config(),tabs=await chrome.tabs.query({url:enrollment.origins[0]+'/*'}),frames=await fixtureChromeFrames({tabId:tabs[0].id}),child=frames.find(f=>f.frameId!==0&&f.url.startsWith(enrollment.origins[0]));
    if(!child)return {identified:false};fixtureInactiveChild={id:child.documentId,lifecycle,type};
    const before=await inventory(enrollment);return {identified:!!child.documentId,parentKnown:frames.some(f=>f.frameId===child.parentFrameId),eligible:before.documents.some(d=>d.documentId===child.documentId)};
   };
   globalThis.fixtureActivateChild=async()=>{const id=fixtureInactiveChild?.id;fixtureInactiveChild=null;const current=await inventory(await config());return {sameDocument:current.documents.some(d=>d.documentId===id),bound:documents.has(current.documents.find(d=>d.documentId===id)?.tabId+':'+id),held:documentControlLeases.has(current.documents.find(d=>d.documentId===id)?.tabId+':'+id)};};

   globalThis.fixtureCensusSummary=async()=>{
    const enrollment=await config(),tabs=await chrome.tabs.query({url:enrollment.origins[0]+'/*'}),frames=await chrome.webNavigation.getAllFrames({tabId:tabs[0].id});
    const metadata={activeRoot:frames.some(f=>f.frameId===0&&f.documentLifecycle==='active'),opaqueActiveChild:frames.some(f=>f.frameId!==0&&f.documentLifecycle==='active'&&new URL(f.url).protocol==='about:'),failedChildren:frames.filter(f=>f.frameId!==0&&f.errorOccurred===true).length,failedChildrenKnown:frames.filter(f=>f.frameId!==0&&f.errorOccurred===true).every(f=>typeof f.documentId==='string'&&f.documentId.length>0)};
    return metadata;
   };
   const fixtureGrant={brokerEpoch:'original-broker',channelEpoch:'original-channel',scopeHash:'a'.repeat(64),trustScope:'desktop',scopeQualified:true,profileQualified:false,leaseRequired:true,mutationFingerprintVersion:2};
   globalThis.fixtureSeed=async origin=>{
    const tab=(await chrome.tabs.query({url:origin+'/*'}))[0],frame=(await chrome.webNavigation.getAllFrames({tabId:tab.id})).find(f=>f.frameId===0);
    fixtureOriginal={profileChannel:'fixture',browserInstance:'isolated',tabId:tab.id,frameId:0,documentId:frame.documentId,documentGeneration:1};
    fixtureRows=[{identity:fixtureOriginal,fence:reconnectFence(fixtureGrant),attemptId:'b'.repeat(64),fingerprintSHA256:'c'.repeat(64),dispatchState:'unknown'}];
    const pending={version:1,phase:'pending',nonce:'d'.repeat(64),oldFence:reconnectFence(fixtureGrant),newFence:{brokerEpoch:'interrupted-broker',channelEpoch:'interrupted-channel',scopeHash:fixtureGrant.scopeHash},history:[]};
    await chrome.storage.local.set({lastGrant:fixtureGrant,mechanizeReconnect:pending});return true;
   };
   let fixtureLargeOriginal;
   globalThis.fixtureSeedLarge=async origin=>{
    await fixtureSeed(origin);fixtureRows=[];
    const base=reconnectFence(fixtureGrant),history=Array.from({length:36},(_,i)=>({nonce:(i+100).toString(16).padStart(64,'0'),oldFence:{...base,brokerEpoch:'history-'+i,channelEpoch:'history-'+i},newFence:i===35?base:{...base,brokerEpoch:'history-'+(i+1),channelEpoch:'history-'+(i+1)},executors:i===0?[]:Array.from({length:24},(_,n)=>({identity:{...fixtureOriginal,tabId:n+20,documentId:'synthetic-retired-'+n},receiptCount:3,receiptRevision:3}))}));
    const original={version:1,phase:'pending',nonce:'c'.repeat(64),oldFence:history[0].oldFence,newFence:{...base,brokerEpoch:'abandoned-first',channelEpoch:'abandoned-first'},history:[]};
    const journal={version:2,phase:'pending',nonce:'d'.repeat(64),oldFence:base,newFence:{...base,brokerEpoch:'abandoned-next',channelEpoch:'abandoned-next'},history,recovery:{kind:'emptySetupDocuments',originalPending:original}};
    await chrome.storage.local.set({mechanizeReconnect:journal});fixtureLargeOriginal=JSON.stringify((await chrome.storage.local.get('mechanizeReconnect')).mechanizeReconnect);return new TextEncoder().encode(fixtureLargeOriginal).length;
   };
   globalThis.fixtureArchiveSummary=async()=>{
    const journal=(await chrome.storage.local.get('mechanizeReconnect')).mechanizeReconnect,ref=journal.audit;
    const archived=ref&&(await chrome.storage.local.get(reconnectAuditPrefix+ref.digest))[reconnectAuditPrefix+ref.digest];
    return {archived:!!ref,preserved:archived?.journalJSON===fixtureLargeOriginal,hashMatches:!!ref&&await reconnectPendingDigest(archived?.journalJSON||'')===ref.digest,historyCount:journal.history.length+(archived?JSON.parse(archived.journalJSON).history.length:0)};
   };
   globalThis.fixtureRecover=async label=>{
    closeNativeConnection();await connectNativeOnce();fixtureFrames.length=0;
    const before=JSON.stringify((await chrome.storage.local.get('mechanizeReconnect')).mechanizeReconnect);
    await receive({type:'processQualified',brokerEpoch:label,channelEpoch:label,scopeHash:'a'.repeat(64),trustScope:'desktop',scopeQualified:true,profileQualified:false,executorQualified:false,fixtureOnly:false,executorChallenge:label,mutationFingerprintVersion:2,reconnectBindingsVersion:1});
    const journal=(await chrome.storage.local.get('mechanizeReconnect')).mechanizeReconnect;
    await verifyReconnectArchives(journal);
    const audit=journal.audit&&(await chrome.storage.local.get(reconnectAuditPrefix+journal.audit.digest))[reconnectAuditPrefix+journal.audit.digest];
    return {connected:Boolean(port),attention:fixtureFrames.filter(f=>f.type==='attention').map(f=>f.error?.code),prepared:fixtureFrames.some(f=>f.type==='executorPrepared'),phase:reconnectDiagnosticPhase,reason:reconnectDiagnosticReason,inventoryReason:reconnectInventoryReason,originalRetained:audit?audit.journalJSON===before:JSON.stringify(reconnectOriginalPending(journal.recovery)||journal)===before,adopted:journal.phase==='adopted',generation:journal.history.at(-1)?.executors[0]?.identity.documentGeneration||0};
   };
  `;
  await writeFile(join(extension,'worker.js'),boot+'\n'+source+'\n'+probe);
  context=await chromium.launchPersistentContext(join(directory,'profile'),{executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,ignoreDefaultArgs:['--disable-extensions'],args:['--enable-unsafe-extension-debugging']});
  const page=await context.newPage();await page.goto(origin+'/original');for(const p of context.pages())if(p!==page)await p.close();
  const cdp=await context.browser().newBrowserCDPSession(),next=context.waitForEvent('serviceworker',{timeout:10000});await cdp.send('Extensions.loadUnpacked',{path:extension});const worker=await next;
  await worker.evaluate(async()=>{for(let i=0;i<200&&!globalThis.fixtureReady;i++)await new Promise(r=>setTimeout(r,10));});
  const management=await context.newPage();await management.goto('chrome://extensions/');
  const missing=await worker.evaluate(async()=>{const tabs=await chrome.tabs.query({});return tabs.some(t=>typeof t.url!=='string'&&t.status==='complete');});assert.equal(missing,true,'fixture must reproduce omitted Chrome-internal tab URL');
  assert.equal(await worker.evaluate(origin=>fixtureSeed(origin),origin),true);
  const retained=await worker.evaluate(()=>fixtureRecover('first-recovery'));assert.equal(retained.prepared,false);assert.equal(retained.originalRetained,true);assert.equal(retained.reason,'unknownReceipts',JSON.stringify(retained));
  await page.goto(origin+'/successor');const success=await worker.evaluate(()=>fixtureRecover('second-recovery'));
  assert.equal(success.prepared,true,JSON.stringify(success));assert.equal(success.originalRetained,true);assert.equal(success.adopted,true);assert.ok(success.generation>=1);
  assert.equal(await page.evaluate(()=>window.inputs),0);assert.equal(context.pages().length,2);
  // A complete active about:blank child remains visible to the source census,
  // but never becomes an eligible executable document or an input target.
  await worker.evaluate(origin=>fixtureSeed(origin),origin);
  await page.goto(origin+'/opaque-successor');
  await page.evaluate(()=>new Promise(resolve=>{const iframe=document.createElement('iframe');iframe.onload=resolve;document.body.append(iframe);}));
  const embedded=await worker.evaluate(()=>fixtureCensusSummary());
  assert.deepEqual(embedded,{activeRoot:true,opaqueActiveChild:true,failedChildren:0,failedChildrenKnown:true});
  const withChild=await worker.evaluate(()=>fixtureRecover('child-census'));
  assert.equal(withChild.prepared,true,JSON.stringify(withChild));assert.equal(withChild.originalRetained,true);
  assert.equal(await page.evaluate(()=>window.inputs),0);
  // Lifecycle-only fixture override on independently identified real Chrome
  // child metadata. Headless Chrome does not deterministically prerender WebUI.
  // Production worker, real renderer, document IDs and parent tree stay intact.
  await worker.evaluate(origin=>fixtureSeed(origin),origin);await page.goto(origin+'/dormant-successor');
  await page.evaluate(()=>new Promise(resolve=>{const iframe=document.createElement('iframe');iframe.onload=resolve;iframe.src='/public-child';document.body.append(iframe);}));
  const dormant=await worker.evaluate(()=>fixtureDormantChild('prerender'));assert.deepEqual(dormant,{identified:true,parentKnown:true,eligible:false});
  const withDormant=await worker.evaluate(()=>fixtureRecover('prerender-child-census'));assert.equal(withDormant.prepared,true,JSON.stringify(withDormant));assert.equal(withDormant.originalRetained,true);assert.equal(await page.evaluate(()=>window.inputs),0);
  const reactivated=await worker.evaluate(()=>fixtureActivateChild());assert.deepEqual(reactivated,{sameDocument:true,bound:false,held:false});
  await worker.evaluate(origin=>fixtureSeed(origin),origin);await page.goto(origin+'/fenced-successor');
  await page.evaluate(()=>new Promise(resolve=>{const iframe=document.createElement('iframe');iframe.onload=resolve;iframe.src='/public-child';document.body.append(iframe);}));
  const fenced=await worker.evaluate(()=>fixtureDormantChild('active','fenced_frame'));assert.deepEqual(fenced,{identified:true,parentKnown:true,eligible:false});
  const withFenced=await worker.evaluate(()=>fixtureRecover('fenced-child-census'));assert.equal(withFenced.prepared,true,JSON.stringify(withFenced));assert.equal(withFenced.originalRetained,true);assert.equal(await page.evaluate(()=>window.inputs),0);await worker.evaluate(()=>fixtureActivateChild());
  // An independently identified real nested subtree is represented as a
  // prerender forest by a metadata-only override; no identity is fabricated.
  await worker.evaluate(origin=>fixtureSeed(origin),origin);await page.goto(origin+'/forest-successor');
  await page.evaluate(()=>new Promise(resolve=>{const iframe=document.createElement('iframe');iframe.onload=resolve;iframe.src='/public-child';document.body.append(iframe);}));
  const childPage=page.frames().find(f=>f.parentFrame()===page.mainFrame());await childPage.evaluate(()=>new Promise(resolve=>{const iframe=document.createElement('iframe');iframe.onload=resolve;iframe.src='/public-nested';document.body.append(iframe);}));
  const forest=await worker.evaluate(()=>fixtureDormantChild('prerender','outermost_frame'));assert.deepEqual(forest,{identified:true,parentKnown:true,eligible:false});
  const withForest=await worker.evaluate(()=>fixtureRecover('inactive-forest-census'));assert.equal(withForest.prepared,true,JSON.stringify(withForest));assert.equal(withForest.originalRetained,true);assert.equal(await page.evaluate(()=>window.inputs),0);
  const forestActivated=await worker.evaluate(()=>fixtureActivateChild());assert.deepEqual(forestActivated,{sameDocument:true,bound:false,held:false});
  await worker.evaluate(origin=>fixtureSeed(origin),origin);await page.goto(origin+'/error-successor');
  await page.evaluate(()=>new Promise(resolve=>{const iframe=document.createElement('iframe');iframe.onload=resolve;iframe.src='/broken-child';document.body.append(iframe);}));
  const failed=await worker.evaluate(()=>fixtureCensusSummary());assert.ok(failed.failedChildren>0);assert.equal(failed.failedChildrenKnown,true);
  const withError=await worker.evaluate(()=>fixtureRecover('failed-child-census'));
  assert.equal(withError.prepared,true,JSON.stringify(withError));assert.equal(withError.originalRetained,true);assert.equal(await page.evaluate(()=>window.inputs),0);

  await page.goto(origin+'/large-history-successor');const predecessorBytes=await worker.evaluate(origin=>fixtureSeedLarge(origin),origin);assert.ok(predecessorBytes>128*1024&&predecessorBytes<256*1024);
  const large=await worker.evaluate(()=>fixtureRecover('large-archive-recovery'));assert.equal(large.prepared,true,JSON.stringify(large));assert.equal(large.originalRetained,true);
  assert.deepEqual(await worker.evaluate(()=>fixtureArchiveSummary()),{archived:true,preserved:true,hashMatches:true,historyCount:37});assert.equal(await page.evaluate(()=>window.inputs),0);

 }finally{await context?.close();server?.closeAllConnections();if(server)await new Promise(r=>server.close(r));await rm(directory,{recursive:true,force:true});}
});
