// Disposable real-Chrome extension fixture. The production worker/content run
// unchanged; native messaging uses a test pipe, and enrollment is seeded into
// real isolated extension storage before its initial read. No installed
// native host, user profile, user storage, or external website is accessed.
import {chromium} from 'playwright-core';
import {createServer} from 'node:https';
import {mkdtemp,readFile,writeFile,cp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createInterface} from 'node:readline';
let activationRepliesDropped=0;const visibilityFixture=process.env.MECHANIZE_VISIBILITY_UNKNOWN==='1';
const allWebsites=process.env.MECHANIZE_PRIVATE_MANUAL_ALL_WEBSITES==='1';
const diagnosticFixture=process.env.MECHANIZE_PRIVATE_DIAGNOSTIC_FIXTURE==='1';
const archived=process.env.MECHANIZE_PRIVATE_ARCHIVE_FIXTURE==='1',generationRace=process.env.MECHANIZE_PRIVATE_GENERATION_RACE||'';
const phase=value=>process.stderr.write('fixture-phase:'+value+'\n');
phase('starting');
const directory=await mkdtemp(join(tmpdir(),'mechanize-private-handoff-'));
const cert=join(directory,'cert.pem'),key=join(directory,'key.pem');
if(spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'}).status!==0)throw Error('Fixture TLS unavailable');
const html=`<!doctype html><title>Private handoff fixture</title><form method="post"><label>User<input autocomplete="username"></label><label>Password<input type="password" autocomplete="current-password"></label><button>Login</button></form><script>window.fixtureSubmits=0;document.querySelector('form').onsubmit=e=>{e.preventDefault();window.fixtureSubmits++;document.body.innerHTML='<h1>fixture-user-canary</h1><h2>Fixture records</h2><button id="ordinary">Ordinary action</button><p id="result">Ready</p>';window.ordinaryClicks=0;document.querySelector('#ordinary').onclick=()=>{window.ordinaryClicks++;document.querySelector('#result').textContent='Applied';};};</script>`;
const publicHTML='<title>Public handoff fixture</title><h1>fixture-user-canary</h1><h2>Fixture records</h2><p>fixture-password-canary</p><script>window.fixtureSubmits=0;</script>';
const server=createServer({key:await readFile(key),cert:await readFile(cert)},(request,response)=>{response.setHeader('content-type','text/html');response.end(request.url==='/public'?publicHTML:diagnosticFixture?html.replace('<button>Login</button>','<button>Login</button><button>Alternative</button>'):html);});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin=`https://127.0.0.1:${server.address().port}`;
const extension=join(directory,'extension');await cp(new URL('../../../extension/chrome',import.meta.url),extension,{recursive:true,filter:source=>!source.includes('/node_modules')&&!source.includes('/test')});
const manifest=JSON.parse(await readFile(join(extension,'manifest.json'),'utf8'));manifest.name='Mechanize isolated privacy handoff';manifest.host_permissions=allWebsites?['http://*/*','https://*/*']:[origin+'/*'];manifest.background={service_worker:'worker.js',type:'module'};await writeFile(join(extension,'manifest.json'),JSON.stringify(manifest));
const boot=`const listeners=[],disconnected=[];globalThis.fixtureOutbound=[];globalThis.fixtureNativeCalls=0;globalThis.fixtureInbound=frame=>{for(const f of listeners)f(frame);};const nativeAdapter=()=>{fixtureNativeCalls++;return ({postMessage:value=>fixtureOutbound.push(value),onMessage:{addListener:f=>listeners.push(f)},onDisconnect:{addListener:f=>disconnected.push(f)},disconnect:()=>{for(const f of disconnected)f();}});};chrome.runtime.connectNative=nativeAdapter;if(chrome.runtime.connectNative!==nativeAdapter)throw Error('Fixture adapter unavailable');const fixtureStorageReady=chrome.storage.local.set({enrollment:{profileChannel:'fixture',browserInstance:'isolated',origins:${JSON.stringify(allWebsites?[]:[origin])},allWebsites:${allWebsites}},...(${archived}?{mechanizeProtectedOrigins:[${JSON.stringify(origin)}]}:{})});const fixtureStorageGet=chrome.storage.local.get.bind(chrome.storage.local);chrome.storage.local.get=async(...args)=>{await fixtureStorageReady;return fixtureStorageGet(...args);};`;
const currentContent=await readFile(join(extension,'content.js'),'utf8'),currentSecureInput=await readFile(join(extension,'secure-input.js'),'utf8');
if(diagnosticFixture){
 // Preserve the pre-diagnostic executor's strict request/reply contract. It is
 // actually injected first, then the helper and content files are reinjected.
 const oldContent=currentContent.replace("if(diagnostics)keys.push('diagnostics');",'').replace("...(diagnostics?{inspectionReason}:{})",'').replace('globalThis.__mechanizeExecutor = true;','globalThis.__mechanizeExecutor = true;globalThis.__fixtureLegacyExecutor=true;');
 await writeFile(join(extension,'content.js'),oldContent);
 await writeFile(join(extension,'secure-input.js'),currentSecureInput.replace('inspect,inspectionReason,','inspect,'));
}
const workerSource=await readFile(join(extension,'worker.js'),'utf8');
await writeFile(join(extension,'worker.js'),boot+'\n'+workerSource+'\nglobalThis.fixtureBoot=true;globalThis.fixtureState=()=>({attention:connectionAttention,phase:reconnectDiagnosticPhase,reason:reconnectDiagnosticReason,nativeCalls:fixtureNativeCalls,portPresent:Boolean(port),privateMaterialPresent:privateRedactions.length>0});');
phase('launch');
const context=await chromium.launchPersistentContext(join(directory,'profile'),{executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,ignoreHTTPSErrors:true,ignoreDefaultArgs:['--disable-extensions'],args:['--enable-unsafe-extension-debugging']});
let finished=false,polling=false,restarting=false,retainedSubmits=0,openedLogin=false,driftInjected=false,manualExtra=null,privacyCommitRefusal=false,ordinaryAcquireDrifts=0;const counts={acquire:0,retire:0,validate:0,privateSubmit:0,privateFill:0,activation:0};
const emit=frame=>process.stdout.write(JSON.stringify(frame)+'\n');
const finish=async()=>{if(finished)return;finished=true;clearInterval(timer);await context.close();await new Promise(resolve=>server.close(resolve));await rm(directory,{recursive:true,force:true});};
let timer;
try{
 phase('page');let page=await context.newPage();await page.goto(archived?'about:blank':origin);phase('page-ready');for(const other of context.pages())if(other!==page)await other.close();
 const cdp=await context.browser().newBrowserCDPSession();await cdp.send('Extensions.loadUnpacked',{path:extension});
 let worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker',{timeout:10000});phase('worker-ready');
 phase('worker-metadata');const diagnostic=await worker.evaluate(async()=>{for(let i=0;i<100&&!globalThis.fixtureBoot;i++)await new Promise(r=>setTimeout(r,10));await new Promise(r=>setTimeout(r,50));return globalThis.fixtureState?.()||{boot:false};});
 phase('ready');emit({type:'fixture.ready',diagnostic,origin,extensionOrigin:'chrome-extension://'+new URL(worker.url()).hostname+'/'});
 timer=setInterval(async()=>{if(polling||finished||restarting)return;polling=true;const pollingWorker=worker;try{const frames=await pollingWorker.evaluate(()=>globalThis.fixtureBoot===false?[{type:'fixture.failure',code:'workerBootUnavailable'}]:fixtureOutbound.splice(0));if(pollingWorker!==worker||restarting)return;for(const frame of frames){if(process.env.MECHANIZE_CLASSIFIED_PUBLIC_READ==='1'&&frame.type==='credentialScopeResult')phase('public-scope-'+JSON.stringify({ready:frame.ready,reason:frame.reason,proof:!!frame.publicDocument,target:!!frame.targetIdentity,route:!!frame.loginRouteSHA256}));if(visibilityFixture&&frame.type==='browser.activateTabResult'&&activationRepliesDropped++===0){phase('activation-result-lost');continue;}emit(frame);if(archived&&!openedLogin&&frame.type==='executorPrepared'){openedLogin=true;phase('archive-qualified');await page.goto(origin);phase('archived-login-opened');}}}catch{if(!finished&&!restarting&&pollingWorker===worker)emit({type:'fixture.failure',code:'workerUnavailable'});}finally{polling=false;}},5);
 createInterface({input:process.stdin}).on('line',async line=>{
  try{
   const frame=JSON.parse(line);
   if(frame.type==='fixture.stop'){await finish();process.exit(0);}
   if(frame.type==='fixture.publicReadSPA'){
    await page.evaluate(()=>{document.querySelector('form').hidden=true;history.pushState({},'', '/history');document.body.insertAdjacentHTML('beforeend','<section id="public-area"><h2>Fixture public records</h2><p id="public-result">Public ready</p><p id="public-canary">fixture-password-canary</p></section>');});
    emit({type:'fixture.state',...counts,submits:await page.evaluate(()=>window.fixtureSubmits||0)});return;
   }
   if(frame.type==='fixture.publicReadLogin'){
    await page.evaluate(()=>{document.querySelector('#public-area')?.remove();document.querySelector('form').hidden=false;history.pushState({},'', '/');});
    emit({type:'fixture.state',...counts,submits:await page.evaluate(()=>window.fixtureSubmits||0)});return;
   }
   if(frame.type==='fixture.independent'){manualExtra=await context.newPage();await manualExtra.goto(origin+'/public');emit({type:'fixture.state',...counts,submits:retainedSubmits+(await page.evaluate(()=>window.fixtureSubmits||0))});return;}
   if(frame.type==='fixture.freshLogin'){if(manualExtra){await manualExtra.close();manualExtra=null;}await page.goto(origin);const documentId=await worker.evaluate(async origin=>{const tabs=await chrome.tabs.query({url:origin+'/*'});if(tabs.length!==1)throw Error('fixture tab count');const frames=await chrome.webNavigation.getAllFrames({tabId:tabs[0].id});return frames.find(f=>f.frameId===0).documentId;},origin);emit({type:'fixture.state',...counts,documentId,submits:retainedSubmits+(await page.evaluate(()=>window.fixtureSubmits||0))});return;}
   if(frame.type==='fixture.manualSameTab'){retainedSubmits+=await page.evaluate(()=>window.fixtureSubmits||0);await page.goto(origin+'/public');emit({type:'fixture.state',...counts,submits:retainedSubmits,manualTabOpen:!page.isClosed()});return;}
   if(frame.type==='fixture.manualReplacement'){phase('manual-replacement');
    retainedSubmits+=await page.evaluate(()=>window.fixtureSubmits||0);const previous=page;page=await context.newPage();await page.goto(origin+'/public');await previous.close();
    emit({type:'fixture.state',...counts,submits:retainedSubmits,manualTabOpen:!page.isClosed()});return;
   }
   if(frame.type==='fixture.restartWorker'){phase('worker-restart');
    restarting=true;const next=context.waitForEvent('serviceworker',{timeout:10000});next.catch(()=>{});await cdp.send('Extensions.loadUnpacked',{path:extension});worker=await next;
    const metadata=await worker.evaluate(async()=>{for(let i=0;i<200&&!globalThis.fixtureBoot;i++)await new Promise(r=>setTimeout(r,10));return fixtureState();});
    restarting=false;phase('worker-restarted');emit({type:'fixture.state',...counts,submits:retainedSubmits,privateMaterialPresent:metadata.privateMaterialPresent,manualTabOpen:!page.isClosed()});return;
   }
   if(frame.type==='fixture.manualDuplicate'){manualExtra=await context.newPage();await manualExtra.goto(origin+'/public');emit({type:'fixture.state',...counts,submits:retainedSubmits+(await page.evaluate(()=>window.fixtureSubmits||0))});return;}
   if(frame.type==='fixture.manualUnique'){if(manualExtra)await manualExtra.close();manualExtra=null;emit({type:'fixture.state',...counts,submits:retainedSubmits+(await page.evaluate(()=>window.fixtureSubmits||0))});return;}
   if(frame.type==='fixture.manualChallenge'){await page.evaluate(()=>{document.body.innerHTML='<p>Enter verification code</p>';});emit({type:'fixture.state',...counts,submits:retainedSubmits+(await page.evaluate(()=>window.fixtureSubmits||0))});return;}
   if(frame.type==='fixture.navigate'){
    retainedSubmits+=await page.evaluate(()=>window.fixtureSubmits||0);await page.goto(origin+'/public');
    emit({type:'fixture.state',...counts,submits:retainedSubmits+(await page.evaluate(()=>window.fixtureSubmits||0))});return;
   }
   if(frame.type==='fixture.commitRefusal'){retainedSubmits+=await page.evaluate(()=>window.fixtureSubmits||0);await page.goto(origin+'/public');privacyCommitRefusal=true;emit({type:'fixture.state',...counts,submits:retainedSubmits});return;}
   if(privacyCommitRefusal&&frame.type==='credentialPrivacyCommit'){privacyCommitRefusal=false;await page.evaluate(()=>{document.body.innerHTML='<p>Enter verification code</p>';});}
   if(frame.type==='fixture.recoverPrivacy'){await page.evaluate(html=>{document.body.innerHTML=html;},publicHTML);emit({type:'fixture.state',...counts,submits:retainedSubmits+(await page.evaluate(()=>window.fixtureSubmits||0))});return;}
   if(frame.type==='fixture.privacyChallenge'){await page.evaluate(()=>{document.body.innerHTML='<p>Enter verification code</p>';});emit({type:'fixture.state',...counts,submits:retainedSubmits+(await page.evaluate(()=>window.fixtureSubmits||0))});return;}
   if(frame.type==='fixture.blockedNavigation'){retainedSubmits+=await page.evaluate(()=>window.fixtureSubmits||0);await page.goto(origin+'/blocked');emit({type:'fixture.state',...counts,submits:retainedSubmits+(await page.evaluate(()=>window.fixtureSubmits||0))});return;}
   if(frame.type==='fixture.expire'){
    await page.evaluate(()=>{document.body.innerHTML='<form><input autocomplete="username"><input type="password"><button>Login</button></form>';});
    emit({type:'fixture.state',...counts,submits:retainedSubmits+(await page.evaluate(()=>window.fixtureSubmits||0))});return;
   }
   if(frame.type==='fixture.redactionState'){const safe=await worker.evaluate(()=>fixtureState());emit({type:'fixture.state',privateMaterialPresent:safe.privateMaterialPresent});return;}
   if(frame.type==='fixture.state'){emit({type:'fixture.state',...counts,ordinaryClicks:await page.evaluate(()=>window.ordinaryClicks||0),submits:retainedSubmits+(await page.evaluate(()=>window.fixtureSubmits||0))});return;}
   if(archived&&frame.type==='processQualified'){
    await worker.evaluate(async frame=>{
     const old={brokerEpoch:'archive-old-broker',channelEpoch:'archive-old-channel',scopeHash:frame.scopeHash,mutationFingerprintVersion:2,leaseRequired:true,trustScope:frame.trustScope,scopeQualified:true,profileQualified:frame.profileQualified};
     const fence=x=>({brokerEpoch:x.brokerEpoch,channelEpoch:x.channelEpoch,scopeHash:x.scopeHash}),history=[];
     for(let i=0;i<64;i++)history.push({nonce:(i+1).toString(16).padStart(64,'0'),oldFence:{...fence(old),brokerEpoch:'archive-'+i,channelEpoch:'archive-'+i},newFence:i===63?fence(old):{...fence(old),brokerEpoch:'archive-'+(i+1),channelEpoch:'archive-'+(i+1)},executors:[]});const tail=history.at(-1);
     await chrome.storage.local.set({lastGrant:old,mechanizeReconnect:{version:1,phase:'adopted',nonce:tail.nonce,oldFence:tail.oldFence,newFence:tail.newFence,history}});
    },frame);
   }
   if(process.env.MECHANIZE_ORDINARY_ACQUIRE_DRIFT==='2'&&frame.action==='executor.acquire'&&counts.privateSubmit===1&&ordinaryAcquireDrifts<2){ordinaryAcquireDrifts++;await page.evaluate(()=>document.body.append(document.createElement('aside')));}
   if(generationRace&&frame.action==='executor.acquire'&&(!driftInjected||generationRace==='always')){
    driftInjected=true;await page.evaluate(mode=>{
     document.body.append(document.createElement('aside'));
     if(mode==='replacement'){const input=document.querySelector('[autocomplete=username]');input.replaceWith(input.cloneNode(true));}
     if(mode==='route')document.querySelector('form').action='/changed';
     if(mode==='challenge')document.body.append(Object.assign(document.createElement('p'),{textContent:'Enter verification code'}));
     if(mode==='expired')document.body.innerHTML='<h1>Session expired</h1>';
    },generationRace);
   }
   if(diagnosticFixture&&frame.type==='credentialInspect'){
    await writeFile(join(extension,'content.js'),currentContent);await writeFile(join(extension,'secure-input.js'),currentSecureInput);
    const state=await worker.evaluate(async identity=>{const target={tabId:identity.tabId,documentIds:[identity.documentId]};await chrome.scripting.executeScript({target,world:'ISOLATED',files:['secure-input.js','content.js']});const result=await chrome.scripting.executeScript({target,world:'ISOLATED',func:()=>({legacy:globalThis.__fixtureLegacyExecutor===true,helper:typeof globalThis.MechanizeSecureInput?.inspectionReason==='function'})});return result[0].result;},frame.identity);
    if(!state.legacy||!state.helper)throw Error('Legacy diagnostic fixture unavailable');phase('legacy-executor-new-helper');
   }
   if(frame.type==='browser.activateTab')counts.activation++;
   if(frame.type==='credentialDelivery')counts.privateFill++;
   if(frame.type==='credentialSubmit')counts.privateSubmit++;
   if(frame.action==='executor.acquire')counts.acquire++;
   if(frame.action==='executor.retire')counts.retire++;
   if(frame.action==='executor.validate')counts.validate++;
   await worker.evaluate(frame=>fixtureInbound(frame),frame);
  }catch(error){const message=String(error?.message||'');const code=message.includes('ERR_BLOCKED_BY_CLIENT')?'fixtureReloadBlocked':message.includes('ERR_FILE_NOT_FOUND')?'fixtureReloadMissing':message.includes('Timeout')?'fixtureReloadTimeout':message.includes('closed')?'fixtureReloadClosed':message.includes('before initialization')?'fixtureBindingUnavailable':'fixtureExchangeUnavailable';phase(code);emit({type:'fixture.failure',code});}
 });
 process.stdin.on('end',()=>void finish());
}catch{await finish();throw Error('Isolated privacy fixture unavailable');}
