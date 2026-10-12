import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {mkdtemp,cp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

// The native host is synthetic; Chrome's worker lifecycle, storage, alarms and
// permission API are real. No user profile or installed native host is touched.
test('real Chrome reconnects offline native transport and restarts its worker without Options or permission prompts',{timeout:60000},async()=>{
 const directory=await mkdtemp(join(tmpdir(),'mechanize-connection-'));
 let context;
 try{
  const extension=join(directory,'extension');await cp(new URL('../../../extension/chrome',import.meta.url),extension,{recursive:true,filter:p=>!p.includes('/test')&&!p.includes('/node_modules')});
  const manifest=JSON.parse(await readFile(join(extension,'manifest.json'),'utf8'));manifest.host_permissions=['https://fixture.example.test/*'];await writeFile(join(extension,'manifest.json'),JSON.stringify(manifest));
  const source=await readFile(join(extension,'worker.js'),'utf8');
  const adapter=`
   let fixtureOnline=false,fixtureEpoch=1,fixtureCalls=0,fixturePrompts=0,fixtureActive=0,fixturePeak=0;
   const fixturePorts=[],fixtureFrames=[];
   chrome.permissions.request=async()=>{fixturePrompts++;throw Error('Unexpected permission request');};
   const originalGet=chrome.storage.local.get.bind(chrome.storage.local);
   const seeded=(async()=>{if(!(await originalGet('enrollment')).enrollment)await chrome.storage.local.set({enrollment:{profileChannel:'fixture',browserInstance:'isolated',origins:['https://fixture.example.test']}});})();
   chrome.storage.local.get=async(...args)=>{await seeded;return originalGet(...args);};
   chrome.runtime.connectNative=()=>{
    fixtureCalls++;const listeners=[],disconnects=[];let closed=false;fixtureActive++;fixturePeak=Math.max(fixturePeak,fixtureActive);
    const close=()=>{if(closed)return;closed=true;fixtureActive--;for(const f of disconnects)f();};
    const p={onMessage:{addListener:f=>listeners.push(f)},onDisconnect:{addListener:f=>disconnects.push(f)},disconnect:close,postMessage:frame=>{
     fixtureFrames.push(frame);
     if(frame.type==='hello')setTimeout(()=>{if(closed)return;if(!fixtureOnline){close();return;}for(const f of listeners)f({type:'processQualified',brokerEpoch:'broker-'+fixtureEpoch,channelEpoch:'channel-'+fixtureEpoch,scopeHash:'a'.repeat(64),profileQualified:true,scopeQualified:true,fixtureOnly:false,executorQualified:false,executorChallenge:'challenge-'+fixtureEpoch,mutationFingerprintVersion:2});},10);
    }};fixturePorts.push(p);return p;
   };
   globalThis.fixtureNextEpoch=()=>{fixtureEpoch++;};globalThis.fixtureSetOnline=value=>{fixtureOnline=value;if(!value)for(const p of fixturePorts)p.disconnect();};
  `;
  const inspect=`
   globalThis.fixtureReady=true;
   globalThis.fixtureState=async()=>({calls:fixtureCalls,prompts:fixturePrompts,active:fixtureActive,peak:fixturePeak,connected:Boolean(port),qualified:Boolean(grant),retry:connectionLifecycle.status(),alarm:Boolean(await chrome.alarms.get('mechanize-native-reconnect')),helloCount:fixtureFrames.filter(f=>f.type==='hello').length,emptyHellos:fixtureFrames.filter(f=>f.type==='hello').every(f=>Array.isArray(f.documents)&&f.documents.length===0),prepared:fixtureFrames.filter(f=>f.type==='executorPrepared').length,types:[...new Set(fixtureFrames.map(f=>f.type))],enabled:(await chrome.storage.local.get('connectionEnabled')).connectionEnabled!==false});
  `;
  await writeFile(join(extension,'worker.js'),adapter+'\n'+source+'\n'+inspect);
  context=await chromium.launchPersistentContext(join(directory,'profile'),{executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,ignoreDefaultArgs:['--disable-extensions'],args:['--enable-unsafe-extension-debugging']});
  const cdp=await context.browser().newBrowserCDPSession();
  const load=async()=>{const next=context.waitForEvent('serviceworker',{timeout:10000});await cdp.send('Extensions.loadUnpacked',{path:extension});const worker=await next;await worker.evaluate(async()=>{for(let i=0;i<200&&!globalThis.fixtureReady;i++)await new Promise(r=>setTimeout(r,10));});return worker;};
  let worker=await load();
  const wait=async predicate=>{const end=Date.now()+12000;while(Date.now()<end){const s=await worker.evaluate(()=>fixtureState());if(predicate(s))return s;await new Promise(r=>setTimeout(r,50));}throw Error('Bounded connection condition not reached: '+JSON.stringify(await worker.evaluate(()=>fixtureState())));};
  let state=await wait(s=>s.calls>=2&&s.retry.phase==='retry');assert.equal(state.prompts,0);assert.equal(state.alarm,true);assert.equal(state.qualified,false);
  // Host has been absent for longer than the old single one-second retry.
  await worker.evaluate(()=>fixtureSetOnline(true));state=await wait(s=>s.qualified);assert.ok(state.calls>=3);assert.equal(state.peak,1);assert.equal(state.emptyHellos,true);assert.equal(state.alarm,false);
  await worker.evaluate(()=>{fixtureNextEpoch();fixtureSetOnline(false);});state=await wait(s=>s.calls>=4&&s.retry.phase==='retry');await worker.evaluate(()=>fixtureSetOnline(true));state=await wait(s=>s.qualified&&s.prepared>=2);assert.equal(state.peak,1);assert.equal(state.prompts,0);
  // Stop and recreate the actual MV3 worker with storage retained. No Options
  // document or connect message participates in either startup.
  await worker.evaluate(()=>fixtureSetOnline(false));await wait(s=>s.retry.phase==='retry');worker=await load();state=await wait(s=>s.alarm&&s.retry.phase==='retry');assert.equal(state.prompts,0);await worker.evaluate(()=>fixtureSetOnline(true));state=await wait(s=>s.qualified);assert.equal(state.emptyHellos,true);assert.equal(state.peak,1);
  await worker.evaluate(()=>chrome.storage.local.set({connectionEnabled:false}));state=await wait(s=>!s.enabled&&!s.connected&&!s.retry.retryScheduled);const calls=state.calls;await new Promise(r=>setTimeout(r,1100));assert.equal((await worker.evaluate(()=>fixtureState())).calls,calls);
  await worker.evaluate(()=>chrome.storage.local.set({connectionEnabled:true}));state=await wait(s=>s.qualified);assert.equal(state.prompts,0);assert.equal(state.peak,1);assert.equal(state.emptyHellos,true);assert.ok(state.types.every(type=>['hello','executorPrepared','attention','documents','controllerSync'].includes(type)));assert.ok(context.pages().every(page=>!page.url().includes('options.html')));
 }finally{await context?.close();await rm(directory,{recursive:true,force:true});}
});
