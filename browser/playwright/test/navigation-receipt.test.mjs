import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {chromium} from 'playwright-core';
import {PlaywrightEngine} from '../engine.mjs';
import fingerprint from '../fingerprint.cjs';
import {pageEvents} from '../relay.mjs';

// Disposable public fixture: no existing profile, user page, credential or input.
for(const mode of ['same-document','new-document'])test('navigation retains exact original receipt diagnosis: '+mode,{timeout:20000},async()=>{
 const browser=await chromium.launch({executablePath:process.env.MECHANIZE_FIXTURE_CHROMIUM||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
 try{
  const context=await browser.newContext(),page=await context.newPage();
  await page.route('https://fixture.test/**',route=>route.fulfill({contentType:'text/html',body:route.request().url().endsWith('/next')?'<h1>Next public document</h1>':'<a href="'+(mode==='new-document'?'/next':'#next')+'">Open records</a><p>Public fixture</p>'}));
  await page.goto('https://fixture.test');
  const scope=vm.createContext({URL,Date,TextEncoder,setTimeout,clearTimeout,crypto:globalThis.crypto});
  for(const module of ['protocol','fingerprint','cdp-transport','playwright-target','playwright-relay','playwright-worker'])vm.runInContext(await readFile(new URL('../../../extension/chrome/'+module+'.js',import.meta.url),'utf8'),scope);
  const events=new Set(),local={},session={},listeners=new Set(),pending=new Map(),failures=[];let cdp,worker,sequence=0,documentId='original-document',down=0,up=0,releaseAckAfterNavigation=false;let navigationObserved;const navigated=new Promise(resolve=>{navigationObserved=resolve;});
  const port={postMessage(message){if(message.type==='playwright.event'){for(const listener of listeners)listener({method:message.method,params:message.params});return;}pending.get(message.requestId)?.(message);pending.delete(message.requestId);}};
  const storage=values=>({setAccessLevel:async()=>{},get:async key=>key===null?structuredClone(values):{[key]:structuredClone(values[key])},set:async value=>Object.assign(values,structuredClone(value))});
  const api={storage:{local:storage(local),session:storage(session)},webNavigation:{getAllFrames:async()=>[{frameId:0,documentId,url:page.url()}]},debugger:{onEvent:{addListener:listener=>events.add(listener)},attach:async()=>{cdp=await context.newCDPSession(page);for(const method of pageEvents)cdp.on(method,params=>{if(method==='Page.frameNavigated'&&!params.frame.parentId){documentId='replacement-document';worker.invalidate(held=>held.identity.documentId==='original-document',true);navigationObserved();}for(const listener of events)listener({tabId:7},method,params);});},sendCommand:async(_target,method,params)=>{if(method==='Input.dispatchMouseEvent'&&params.type==='mousePressed')down++;if(method==='Input.dispatchMouseEvent'&&params.type==='mouseReleased')up++;const response=await cdp.send(method,params);if(mode==='new-document'&&method==='Input.dispatchMouseEvent'&&params.type==='mouseReleased'){await navigated;releaseAckAfterNavigation=true;}return response;}}};
  const identity={profileChannel:'fixture',browserInstance:'isolated',tabId:7,frameId:0,documentId,documentGeneration:1};
  worker=scope.MechanizePlaywrightWorker.create(api,{port:()=>port,receiptCurrent:()=>true,current:()=>documentId===identity.documentId,acquire:()=>{},release:()=>{},unknown:()=>{},redact:value=>value});
  const command={requestId:'navigate',action:'element.press',identity,brokerEpoch:'fixture',channelEpoch:'fixture',scopeHash:'a'.repeat(64),deadlineUnixMs:Date.now()+5000,locator:{strategy:'role',value:'link',name:'Open records',exact:true},attemptId:'navigation-attempt',controlLease:{id:'fixture-lease',generation:1},fingerprintVersion:2};command.fingerprintSHA256=(await fingerprint.mutationV2(command)).sha256;
  async function call(type,fields={}){const requestId='request-'+(++sequence);const response=new Promise(resolve=>pending.set(requestId,resolve));await worker.receive({type:'playwright.'+type,requestId,relayId:'navigation-relay',deadlineUnixMs:command.deadlineUnixMs,...fields},port);const reply=await response;if(reply.errorCode){failures.push({phase:type,code:reply.errorCode,state:reply.dispatchState,terminal:reply.result?.receipt?.dispatchState});throw Object.assign(Error('Closed fixture refusal'),{code:reply.errorCode,dispatchState:reply.dispatchState});}return reply.result;}
  const host={admit:async()=>({identity,origin:'https://fixture.test',brokerEpoch:'fixture',channelEpoch:'fixture',scopeHash:'a'.repeat(64),controlLease:command.controlLease,fingerprintSHA256:command.fingerprintSHA256,committed:true,privateQuarantined:false}),current:async()=>documentId===identity.documentId,openRelay:async()=>{await call('open',{command,origin:'https://fixture.test'});return{current:async()=>documentId===identity.documentId,onEvent:listener=>{listeners.add(listener);return()=>listeners.delete(listener)},send:(method,params)=>call('send',{method,params}),close:()=>call('close')};},commitIntent:async()=>true,persistReceipt:async receipt=>(await call('receipt',{dispatchState:receipt.dispatchState,effectState:receipt.effectState,...(receipt.errorCode?{errorCode:receipt.errorCode}:{}),...(receipt.inputSemantics?{inputSemantics:receipt.inputSemantics}:{})})).persisted,redact:async value=>value};
  const result=await new PlaywrightEngine(host).execute(command);
  const original=await worker.query({...command,requestId:'original-receipt-query'});
  assert.equal(down,1);assert.equal(up,1);
  if(mode==='same-document'){assert.equal(result.errorCode,undefined);assert.equal(original.dispatchState,'dispatched');}
  else{assert.equal(result.errorCode,undefined,JSON.stringify(failures));assert.equal(original.dispatchState,'dispatched');await page.waitForURL('https://fixture.test/next');assert.equal(documentId,'replacement-document');assert.equal(releaseAckAfterNavigation,true);}
  assert.equal(original.identity.documentId,identity.documentId);assert.equal(original.fingerprintSHA256,command.fingerprintSHA256);
  console.log(JSON.stringify({fixture:'inert-navigation',mode,down,up,releaseAckAfterNavigation,resultCode:result.errorCode||'none',receiptState:original.dispatchState,receiptCode:original.error?.code||'none',failures}));
 }finally{await browser.close();}
});
