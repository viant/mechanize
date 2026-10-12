import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {chromium} from 'playwright-core';
import {PlaywrightEngine} from '../engine.mjs';
import fingerprint from '../fingerprint.cjs';
import {pageEvents} from '../relay.mjs';

// Disposable synthetic page only; never attaches to an existing browser/profile.
test('textarea Unicode fill and trapped focus distinguish original relay denial from receipt masking',{timeout:30000},async()=>{
 const browser=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
 try {for(const trapped of [false,true]){
  const context=await browser.newContext(),page=await context.newPage();
  try {
   await page.route('https://fixture.test/**',route=>route.fulfill({contentType:'text/html',body:'<meta charset="utf-8"><button id="menu">Open choice</button><textarea data-testid="composer-input" placeholder="Type a message…"></textarea>'+(trapped?'<script>document.addEventListener("focusin",event=>{if(event.target.tagName==="TEXTAREA")document.querySelector("#menu").focus()})</script>':'')}));
   await page.goto('https://fixture.test');
   const scope=vm.createContext({URL,Date,TextEncoder,setTimeout,clearTimeout,crypto:globalThis.crypto});
   for(const module of ['protocol','fingerprint','cdp-transport','playwright-target','playwright-relay','playwright-worker'])vm.runInContext(await readFile(new URL('../../../extension/chrome/'+module+'.js',import.meta.url),'utf8'),scope);
   const events=new Set(),journal={},listeners=new Set(),pending=new Map(),errors=[];let cdp,inputs=0,seq=0;
   const port={postMessage(message){if(message.type==='playwright.event'){for(const fn of listeners)fn({method:message.method,params:message.params});return;}pending.get(message.requestId)?.(message);pending.delete(message.requestId);}};
   const api={storage:{local:{setAccessLevel:async()=>{},get:async key=>({[key]:journal[key]}),set:async values=>Object.assign(journal,structuredClone(values))},session:{get:async key=>key===null?{...journal}:{[key]:journal[key]},set:async values=>Object.assign(journal,structuredClone(values))}},webNavigation:{getAllFrames:async()=>[{frameId:0,documentId:'fixture-document',url:page.url()}]},debugger:{onEvent:{addListener:fn=>events.add(fn)},attach:async()=>{cdp=await context.newCDPSession(page);for(const method of pageEvents)cdp.on(method,params=>{for(const fn of events)fn({tabId:7},method,params);});},sendCommand:async(_target,method,params)=>{if(method.startsWith('Input.'))inputs++;return cdp.send(method,params);}}};
   const worker=scope.MechanizePlaywrightWorker.create(api,{port:()=>port,acquire:()=>{},release:()=>{},current:()=>true,unknown:()=>{},redact:value=>value});
   const identity={profileChannel:'fixture',browserInstance:'isolated',tabId:7,frameId:0,documentId:'fixture-document',documentGeneration:1};
   const text='Synthetic public message — Zażółć gęślą jaźń. '.repeat(10);
   const command={requestId:'textarea',action:'element.fill',identity,brokerEpoch:'fixture',channelEpoch:'fixture',scopeHash:'a'.repeat(64),deadlineUnixMs:Date.now()+5000,locator:{strategy:'testId',value:'composer-input',exact:true},args:{value:text},attemptId:'textarea-attempt',controlLease:{id:'fixture-lease',generation:1},fingerprintVersion:2};
   command.fingerprintSHA256=(await fingerprint.mutationV2(command)).sha256;
   async function call(type,fields={}){const requestId='request-'+(++seq);const result=new Promise(resolve=>pending.set(requestId,resolve));await worker.receive({type:'playwright.'+type,requestId,relayId:'fixture-relay',deadlineUnixMs:command.deadlineUnixMs,...fields},port);const reply=await result;if(reply.errorCode){errors.push({phase:type,code:reply.errorCode,state:reply.dispatchState,terminal:reply.result?.receipt?.dispatchState});throw Object.assign(Error('Closed relay refusal'),{code:reply.errorCode,dispatchState:reply.dispatchState});}return reply.result;}
   const host={admit:async()=>({identity,origin:'https://fixture.test',brokerEpoch:'fixture',channelEpoch:'fixture',scopeHash:'a'.repeat(64),controlLease:command.controlLease,fingerprintSHA256:command.fingerprintSHA256,committed:true,privateQuarantined:false}),current:async()=>true,openRelay:async()=>{await call('open',{command,origin:'https://fixture.test'});return {current:async()=>true,onEvent:fn=>{listeners.add(fn);return()=>listeners.delete(fn)},send:(method,params)=>call('send',{method,params}),close:()=>call('close')};},commitIntent:async()=>true,persistReceipt:async r=>(await call('receipt',{dispatchState:r.dispatchState,effectState:r.effectState,...(r.errorCode?{errorCode:r.errorCode}:{}),...(r.inputSemantics?{inputSemantics:r.inputSemantics}:{})})).persisted,redact:async value=>value};
   const result=await new PlaywrightEngine(host).execute(command);
   const receipt=journal['playwrightAttempt:textarea-attempt']?.receipt;
   if(!trapped){assert.equal(result.errorCode,undefined,JSON.stringify(errors));assert.equal(result.dispatchState,'dispatched');assert.equal(inputs,1);assert.equal(await page.getByTestId('composer-input').inputValue(),text);assert.equal(receipt.dispatchState,'dispatched');}
   else {assert.equal(inputs,0);assert.equal(await page.getByTestId('composer-input').inputValue(),'');assert.equal(errors[0].code,'playwrightTargetChanged');assert.equal(errors[0].state,'notDispatched');assert.equal(receipt.dispatchState,'notDispatched');assert.equal(receipt.error.code,'playwrightTargetChanged');assert.equal(errors[0].terminal,'notDispatched');assert.equal(result.errorCode,'playwrightReceiptUncertain');}
   console.log(JSON.stringify({fixture:'synthetic-textarea',trapped,inputs,receiptState:receipt?.dispatchState,resultCode:result.errorCode||'none',closedErrors:errors}));
  }finally{await context.close();}
 }}finally{await browser.close();}
});
