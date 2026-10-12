import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {chromium} from 'playwright-core';
import {PlaywrightEngine} from '../engine.mjs';
import fingerprint from '../fingerprint.cjs';
import {pageEvents} from '../relay.mjs';

test('large synthetic SPA uses one pinned role-link input and independently observes delayed readiness',{timeout:30000},async()=>{
 const browser=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
 try{
  const context=await browser.newContext(),page=await context.newPage();
  await page.route('https://fixture.test/**',route=>route.fulfill({contentType:'text/html',body:'<a href="#records">Record history</a><p id="ready">Dashboard</p><main></main><script>document.querySelector("main").innerHTML=Array.from({length:1500},(_,i)=>"<section>Decorative item "+i+"</section>").join("");window.inputCount=0;document.querySelector("a").onclick=e=>{e.preventDefault();inputCount++;document.querySelector("#ready").textContent="Loading";setTimeout(()=>{document.querySelector("#ready").textContent="Records ready";history.pushState({},"","#records")},650)};</script>'}));
  await page.goto('https://fixture.test');
  const scope=vm.createContext({URL,Date,TextEncoder,setTimeout,clearTimeout});
  for(const name of ['cdp-transport','playwright-target','playwright-relay'])vm.runInContext(await readFile(new URL('../../../extension/chrome/'+name+'.js',import.meta.url),'utf8'),scope);
  const events=new Set(),methods=[];let cdp,hostCurrent=0,localCurrent=0,sendCallbacks=0,receipts=0;
  const api={webNavigation:{getAllFrames:async()=>[{frameId:0,documentId:'fixture-document',url:page.url()}]},debugger:{onEvent:{addListener:fn=>events.add(fn)},attach:async()=>{cdp=await context.newCDPSession(page);for(const method of pageEvents)cdp.on(method,params=>{for(const fn of events)fn({tabId:7},method,params)});},sendCommand:async(_target,method,params)=>{methods.push(method);return cdp.send(method,params);}}};
  const relay=scope.MechanizePlaywrightRelay.create(api,()=>true),identity={profileChannel:'fixture',browserInstance:'isolated',tabId:7,frameId:0,documentId:'fixture-document',documentGeneration:1};
  const delay=()=>new Promise(resolve=>setTimeout(resolve,4));
  const host={admit:async c=>({identity,origin:'https://fixture.test',brokerEpoch:'fixture',channelEpoch:'fixture',scopeHash:'a'.repeat(64),controlLease:c.controlLease,fingerprintSHA256:c.fingerprintSHA256,committed:true,privateQuarantined:false}),current:async()=>{hostCurrent++;await delay();return true},openRelay:async(_,command)=>{
    const local=await relay.open({identity,origin:'https://fixture.test',command},command.deadlineUnixMs);
    return {current:async()=>{localCurrent++;return local.current()},onEvent:f=>local.onEvent(f),close:()=>local.close(),send:async(...args)=>{sendCallbacks++;await delay();return local.send(...args)}};
  },commitIntent:async()=>true,persistReceipt:async()=>{receipts++;return true},redact:async value=>value};
  const command={requestId:'slow-spa',action:'element.press',identity,brokerEpoch:'fixture',channelEpoch:'fixture',scopeHash:'a'.repeat(64),deadlineUnixMs:Date.now()+2000,locator:{strategy:'role',value:'link',name:'Record history',exact:true},attemptId:'slow-spa-attempt',controlLease:{id:'fixture-lease',generation:1},fingerprintVersion:2};command.fingerprintSHA256=(await fingerprint.mutationV2(command)).sha256;
  const engine=new PlaywrightEngine(host),began=performance.now(),result=await engine.execute(command),elapsedMs=Math.round(performance.now()-began);
  assert.equal(result.dispatchState,'dispatched',JSON.stringify(result));assert.equal(result.effectState,'unverified');assert.equal(receipts,1);
  await page.locator('#ready').getByText('Records ready',{exact:true}).waitFor({timeout:2000});assert.equal(await page.evaluate(()=>inputCount),1);
  const beforeCalls=methods.length;assert.equal((await engine.execute(command)).dispatchState,'dispatched');assert.equal(methods.length,beforeCalls);assert.equal(await page.evaluate(()=>inputCount),1);
  console.log(JSON.stringify({fixture:'large-slow-SPA',elapsedMs,hostCurrent,localCurrent,sendCallbacks,actualCDPRequests:methods.length,runtimeFunctionCalls:methods.filter(m=>m==='Runtime.callFunctionOn').length,physicalInputCount:1,readinessVerified:true,receiptCount:receipts}));
 }finally{await browser.close();}
});
