import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {chromium} from 'playwright-core';
import {PlaywrightEngine} from '../engine.mjs';
import fingerprint from '../fingerprint.cjs';
import {pageEvents} from '../relay.mjs';

for(const mode of ['normal','hrefChanged','replaced','sensitive'])test('actual Playwright role-link target guard: '+mode,{timeout:30000},async()=>{
 const browser=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
 try{
  const context=await browser.newContext(),page=await context.newPage();
  await page.route('https://fixture.test/**',route=>route.fulfill({contentType:'text/html',body:'<meta charset="utf-8"><a href="#history">Record history</a><p id="result">Dashboard</p><script>document.querySelector("a").onclick=e=>{e.preventDefault();document.querySelector("#result").textContent="History";};</script>'}));
  await page.goto('https://fixture.test');
  assert.equal(await page.getByRole('link',{name:'Record history',exact:true}).count(),1);
  const scope=vm.createContext({URL,Date,TextEncoder,setTimeout,clearTimeout});
  for(const name of ['cdp-transport','playwright-target','playwright-relay'])vm.runInContext(await readFile(new URL('../../../extension/chrome/'+name+'.js',import.meta.url),'utf8'),scope);
  let cdp,inputs=0,lastMethod='none',lastClosedFailure='none';const events=new Set();
  const api={webNavigation:{getAllFrames:async()=>[{frameId:0,documentId:'fixture-document',url:page.url()}]},debugger:{onEvent:{addListener:fn=>events.add(fn)},attach:async()=>{cdp=await context.newCDPSession(page);for(const method of pageEvents)cdp.on(method,params=>{for(const fn of events)fn({tabId:7},method,params);});},sendCommand:async(_target,method,params)=>{lastMethod=method;
   if(method==='Input.dispatchMouseEvent'&&params.type==='mouseMoved'&&mode!=='normal')await page.evaluate(mode=>{const link=document.querySelector('a');if(mode==='hrefChanged')link.href='#other';if(mode==='replaced')link.replaceWith(link.cloneNode(true));if(mode==='sensitive')link.setAttribute('data-mechanize-secret','');},mode);
   if(method==='Input.dispatchMouseEvent'&&params.type==='mousePressed')inputs++;return cdp.send(method,params);}}};
  const relay=scope.MechanizePlaywrightRelay.create(api,()=>true),identity={profileChannel:'fixture',browserInstance:'isolated',tabId:7,frameId:0,documentId:'fixture-document',documentGeneration:1};
  const host={admit:async c=>({identity,origin:'https://fixture.test',brokerEpoch:'fixture',channelEpoch:'fixture',scopeHash:'a'.repeat(64),controlLease:c.controlLease,fingerprintSHA256:c.fingerprintSHA256,committed:true,privateQuarantined:false}),current:async()=>true,openRelay:async(_,command)=>{
   const local=await relay.open({identity,origin:'https://fixture.test',command},command.deadlineUnixMs);
   return {current:()=>local.current(),onEvent:fn=>local.onEvent(fn),close:()=>local.close(),send:async(...args)=>{try{return await local.send(...args);}catch(error){lastClosedFailure=/^playwright[A-Za-z]+$/.test(error.code||'')?error.code:'unclassified';throw error;}}};
  },commitIntent:async()=>true,persistReceipt:async()=>true,redact:async value=>value};
  const command={requestId:'role-link',action:'element.press',identity,brokerEpoch:'fixture',channelEpoch:'fixture',scopeHash:'a'.repeat(64),deadlineUnixMs:Date.now()+4000,locator:{strategy:'role',value:'link',name:'Record history',exact:true},attemptId:'role-link-attempt',controlLease:{id:'fixture-lease',generation:1},fingerprintVersion:2};command.fingerprintSHA256=(await fingerprint.mutationV2(command)).sha256;
  const result=await new PlaywrightEngine(host).execute(command);
  assert.equal(result.dispatchState,mode==='normal'?'dispatched':'notDispatched',JSON.stringify({errorCode:result.errorCode,lastMethod,lastClosedFailure,inputs}));
  assert.equal(inputs,mode==='normal'?1:0);assert.equal(await page.locator('#result').textContent(),mode==='normal'?'History':'Dashboard');
  if(mode!=='normal')assert.equal(lastClosedFailure,'playwrightTargetChanged');
 }finally{await browser.close();}
});
