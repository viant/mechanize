import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,access} from 'node:fs/promises';
import vm from 'node:vm';
import {chromium} from 'playwright-core';
import {PlaywrightEngine} from '../engine.mjs';
import fingerprint from '../fingerprint.cjs';
import {pageEvents} from '../relay.mjs';

test('owned relay enables focus in a real background Chrome tab before ordinary fill and click',{timeout:30000},async()=>{
  // Full headless Chrome implements per-tab focus; headless-shell reports every
  // tab focused. This launches an isolated disposable profile with no user UI.
  const executable=process.env.MECHANIZE_FOCUS_FIXTURE_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  await access(executable);
  const browser=await chromium.launch({executablePath:executable,headless:true});
  try{
    const context=await browser.newContext(),page=await context.newPage();
    await page.route('https://fixture.test/**',route=>route.fulfill({contentType:'text/html',body:'<input id="entry"><button id="apply">Apply</button><p id="result"></p><script>document.querySelector("#apply").onclick=()=>{if(document.hasFocus())requestAnimationFrame(()=>requestAnimationFrame(()=>document.querySelector("#result").textContent=document.querySelector("#entry").value));}</script>'}));
    await page.goto('https://fixture.test');
    const foreground=await context.newPage();await foreground.setContent('Disposable foreground tab');
    for(const tab of [page,foreground]){const setup=await context.newCDPSession(tab);await setup.send('Emulation.setFocusEmulationEnabled',{enabled:false});await setup.detach();}
    await foreground.bringToFront();assert.equal(await page.evaluate(()=>document.hasFocus()),false);assert.equal(await foreground.evaluate(()=>document.hasFocus()),true);
    const scope=vm.createContext({URL,Date,TextEncoder,setTimeout,clearTimeout});
    for(const module of ['cdp-transport','playwright-target','playwright-relay'])vm.runInContext(await readFile(new URL('../../../extension/chrome/'+module+'.js',import.meta.url),'utf8'),scope);
    const events=new Set(),calls=[];let cdp;
    const api={webNavigation:{getAllFrames:async()=>[{frameId:0,documentId:'fixture-document',url:page.url()}]},debugger:{onEvent:{addListener:f=>events.add(f)},attach:async()=>{cdp=await context.newCDPSession(page);for(const method of pageEvents)cdp.on(method,params=>{for(const listener of events)listener({tabId:7},method,params)});},sendCommand:async(target,method,params)=>{assert.equal(target.tabId,7);assert.equal(target.sessionId,undefined);calls.push(method);return cdp.send(method,params);}}};
    let hostChecks=0;
    const relay=scope.MechanizePlaywrightRelay.create(api,()=>true);
    const identity={profileChannel:'fixture',browserInstance:'isolated',tabId:7,frameId:0,documentId:'fixture-document',documentGeneration:1};
    const host={admit:async c=>({identity,origin:'https://fixture.test',brokerEpoch:'fixture',channelEpoch:'fixture',scopeHash:'a'.repeat(64),controlLease:c.controlLease,fingerprintSHA256:c.fingerprintSHA256,committed:true,privateQuarantined:false}),current:async()=>{hostChecks++;return true},openRelay:(_,command)=>relay.open({identity,origin:'https://fixture.test',command},command.deadlineUnixMs),commitIntent:async()=>true,persistReceipt:async()=>true,redact:async value=>value};
    const engine=new PlaywrightEngine(host);
    let sequence=0;const stats=[];
    for(const [action,target,args] of [['element.fill','entry',{value:'synthetic public input'}],['element.press','apply',undefined]]){
      const command={requestId:'focus-'+(++sequence),action,identity,brokerEpoch:'fixture',channelEpoch:'fixture',scopeHash:'a'.repeat(64),deadlineUnixMs:Date.now()+4000,locator:{strategy:'id',value:target,exact:true},...(args?{args}:{}),attemptId:'focus-attempt-'+sequence,controlLease:{id:'fixture-lease',generation:1},fingerprintVersion:2};
      command.fingerprintSHA256=(await fingerprint.mutationV2(command)).sha256;
      const began=performance.now(),startCalls=calls.length,startChecks=hostChecks;
      const result=await engine.execute(command);assert.equal(result.dispatchState,'dispatched',JSON.stringify(result));
      stats.push({action,elapsedMs:Math.round(performance.now()-began),cdpRequests:calls.length-startCalls,hostCurrentChecks:hostChecks-startChecks,runtimeCalls:calls.slice(startCalls).filter(method=>method==='Runtime.callFunctionOn').length});
    }
    await page.locator('#result').getByText('synthetic public input',{exact:true}).waitFor({timeout:2000});
    assert.equal(calls[0],'Emulation.setFocusEmulationEnabled');assert.equal(calls.filter(m=>m==='Emulation.setFocusEmulationEnabled').length,2);assert.equal(calls.includes('Page.bringToFront'),false);
    console.log(JSON.stringify({fixture:'background-Chrome-focus',initialFocus:false,focusEmulation:true,actualPlaywrightFillAndClick:true,animationFrameResultVerified:true,tabActivationCommands:0,stats}));
  }finally{await browser.close();}
});
