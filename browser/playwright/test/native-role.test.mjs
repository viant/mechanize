import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {chromium} from 'playwright-core';
import {PlaywrightEngine} from '../engine.mjs';
import fingerprint from '../fingerprint.cjs';
import {pageEvents} from '../relay.mjs';

const cases=[
 ['radio','Current period','<label for="choice">Current period</label><input id="choice" type="radio">',true],
 ['checkbox','Include archived','<label><input type="checkbox">Include archived</label>',true],
 ['combobox','Report format','<label for="choice">Report format</label><select id="choice"><option>Text</option><option>Table</option></select>',true],
 ['listbox','Visible columns','<label for="choice">Visible columns</label><select id="choice" multiple><option>First</option><option>Second</option></select>'],
 ['option','First','<select multiple><option>First</option><option>Second</option></select>'],
 ['spinbutton','Quantity','<label for="choice">Quantity</label><input id="choice" type="number">',true],
 ['searchbox','Find records','<label for="choice">Find records</label><input id="choice" type="search">',true],
 ['textbox','Description','<label for="choice">Description</label><input id="choice" type="text">',true],
 ['textbox','Notes','<label for="choice">Notes</label><textarea id="choice"></textarea>'],
 ['textbox','Email contact','<label for="choice">Email contact</label><input id="choice" type="email">'],
 ['button','Run report','<input type="button" value="Run report">',true],
 ['button','Open details','<button aria-labelledby="name"><span>Other text</span></button><span id="name" hidden>Open details</span>',true],
 ['button','Quoted "name" \\ path','<button aria-label="Quoted &quot;name&quot; \\ path">Other</button>',true],
 ['checkbox','Fallback role','<div role="invalid checkbox" aria-label="Fallback role" tabindex="0">Choice</div>'],
 ['link','Public records','<a href="#records">Public records</a>'],
 ['img','Public icon','<img alt="Public icon" src="data:image/svg+xml,%3Csvg xmlns=\"http://www.w3.org/2000/svg\"/%3E">'],
 ['heading','Summary','<h2>Summary</h2>'],
 ['navigation','Sections','<nav aria-label="Sections">Content</nav>'],
 ['region','Details','<section aria-label="Details">Content</section>'],
 ['main','Main content','<main aria-label="Main content">Content</main>'],
 ['list','Record list','<ul aria-label="Record list"><li>Item</li></ul>'],
 ['listitem',undefined,'<ul><li>Item</li></ul>'],
 ['table','Results','<table aria-label="Results"><tr><th scope="col">Column</th></tr><tr><td>Value</td></tr></table>'],
 ['columnheader','Column','<table><tr><th scope="col">Column</th></tr></table>'],
 ['rowheader','Row name','<table><tr><th scope="row">Row name</th><td>Value</td></tr></table>'],
 ['cell','Value','<table><tr><td>Value</td></tr></table>'],
 ['progressbar','Completion','<progress aria-label="Completion" value="1" max="2"></progress>'],
 ['slider','Amount','<label for="choice">Amount</label><input id="choice" type="range">'],
 ['group','Options','<fieldset><legend>Options</legend>Content</fieldset>'],
 ['status',undefined,'<output>Computed result</output>'],
];
async function executeCase(browser,item,mode='normal'){
 const [role,name,html,click]=item,context=await browser.newContext(),page=await context.newPage();
 try{
  await page.route('https://fixture.test/**',route=>route.fulfill({contentType:'text/html',body:'<meta charset="utf-8">'+html}));await page.goto('https://fixture.test');
  const locator=page.getByRole(role,{exact:true,...(name===undefined?{}:{name})});assert.equal(await locator.count(),1,role+': Playwright fixture selection');
  const scope=vm.createContext({URL,Date,TextEncoder,setTimeout,clearTimeout});for(const name of ['cdp-transport','playwright-target','playwright-relay'])vm.runInContext(await readFile(new URL('../../../extension/chrome/'+name+'.js',import.meta.url),'utf8'),scope);
  let cdp,inputs=0,failure='none',changed=false;const events=new Set();
  const api={webNavigation:{getAllFrames:async()=>[{frameId:0,documentId:'fixture-document',url:page.url()}]},debugger:{onEvent:{addListener:fn=>events.add(fn)},attach:async()=>{cdp=await context.newCDPSession(page);for(const method of pageEvents)cdp.on(method,params=>{for(const fn of events)fn({tabId:7},method,params);});},sendCommand:async(_target,method,params)=>{
   if(method==='Input.dispatchMouseEvent'&&params.type==='mouseMoved'&&mode!=='normal'&&!changed){changed=true;await page.evaluate(mode=>{const node=document.querySelector('input,select');if(mode==='replacement')node.replaceWith(node.cloneNode(true));if(mode==='label')document.querySelector('label').textContent='Different choice';if(mode==='type')node.type='checkbox';if(mode==='sensitive')node.setAttribute('data-mechanize-secret','');},mode);}
   if(method==='Input.dispatchMouseEvent'&&params.type==='mousePressed')inputs++;return cdp.send(method,params);
  }}};
  const identity={profileChannel:'fixture',browserInstance:'isolated',tabId:7,frameId:0,documentId:'fixture-document',documentGeneration:1},relay=scope.MechanizePlaywrightRelay.create(api,()=>true);
  const host={admit:async c=>({identity,origin:'https://fixture.test',brokerEpoch:'fixture',channelEpoch:'fixture',scopeHash:'a'.repeat(64),controlLease:c.controlLease,fingerprintSHA256:c.fingerprintSHA256,committed:true,privateQuarantined:false}),current:async()=>true,openRelay:async(_,command)=>{const local=await relay.open({identity,origin:'https://fixture.test',command},command.deadlineUnixMs);return{current:()=>local.current(),onEvent:fn=>local.onEvent(fn),close:()=>local.close(),send:async(...args)=>{try{return await local.send(...args);}catch(e){failure=/^playwright[A-Za-z]+$/.test(e.code||'')?e.code:'unclassified';throw e;}}};},commitIntent:async()=>true,persistReceipt:async()=>true,redact:async value=>value};
  const command={requestId:'role-guard',action:click?'element.press':'read',identity,brokerEpoch:'fixture',channelEpoch:'fixture',scopeHash:'a'.repeat(64),deadlineUnixMs:Date.now()+5000,locator:{strategy:'role',value:role,exact:true,...(name===undefined?{}:{name})},...(click?{attemptId:'role-attempt',controlLease:{id:'fixture-lease',generation:1},fingerprintVersion:2}:{args:{attribute:'text'}})};
  if(click)command.fingerprintSHA256=(await fingerprint.mutationV2(command)).sha256;
  const result=await new PlaywrightEngine(host).execute(command);
  assert.equal(result.errorCode,mode==='normal'?undefined:'playwrightTargetChanged',JSON.stringify({role,failure,code:result.errorCode,inputs}));
  assert.equal(inputs,click&&mode==='normal'?1:0,role);
  if(click&&mode==='normal'&&['radio','checkbox'].includes(role))assert.equal(await locator.isChecked(),true);
  if(mode!=='normal')assert.equal(failure,'playwrightTargetChanged');
 }finally{await context.close();}
}
test('pinned Playwright semantics cover common native implicit roles and accessible names',{timeout:60000},async()=>{
 const browser=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});try{for(const item of cases)await executeCase(browser,item);}finally{await browser.close();}
});
test('native radio proof rejects changed type, label, element or private status before physical input',{timeout:30000},async()=>{
 const browser=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});try{for(const mode of ['type','label','replacement','sensitive'])await executeCase(browser,cases[0],mode);}finally{await browser.close();}
});
