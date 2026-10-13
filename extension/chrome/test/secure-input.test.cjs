const {test} = require('node:test');
const assert = require('node:assert/strict');
const {JSDOM} = require('jsdom');
const fs = require('node:fs');
const path = require('node:path');
const html = '<form method="post" action="/authenticate"><input autocomplete="username"><input type="password" autocomplete="current-password"><button>Login</button></form>';
function fixture(body = html) {
  const dom = new JSDOM(body, {url:'https://fixture.example.test/login',runScripts:'outside-only'});
  dom.window.TextEncoder = TextEncoder;
  dom.window.HTMLElement.prototype.getClientRects = function(){return [{width:100,height:20}];};
  dom.window.HTMLElement.prototype.getBoundingClientRect = function(){return {left:10,top:20,width:100,height:20};};
  for (const name of ['protocol.js','accessibility-provider.js','dom.js','secure-input.js']) dom.window.eval(fs.readFileSync(path.join(__dirname,'..',name),'utf8'));
  return {window:dom.window,doc:dom.window.document,receiver:dom.window.MechanizeSecureInput.create()};
}
function payload(extra={}) {return {attemptId:'a'.repeat(64),origin:'https://fixture.example.test',deadlineUnixMs:Date.now()+5000,username:'USERNAME-CANARY',password:'PASSWORD-CANARY',...extra};}
function result(f,p=payload(),check=()=>{}) {return JSON.parse(JSON.stringify(f.receiver.fill(f.doc,p,check)));}
test('private login fill returns only dispatch state and keeps visible login fields unreadable without submission',()=>{
  const f=fixture();let submits=0;f.doc.querySelector('form').addEventListener('submit',()=>submits++);
  assert.deepEqual(result(f),{status:'dispatched'});
  assert.equal(f.doc.querySelector('[autocomplete="username"]').value,'USERNAME-CANARY');
  assert.equal(f.doc.querySelector('[type="password"]').value,'PASSWORD-CANARY');
  assert.equal(submits,0);
  assert.throws(()=>f.window.MechanizeDOM.snapshot(f.doc),e=>e.code==='secureDocumentRequired');
  f.doc.querySelector('form').remove();
  // The content message handler owns actual private-delivery admission. DOM
  // layout inspection must not permanently quarantine a now-empty page.
  assert.ok(!JSON.stringify(f.window.MechanizeDOM.snapshot(f.doc)).includes('CANARY'));
  f.window.close();
});
test('private fill refuses origin drift, extra instructions and expired deadline before writing',()=>{
  for(const extra of [{origin:'https://other.example.test'},{submit:true},{deadlineUnixMs:Date.now()-1}]) {
    const f=fixture();assert.deepEqual(result(f,payload(extra)),{status:'notDispatched'});
    assert.equal(f.doc.querySelector('[type="password"]').value,'');f.window.close();
  }
});
test('ambiguous users, foreign form action and authentication challenges refuse delivery',()=>{
  for(const body of [html.replace('<button>','<input name="username"><button>'),html.replace('/authenticate','https://other.example.test/'),html.replace('<button>','<input autocomplete="one-time-code"><button>'),html.replace('current-password','new-password')]) {
    const f=fixture(body);assert.deepEqual(result(f),{status:'notDispatched'});
    assert.equal(f.doc.querySelector('[type="password"]').value,'');f.window.close();
  }
});
test('authority refusal never exports an exception or writes a credential',()=>{
  const f=fixture();const reply=result(f,payload(),()=>{throw Error('PASSWORD-CANARY private failure');});
  assert.deepEqual(reply,{status:'notDispatched'});assert.equal(JSON.stringify(reply).includes('CANARY'),false);
  assert.equal(f.doc.querySelector('[type="password"]').value,'');f.window.close();
});
test('a false or asynchronous guard cannot admit credential writes',()=>{
  for(const guard of [()=>false,()=>Promise.resolve(true)]) {
    const f=fixture();assert.deepEqual(result(f,payload(),guard),{status:'notDispatched'});
    assert.equal(f.doc.querySelector('[type="password"]').value,'');f.window.close();
  }
});
test('post-input identity drift is unknown, with no echo or replay',()=>{
  const f=fixture();f.doc.querySelector('[autocomplete="username"]').addEventListener('input',()=>f.doc.querySelector('[type="password"]').remove());
  assert.deepEqual(result(f),{status:'unknown'});
  assert.deepEqual(result(f,payload({attemptId:'b'.repeat(64)})),{status:'notDispatched'});f.window.close();
});
test('opaque attempt is consumed once and never causes another input event',()=>{
  const f=fixture();let events=0;f.doc.querySelector('[autocomplete="username"]').addEventListener('input',()=>events++);
  assert.deepEqual(result(f),{status:'dispatched'});assert.deepEqual(result(f),{status:'notDispatched'});
  assert.equal(events,1);f.window.close();
});
test('secure admission inspects form shape without reading values or returning private metadata',()=>{
  const f=fixture();
  for(const el of f.doc.querySelectorAll('input')) Object.defineProperty(el,'value',{get(){throw Error('PRIVATE-CANARY');}});
  assert.deepEqual(JSON.parse(JSON.stringify(f.window.MechanizeSecureInput.inspect(f.doc,'https://fixture.example.test',()=>true))),{ready:true,stage:'pair'});
  assert.deepEqual(JSON.parse(JSON.stringify(f.window.MechanizeSecureInput.inspect(f.doc,'https://other.example.test',()=>true))),{ready:false,stage:'unavailable'});
  assert.deepEqual(JSON.parse(JSON.stringify(f.window.MechanizeSecureInput.inspect(f.doc,'https://fixture.example.test',()=>false))),{ready:false,stage:'unavailable'});
  f.window.close();
});

test('private POST submit uses retained exact form once with scalar result and no value reads',()=>{
 const f=fixture(html);let submits=0;
 f.doc.querySelector('form').addEventListener('submit',e=>{e.preventDefault();submits++;});
 assert.deepEqual(result(f),{status:'dispatched'});
 for(const input of f.doc.querySelectorAll('input'))Object.defineProperty(input,'value',{get(){throw Error('PRIVATE-CANARY');}});
 const request={attemptId:'b'.repeat(64),fillAttemptId:'a'.repeat(64),origin:'https://fixture.example.test',deadlineUnixMs:Date.now()+5000};
 assert.deepEqual(JSON.parse(JSON.stringify(f.receiver.submit(f.doc,request,()=>true))),{status:'dispatched'});
 assert.deepEqual(JSON.parse(JSON.stringify(f.receiver.submit(f.doc,{...request,attemptId:'c'.repeat(64)},()=>true))),{status:'notDispatched'});
 assert.equal(submits,1);assert.throws(()=>f.window.MechanizeDOM.snapshot(f.doc));f.window.close();
});

test('same-document post-submit classification reads no values and repeats no input',()=>{
 const f=fixture(html);let submits=0;
 f.doc.querySelector('form').addEventListener('submit',e=>{e.preventDefault();submits++;});
 assert.equal(result(f).status,'dispatched');
 for(const input of f.doc.querySelectorAll('input'))Object.defineProperty(input,'value',{get(){throw Error('VALUE-CANARY must not be read');}});
 const request={attemptId:'b'.repeat(64),fillAttemptId:'a'.repeat(64),origin:'https://fixture.example.test',deadlineUnixMs:Date.now()+5000};
 assert.equal(f.receiver.submit(f.doc,request,()=>true).status,'dispatched');
 const probe={attemptId:request.attemptId,origin:request.origin,deadlineUnixMs:request.deadlineUnixMs};
 const read=()=>JSON.parse(JSON.stringify(f.receiver.postSubmitStatus(f.doc,probe,()=>true)));
 assert.deepEqual(read(),{ready:false,stage:'pending'});
 assert.deepEqual(read(),{ready:false,stage:'pending'});assert.equal(submits,1);
 const alert=f.doc.createElement('div');alert.setAttribute('role','alert');alert.textContent='Invalid credentials for USERNAME-CANARY';f.doc.body.append(alert);
 assert.deepEqual(read(),{ready:false,stage:'rejected'});alert.remove();
 const otp=f.doc.createElement('input');otp.autocomplete='one-time-code';f.doc.querySelector('form').append(otp);
 assert.deepEqual(read(),{ready:false,stage:'challenge'});otp.remove();
 const mobile=f.doc.createElement('p');mobile.textContent='Potwierdź logowanie w aplikacji. CODE-CANARY';f.doc.body.append(mobile);
 assert.deepEqual(read(),{ready:false,stage:'challenge'});mobile.remove();
 f.doc.querySelector('form').remove();
 assert.deepEqual(read(),{ready:false,stage:'unavailable'});
 assert.ok(!JSON.stringify(f.window.MechanizeDOM.snapshot(f.doc)).includes('CANARY'));
 assert.ok(!JSON.stringify(read()).includes('CANARY'));assert.equal(submits,1);
 f.window.close();
});
test('private staged forms fill only existing username or password and never challenge inputs',()=>{
 for(const [field,stage] of [['<input autocomplete="username">','username'],['<input type="password" autocomplete="current-password">','password']]) {
  const f=fixture(`<form method="post" action="/next">${field}<button>Next</button></form>`);
  assert.equal(f.window.MechanizeSecureInput.inspect(f.doc,'https://fixture.example.test',()=>true).stage,stage);
  assert.deepEqual(result(f),{status:'dispatched'});f.window.close();
 }
 const f=fixture('<form><input autocomplete="one-time-code"><button>Next</button></form>');
 assert.equal(f.window.MechanizeSecureInput.inspect(f.doc,'https://fixture.example.test',()=>true).stage,'challenge');assert.deepEqual(result(f),{status:'notDispatched'});f.window.close();
});
test('private submit denies expired guards, changed form endpoint, GET and duplicate submitters',()=>{
 for(const mode of ['cancelled','endpoint','GET','ambiguous']){
  const f=fixture(html);assert.deepEqual(result(f),{status:'dispatched'});
  if(mode==='endpoint')f.doc.querySelector('form').action='https://other.example.test';
  if(mode==='GET')f.doc.querySelector('form').method='get';
  if(mode==='ambiguous')f.doc.querySelector('form').append(f.doc.createElement('button'));
  const response=f.receiver.submit(f.doc,{attemptId:'b'.repeat(64),fillAttemptId:'a'.repeat(64),origin:'https://fixture.example.test',deadlineUnixMs:Date.now()+5000},()=>mode!=='cancelled');
  assert.equal(response.status,'notDispatched');f.window.close();
 }
});

test('private admission and fill reject unsupported submission before any secret input',()=>{
 const bodies=[
  html.replace('<button>Login</button>',''),
  html.replace('</form>','<button>Other</button></form>'),
  html.replace('<button>','<button formaction="https://other.example.test">'),
  html.replace('<button>','<button formtarget="_blank">')
 ];
 for(const body of bodies){
  const f=fixture(body);let events=0;
  for(const input of f.doc.querySelectorAll('input')){
   input.addEventListener('input',()=>events++);
   Object.defineProperty(input,'value',{get(){throw Error('PRIVATE-CANARY');}});
  }
  const inspected=JSON.parse(JSON.stringify(f.window.MechanizeSecureInput.inspect(f.doc,'https://fixture.example.test',()=>true)));
  assert.deepEqual(inspected,{ready:false,stage:'unavailable'});
  assert.deepEqual(result(f),{status:'notDispatched'});
  assert.equal(events,0);f.window.close();
 }
});
test('submit override drift after private fill refuses dispatch without reading values',()=>{
 for(const [key,value] of [['formmethod','get'],['formaction','https://other.example.test'],['formtarget','_blank']]){
  const f=fixture();assert.deepEqual(result(f),{status:'dispatched'});
  f.doc.querySelector('button').setAttribute(key,value);
  for(const input of f.doc.querySelectorAll('input'))Object.defineProperty(input,'value',{get(){throw Error('PRIVATE-CANARY');}});
  assert.equal(f.receiver.submit(f.doc,{attemptId:'b'.repeat(64),fillAttemptId:'a'.repeat(64),origin:'https://fixture.example.test',deadlineUnixMs:Date.now()+5000},()=>true).status,'notDispatched');
  assert.throws(()=>f.window.MechanizeDOM.snapshot(f.doc));f.window.close();
 }
});

test('private submit clicks JavaScript login button in a default-GET form without native GET or value reads',()=>{
 const f=fixture(html.replace(' method="post"','').replace('<button>','<button type="button">'));
 let clicks=0,submits=0;const form=f.doc.querySelector('form');
 f.doc.querySelector('button').addEventListener('click',()=>{clicks++;form.requestSubmit();});
 form.addEventListener('submit',e=>{submits++;assert.equal(e.defaultPrevented,true);});
 assert.equal(f.window.MechanizeSecureInput.inspect(f.doc,'https://fixture.example.test',()=>true).ready,true);
 assert.deepEqual(result(f),{status:'dispatched'});
 for(const input of f.doc.querySelectorAll('input'))Object.defineProperty(input,'value',{get(){throw Error('PRIVATE-CANARY');}});
 const request={attemptId:'b'.repeat(64),fillAttemptId:'a'.repeat(64),origin:'https://fixture.example.test',deadlineUnixMs:Date.now()+5000};
 assert.equal(f.receiver.submit(f.doc,request,()=>true).status,'dispatched');
 assert.equal(clicks,1);assert.equal(submits,1);
 form.requestSubmit();assert.equal(submits,2,'delayed GET stays cancelled');
 assert.equal(f.receiver.submit(f.doc,{...request,attemptId:'c'.repeat(64)},()=>true).status,'notDispatched');assert.equal(clicks,1);f.window.close();
});
test('private POST login dispatches click handler before the native submit event',()=>{
 const f=fixture();const sequence=[];
 f.doc.querySelector('button').addEventListener('click',()=>sequence.push('click'));
 f.doc.querySelector('form').addEventListener('submit',e=>{assert.equal(e.defaultPrevented,false);e.preventDefault();sequence.push('submit');});
 assert.deepEqual(result(f),{status:'dispatched'});
 assert.equal(f.receiver.submit(f.doc,{attemptId:'b'.repeat(64),fillAttemptId:'a'.repeat(64),origin:'https://fixture.example.test',deadlineUnixMs:Date.now()+5000},()=>true).status,'dispatched');
 assert.deepEqual(sequence,['click','submit']);const cue=f.doc.querySelector('[data-mechanize-pointer]');assert.ok(cue);assert.equal(cue.getAttribute('aria-hidden'),'true');assert.equal(cue.style.pointerEvents,'none');assert.equal(cue.shadowRoot,null);assert.equal(cue.textContent,'');f.window.close();
});
test('private admission allows initially disabled login button and submit requires it enabled',()=>{
 for(const enable of [true,false]){
 const f=fixture(html.replace('<button>','<button disabled>'));
 if(enable)f.doc.querySelector('[type="password"]').addEventListener('input',()=>{f.doc.querySelector('button').disabled=false;});
 assert.equal(f.window.MechanizeSecureInput.inspect(f.doc,'https://fixture.example.test',()=>true).ready,true);
 f.doc.querySelector('form').addEventListener('submit',e=>e.preventDefault());
 assert.deepEqual(result(f),{status:'dispatched'});
 assert.equal(f.receiver.submit(f.doc,{attemptId:'b'.repeat(64),fillAttemptId:'a'.repeat(64),origin:'https://fixture.example.test',deadlineUnixMs:Date.now()+5000},()=>true).status,enable?'dispatched':'notDispatched');f.window.close();
 }
});
test('private submit rejects a replaced login button even with identical markup',()=>{
 const f=fixture();assert.deepEqual(result(f),{status:'dispatched'});const button=f.doc.querySelector('button');button.replaceWith(button.cloneNode(true));
 assert.equal(f.receiver.submit(f.doc,{attemptId:'b'.repeat(64),fillAttemptId:'a'.repeat(64),origin:'https://fixture.example.test',deadlineUnixMs:Date.now()+5000},()=>true).status,'notDispatched');f.window.close();
});

test('private recipient pin tolerates decoration changes without reading credential values',()=>{
 const f=fixture('<p id="decoration">Initial</p>'+html);
 try {
  const user=f.doc.querySelector('[autocomplete=username]'),password=f.doc.querySelector('[type=password]');
  Object.defineProperty(user,'value',{get(){throw Error('USERNAME-CANARY');}});
  Object.defineProperty(password,'value',{get(){throw Error('PASSWORD-CANARY');}});
  const pin=f.window.MechanizeSecureInput.pinRecipient(f.doc,f.doc.location.origin);
  assert.equal(pin.stage,'pair');assert.equal(pin.current(),true);
  f.doc.querySelector('#decoration').textContent='Updated marketing text';
  f.doc.body.insertAdjacentHTML('beforeend','<p>Decorative footer</p>');
  assert.equal(pin.current(),true);
  assert.ok(!JSON.stringify(pin).includes('CANARY'));
  pin.retire();assert.equal(pin.current(),false);
 }finally {f.window.close();}
});

test('private recipient pin rejects replacement submission drift ambiguity and challenges',()=>{
 for(const mode of ['username','password','form','submitter','action','method','target','metadata','ambiguity','challenge']) {
  const f=fixture();
  try {
   const pin=f.window.MechanizeSecureInput.pinRecipient(f.doc,f.doc.location.origin);
   assert.equal(pin.current(),true);
   const form=f.doc.querySelector('form'),user=f.doc.querySelector('[autocomplete=username]'),password=f.doc.querySelector('[type=password]'),button=f.doc.querySelector('button');
   if(mode==='username')user.replaceWith(user.cloneNode(true));
   if(mode==='password')password.replaceWith(password.cloneNode(true));
   if(mode==='form')form.replaceWith(form.cloneNode(true));
   if(mode==='submitter')button.replaceWith(button.cloneNode(true));
   if(mode==='action')form.action='https://other.example.test/submit';
   if(mode==='method')form.method='get';
   if(mode==='target')button.setAttribute('formtarget','_blank');
   if(mode==='metadata')user.setAttribute('name','changed-username');
   if(mode==='ambiguity')form.append(user.cloneNode(true));
   if(mode==='challenge')form.insertAdjacentHTML('beforeend','<input autocomplete="one-time-code">');
   assert.equal(pin.current(),false,mode);
   assert.equal(user.value,'');assert.equal(password.value,'');
  }finally {f.window.close();}
 }
});

test('public obligation identifier does not become a username-first login form',()=>{
 const f=fixture('<form><h1>Tax transfer</h1><label for="business">identyfikator zobowiązania (opcjonalnie)</label><input id="business" value="PUBLIC-FIXTURE"><button>Next</button></form>');
 assert.equal(f.window.MechanizeSecureInput.privacyReady(f.doc,'https://fixture.example.test'),true);
 assert.equal(f.window.MechanizeSecureInput.inspect(f.doc,'https://fixture.example.test',()=>true).ready,false);
 const login=fixture('<form><h1>Zaloguj się</h1><label for="identifier">identyfikator</label><input id="identifier"><button>Continue</button></form>');
 assert.equal(login.window.MechanizeSecureInput.privacyReady(login.doc,'https://fixture.example.test'),false);
});
