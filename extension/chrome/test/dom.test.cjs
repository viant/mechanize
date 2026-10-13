const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
function fixture(html) {
  const dom = new JSDOM(html, {url: 'https://fixture.example.test', runScripts: 'outside-only'});
  dom.window.TextEncoder = TextEncoder;
  dom.window.HTMLElement.prototype.getClientRects = function () { return [{width: 100, height: 20}]; };
  const listeners = [];
  dom.window.chrome = {runtime: {id: 'fixture', onMessage: {addListener: f => listeners.push(f)}}};
  for (const file of ['protocol.js', 'accessibility-provider.js', 'dom.js', 'recorder.js', 'content.js']) dom.window.eval(fs.readFileSync(path.join(__dirname, '..', file), 'utf8'));
  return {window: dom.window, document: dom.window.document, api: dom.window.MechanizeDOM,
    send: message => { let reply; listeners[0](message, {id: 'fixture'}, value => reply = value); return reply; }};
}
const identity = {profileChannel: 'profile1', browserInstance: 'browser1', tabId: 7, frameId: 0, documentId: 'doc1', documentGeneration: 1};
const binding = {identity, brokerEpoch: 'broker1', channelEpoch: 'channel1', scopeHash: 'scope1'};
const command = (action, extra = {}) => ({requestId: 'request1', action, ...binding, deadlineUnixMs: Date.now() + 5000, ...extra});
test('completed login allows ordinary page control while sensitive fields remain redacted',()=>{
 const f=fixture('<button id="history">History</button><p>KNOWN-SECRET</p>');
 f.api.installPrivateDocumentRedactor(f.document,value=>String(value).replaceAll('KNOWN-SECRET','[redacted]'));
 f.document.body.insertAdjacentHTML('beforeend','<input id="password" type="password" aria-label="NEW-SECRET" value="NEW-SECRET"><input id="otp" value="OTP-CANARY">');
 let clicked=0;f.document.querySelector('#history').onclick=()=>clicked++;
 f.api.act(f.document,'element.press',{strategy:'id',value:'history'},{});
 assert.equal(clicked,1);
 const snapshot=JSON.stringify(f.api.snapshot(f.document));
 for(const value of ['KNOWN-SECRET','NEW-SECRET','OTP-CANARY'])assert.ok(!snapshot.includes(value));
 assert.equal(f.api.act(f.document,'read',{strategy:'id',value:'password'},{attribute:'value'}).value,'[redacted]');
 assert.equal(f.api.act(f.document,'resolve',{strategy:'id',value:'password'},{}).name,'[redacted]');
 assert.throws(()=>f.api.act(f.document,'element.fill',{strategy:'id',value:'password'},{value:'new'}),e=>e.code==='secureDocumentRequired');
 f.window.close();
});
test('credential documents withhold all output and refuse ordinary mutation', () => {
  for (const html of [
    '<input type="password" id="secret-canary" value="value-canary"><h1>reflected-canary</h1>',
    '<input autocomplete="username" value="login-canary"><button data-testid="metadata-canary">Save</button>',
    '<form aria-label="Sign in"><label for="account">identyfikator</label><input id="account" value="login-canary"></form>',
  ]) {
    const f = fixture(html);
    for (const run of [() => f.api.snapshot(f.document), () => f.api.resolve(f.document, {strategy:'css', value:'input'}),
      () => f.api.act(f.document, 'read', {strategy:'css', value:'h1'}, {attribute:'text'}),
      () => f.api.act(f.document, 'element.fill', {strategy:'css', value:'input'}, {value:'new-canary'})]) {
      assert.throws(run, e => e.code === 'secureDocumentRequired' && !JSON.stringify(e).includes('canary'));
    }
    f.document.body.innerHTML = '<button>ordinary</button>';
    assert.ok(f.api.snapshot(f.document).nodes.some(n=>n.name==='ordinary'));
    f.document.body.insertAdjacentHTML('beforeend','<input type=password value=RETURNING-CANARY>');
    assert.throws(()=>f.api.snapshot(f.document),e=>e.code==='secureDocumentRequired');
    f.window.close();
  }
});
test('explicit secret region preserves public labels and filters parent text',()=>{
 const f=fixture('<button id=public>History</button><p id=parent>Public <span data-mechanize-secret>reflected-canary</span> text</p>');
 const snapshot=f.api.snapshot(f.document);assert.ok(snapshot.nodes.some(n=>n.name==='History'));assert.ok(!JSON.stringify(snapshot).includes('canary'));
 assert.equal(f.api.act(f.document,'read',{strategy:'id',value:'parent'},{attribute:'text'}).value,'Public text');
 f.document.body.innerHTML='<button>ordinary</button>';assert.ok(f.api.snapshot(f.document).nodes.some(n=>n.name==='ordinary'));f.window.close();
});
test('credential detection includes open shadow roots and fails closed on incomplete coverage', () => {
  const f = fixture('<div id="host"></div>');
  f.document.getElementById('host').attachShadow({mode:'open'}).innerHTML = '<input autocomplete="username" value="canary">';
  assert.throws(() => f.api.snapshot(f.document), e => e.code === 'secureDocumentRequired');
  f.window.close();
  const large = fixture('<div></div>'.repeat(2100));
  assert.equal(large.api.snapshot(large.document).truncated,true);
  large.document.body.innerHTML='<div></div>'.repeat(20001);
  assert.throws(() => large.api.snapshot(large.document), e => e.code === 'secureDocumentRequired');
  large.window.close();
});
test('public navigation discussing credentials does not quarantine a composer', t => {
  const f=fixture('<button title="Fix login token handling">History</button><a id="login-help" href="/help">Login help</a><h2 title="Password reset guide">Guide</h2><input type="submit" value="Login"><textarea id="composer" aria-label="Message"></textarea>');
  t.after(()=>f.window.close());
  assert.equal(f.api.protectedDocument(f.document),false);
  assert.ok(f.api.snapshot(f.document).nodes.some(n=>n.name==='History'));
  f.api.act(f.document,'element.fill',{strategy:'id',value:'composer'},{value:'Public task'});
  assert.equal(f.api.act(f.document,'read',{strategy:'id',value:'composer'},{attribute:'value'}).value,'Public task');
});
test('visible credential entry blocks current reads while other secrets are masked locally', t => {
 for(const html of ['<div role="textbox" aria-label="Username">PRIVATE-CANARY</div>','<div contenteditable="true" aria-label="Password">PRIVATE-CANARY</div>']){
  const f=fixture(html+'<button>History</button>');t.after(()=>f.window.close());
  assert.throws(()=>f.api.snapshot(f.document),e=>e.code==='secureDocumentRequired'&&!JSON.stringify(e).includes('CANARY'));
 }
 for(const html of ['<input hidden name="token" value="PRIVATE-CANARY">','<textarea aria-label="API key">PRIVATE-CANARY</textarea>','<button data-mechanize-secret>PRIVATE-CANARY</button>']){
  const f=fixture('<button id=public>History</button><div id=parent>Public <span id=secret>'+html+'</span> text</div>');t.after(()=>f.window.close());
  for(const input of f.document.querySelectorAll('input,textarea'))Object.defineProperty(input,'value',{get(){throw Error('secret value read')}});
  const snapshot=f.api.snapshot(f.document);assert.ok(snapshot.nodes.some(n=>n.name==='History'));assert.ok(!JSON.stringify(snapshot).includes('CANARY'));
  assert.equal(f.api.act(f.document,'read',{strategy:'id',value:'parent'},{attribute:'text'}).value,'Public text');
  const secret=f.document.querySelector('#secret').firstElementChild;secret.id='sensitive';
  assert.equal(f.api.act(f.document,'read',{strategy:'id',value:'sensitive'},{attribute:'value'}).value,'[redacted]');
  assert.equal(f.api.act(f.document,'read',{strategy:'id',value:'public'},{attribute:'text'}).value,'History');
 }
});
test('ordinary snapshots remain bounded and exclude script content', () => {
  const f = fixture('<input id="case" value="CASE"><button>Save</button><script>private-data</script>');
  assert.equal(f.api.snapshot(f.document, {limit:1}).truncated, true);
  assert.ok(!JSON.stringify(f.api.snapshot(f.document)).includes('private-data'));
  f.window.close();
});
test('strict unique locator, label and open shadow-root semantics', () => {
  const f = fixture('<label for="case">Case ID</label><input id="case"><button>Save</button><button>Save</button><div id="host"></div>');
  assert.equal(f.api.resolve(f.document, {strategy: 'label', value: 'Case ID'}).id, 'case');
  assert.throws(() => f.api.resolve(f.document, {strategy: 'role', value: 'button', name: 'Save'}), e => e.code === 'ambiguousTarget');
  f.document.getElementById('host').attachShadow({mode: 'open'}).innerHTML = '<button data-testid="shadow">Shadow</button>';
  assert.equal(f.api.resolve(f.document, {strategy: 'testId', value: 'shadow'}).textContent, 'Shadow');
});
test('fill uses native setter with untrusted events; file controls require activation', () => {
  const f = fixture('<input id="case"><input type="file" id="file"><button disabled id="disabled">Save</button>');
  const events = [];
  f.document.getElementById('case').addEventListener('input', e => events.push(e.isTrusted));
  f.api.act(f.document, 'element.fill', {strategy: 'id', value: 'case'}, {value: 'literal ${x}\n"quoted"'});
  assert.equal(f.document.getElementById('case').value, 'literal ${x}"quoted"'); // native input strips newlines
  assert.deepEqual(events, [false]);
  assert.throws(() => f.api.act(f.document, 'element.press', {strategy: 'id', value: 'file'}), e => e.code === 'userActivationRequired');
  assert.throws(() => f.api.act(f.document, 'element.press', {strategy: 'id', value: 'disabled'}), e => e.code === 'targetNotActionable');
});
test('document receipts prevent duplicate dispatch and detect attempt conflicts', () => {
  const f = fixture('<button id="save">Save</button>');
  let clicks = 0;
  f.document.getElementById('save').addEventListener('click', () => clicks++);
  f.send({type: 'bind', binding});
  const c = command('element.press', {attemptId: 'attempt1', locator: {strategy: 'id', value: 'save'}});
  assert.equal(f.send(c).dispatchState, 'dispatched');
  assert.equal(f.send({...c, requestId: 'request2'}).dispatchState, 'dispatched');
  assert.equal(clicks, 1);
  assert.equal(f.send({...c, requestId: 'request3', locator: {strategy: 'id', value: 'other'}}).error.code, 'attemptConflict');
  assert.equal(f.send(command('receipt.query', {attemptId: 'attempt1'})).dispatchState, 'dispatched');
  assert.equal(f.send(command('receipt.query', {attemptId: 'lost'})).effectState, 'unknown');
});
test('stale document/frame/generation fails closed; observation refreshes generation', () => {
  const f = fixture('<button id="save">Save</button>');
  f.send({type: 'bind', binding});
  const c = command('element.press', {attemptId: 'attempt1', locator: {strategy: 'id', value: 'save'}});
  assert.equal(f.send({...c, identity: {...identity, documentId: 'doc2'}}).error.code, 'staleIdentity');
  assert.equal(f.send({...c, identity: {...identity, frameId: 1}}).error.code, 'staleIdentity');
  f.document.getElementById('save').textContent = 'Changed';
  assert.equal(f.send(c).error.code, 'staleGeneration');
  assert.ok(f.send(command('observe')).identity.documentGeneration > 1);
  assert.ok(f.send({type: 'bind', binding: {...binding, identity: {...identity, documentGeneration: 20}}}).identity.documentGeneration > 1);
  assert.equal(f.send(command('executor.quiesce')).quiescent, true);
  assert.equal(f.send(c).error.code, 'executorQuiesced');
});
test('schema rejects arbitrary code, expired dispatch and oversized frames', () => {
  const f = fixture('<button>Save</button>');
  const p = f.window.MechanizeProtocol;
  assert.throws(() => p.validate(command('eval', {args: {script: 'alert(1)'}})), e => e.code === 'unsupportedAction');
  assert.throws(() => p.validate(command('observe', {code: 'alert(1)'})), e => e.code === 'invalidRequest');
  assert.throws(() => p.validate(command('observe', {deadlineUnixMs: Date.now() - 1})), e => e.code === 'dispatchExpired');
  assert.throws(() => p.validate(command('observe', {args: {value: 'x'.repeat(256 * 1024)}})), e => e.code === 'frameTooLarge');
});
test('retired exact renderer authority rejects delayed input while fresh lease permits sequential steps', () => {
  const f = fixture('<button id="save">Save</button>');
  let clicks = 0; f.document.getElementById('save').addEventListener('click', () => clicks++);
  f.send({type: 'bind', binding: {...binding, leaseRequired: true}});
  const first = {id: 'first', generation: 1}, second = {id: 'second', generation: 2};
  const mutation = (lease, attemptId) => command('element.press', {controlLease: lease, attemptId, locator: {strategy: 'id', value: 'save'}});
  assert.equal(f.send(mutation(undefined, 'missing')).error.code, 'staleAuthority');
  assert.equal(f.send(command('executor.acquire', {controlLease: first})).validated, true);
  assert.equal(f.send(mutation(first, 'first-attempt')).dispatchState, 'dispatched');
  assert.equal(f.send(command('executor.retire', {controlLease: first})).retiredAuthorityQuiesced, true);
  assert.equal(f.send(mutation(first, 'delayed-old')).error.code, 'staleAuthority');
  assert.equal(f.send(command('executor.acquire', {controlLease: first})).error.code, 'staleAuthority');
  assert.equal(f.send(command('executor.acquire', {controlLease: second})).validated, true);
  assert.equal(f.send(mutation(second, 'second-attempt')).dispatchState, 'dispatched');
  assert.equal(clicks, 2);
  assert.equal(f.send(command('executor.retire', {controlLease: second})).retiredAuthorityQuiesced, true);
  assert.equal(f.send(command('executor.quiesce')).quiescent, true);
  assert.equal(f.send(command('executor.acquire', {controlLease: {id:'third', generation:3}})).error.code, 'executorQuiesced');
});
test('DOM navigation/generation invalidation prevents old admitted authority dispatch', () => {
  const f = fixture('<button id="save">Save</button>');
  f.send({type:'bind', binding:{...binding, leaseRequired:true}});
  const lease = {id:'one',generation:1};
  assert.equal(f.send(command('executor.acquire',{controlLease:lease})).validated,true);
  f.window.dispatchEvent(new f.window.Event('popstate'));
  assert.equal(f.send(command('element.press',{controlLease:lease,attemptId:'old',locator:{strategy:'id',value:'save'}})).error.code,'staleGeneration');
  assert.equal(f.send(command('executor.retire',{controlLease:lease})).retiredAuthorityQuiesced,true);
});

test('credentials appearing during dispatch withhold output and preserve unknown effect', () => {
  const f = fixture('<input id="case"><button id="open">Continue</button>');
  f.document.getElementById('case').addEventListener('input', () => {
    f.document.body.insertAdjacentHTML('beforeend', '<input type="password" value="post-dispatch-canary">');
    f.document.getElementById('case').value = 'reflected-canary';
  });
  assert.throws(() => f.api.act(f.document, 'element.fill', {strategy:'id',value:'case'}, {value:'ordinary'}),
    e => e.code === 'secureDocumentRequired' && e.dispatchState === 'unknown' && !JSON.stringify(e).includes('canary'));
  f.window.close();
});

test('post-login exact selectors handle large layout trees and preserve shadow uniqueness', () => {
 const f=fixture('<button id="history">History</button><div id="shadow-host"></div>');
 f.api.installPrivateDocumentRedactor(f.document, value=>String(value));
 f.document.body.insertAdjacentHTML('afterbegin','<div></div>'.repeat(2500));
 assert.equal(f.api.act(f.document,'read',{strategy:'id',value:'history'},{attribute:'text'}).value,'History');
 const shadow=f.document.getElementById('shadow-host').attachShadow({mode:'open'});
 shadow.innerHTML='<button id="history">Other History</button>';
 assert.throws(()=>f.api.resolve(f.document,{strategy:'id',value:'history'}),e=>e.code==='ambiguousTarget');
 shadow.innerHTML='<input type="password" id="private-field" value="SECRET-CANARY">';
 assert.equal(f.api.act(f.document,'read',{strategy:'id',value:'private-field'},{attribute:'value'}).value,'[redacted]');
 assert.throws(()=>f.api.act(f.document,'element.fill',{strategy:'id',value:'private-field'},{value:'new'}),e=>e.code==='secureDocumentRequired');
 f.window.close();
});

test('executor reinjection preserves the committed private output redactor', () => {
 const f=fixture('<button id="history">KNOWN-SECRET</button>');
 f.api.installPrivateDocumentRedactor(f.document,value=>String(value).replaceAll('KNOWN-SECRET','[redacted]'));
 f.window.eval(fs.readFileSync(path.join(__dirname,'..','dom.js'),'utf8'));
 assert.equal(f.window.MechanizeDOM,f.api);
 assert.equal(f.api.act(f.document,'read',{strategy:'id',value:'history'},{attribute:'text'}).value,'[redacted]');
 f.window.close();
});

test('protocol click geometry settles without animation frames in background tabs', async () => {
 const f=fixture('<button id="begin">Begin</button>');
 try {
  const el=f.document.querySelector('#begin');
  el.getBoundingClientRect=()=>({x:10,y:20,width:100,height:20});
  f.document.elementFromPoint=()=>el;
  f.window.requestAnimationFrame=()=>7;
  let cancelled=false;f.window.cancelAnimationFrame=id=>{cancelled=id===7;};
  const point=await f.api.protocolClickPoint(f.document,{strategy:'id',value:'begin'},Date.now()+1000);
  assert.deepEqual({...point},{x:60,y:30});assert.equal(cancelled,true);
 } finally {f.window.close();}
});

test('background geometry fallback still rejects motion obstruction and expired deadlines', async () => {
 for(const mode of ['motion','obstruction','expired']) {
  const f=fixture('<button id="begin">Begin</button><div id="cover"></div>');
  try {
   const el=f.document.querySelector('#begin');let reads=0;
   el.getBoundingClientRect=()=>({x:mode==='motion'?10+10*reads++:10,y:20,width:100,height:20});
   f.document.elementFromPoint=()=>mode==='obstruction'?f.document.querySelector('#cover'):el;
   f.window.requestAnimationFrame=()=>7;f.window.cancelAnimationFrame=()=>{};
   await assert.rejects(f.api.protocolClickPoint(f.document,{strategy:'id',value:'begin'},Date.now()+(mode==='expired'?1:1000)),e=>['targetNotActionable','dispatchExpired'].includes(e.code));
  } finally {f.window.close();}
 }
});

test('bounded snapshots prioritize visible controls over hidden dialogs without losing coverage',()=>{
 const f=fixture('<div hidden>'+Array.from({length:120},(_,i)=>`<button hidden id="hidden-${i}">Hidden ${i}</button>`).join('')+'</div><input id="search" aria-label="Search history">');
 try {
  const s=f.api.snapshot(f.document,{limit:3});
  assert.equal(s.nodes[0].id,'search');assert.equal(s.nodes.length,3);assert.equal(s.truncated,true);
  assert.equal(s.nodes[0].name,'Search history');assert.equal(s.nodes[0].visible,true);
 }finally {f.window.close();}
});

test('observed accessible name preserves rendered block boundaries for exact role resolution',()=>{
 const f=fixture('<a href="/next" id="next"><div>Upcoming items</div><div>1&nbsp;234 units</div></a><button><span>Save</span><span style="display:inline-block">changes</span></button>');
 const snapshot=f.api.snapshot(f.document);
 assert.equal(snapshot.nodes.find(n=>n.id==='next').name,'Upcoming items 1 234 units');
 assert.equal(f.api.resolve(f.document,{strategy:'role',value:'link',name:'Upcoming items 1 234 units',exact:true}).id,'next');
 assert.equal(snapshot.nodes.find(n=>n.role==='button').name,'Save changes');
 assert.throws(()=>f.api.resolve(f.document,{strategy:'role',value:'link',name:'Upcoming items1 234 units',exact:true}),e=>e.code==='targetNotFound');
 f.window.close();
});
test('name alternatives honor aria descendants hidden references line breaks and composed content',()=>{
 const f=fixture('<button id="nested">Open<span aria-label="details">ignored</span><span aria-hidden="true">hidden</span><br>now</button><span id="label" hidden>Hidden label</span><button id="reference" aria-labelledby="label">ignored</button><div role="button" id="host"></div>');
 f.document.getElementById('host').attachShadow({mode:'open'}).innerHTML='<div>Shadow</div><span>action</span>';
 const nodes=f.api.snapshot(f.document).nodes;
 assert.equal(nodes.find(n=>n.id==='nested').name,'Open details now');
 assert.equal(nodes.find(n=>n.id==='reference').name,'Hidden label');
 assert.equal(nodes.find(n=>n.id==='host').name,'Shadow action');
 f.window.close();
});
test('accessible name traversal never includes credential descendants or editable values',()=>{
 const f=fixture('<button id="safe">Public</button>');
 f.api.installPrivateDocumentRedactor(f.document,value=>String(value).replaceAll('KNOWN-CANARY','[redacted]'));
 f.document.getElementById('safe').innerHTML='<div>Public</div><span data-mechanize-secret>PRIVATE-CANARY</span><input value="EDITABLE-CANARY"><span>KNOWN-CANARY</span>';
 const output=JSON.stringify(f.api.snapshot(f.document));
 assert.ok(!output.includes('PRIVATE-CANARY'));assert.ok(!output.includes('KNOWN-CANARY'));
 const controlName=f.api.snapshot(f.document).nodes.find(node=>node.id==='safe').name;assert.equal(controlName,undefined);
 f.window.close();
});

test('business identifier is public while contextual login identifier remains protected',()=>{
 const f=fixture('<form><label for="business">Business identifier (optional)</label><input id="business" value="public-reference"></form>');
 assert.equal(f.api.snapshot(f.document).nodes.find(n=>n.id==='business').name,'Business identifier (optional)');
 assert.equal(f.api.privateDocumentReady(f.document),true);f.window.close();
 const g=fixture('<form><label for="account">Identifier</label><input id="account"><input type="password"></form>');
 assert.throws(()=>g.api.snapshot(g.document),e=>e.code==='secureDocumentRequired');g.window.close();
});
test('hidden OTP referenced by public label is ID-only without reading its value',()=>{
 const f=fixture('<button id="public">Safe</button>');
 f.api.installPrivateDocumentRedactor(f.document,v=>v);
 f.document.body.insertAdjacentHTML('beforeend','<input hidden id="otp" value="OTP-CANARY"><button id="ref" aria-labelledby="otp">Fallback</button>');
 Object.defineProperty(f.document.getElementById('otp'),'value',{get(){throw Error('private value read');}});
 const nodes=f.api.snapshot(f.document).nodes;
 assert.equal(nodes.find(n=>n.id==='ref').name,undefined);
 assert.throws(()=>f.api.resolve(f.document,{strategy:'role',value:'button',name:'Fallback',exact:true}),e=>e.code==='targetNotFound');
 assert.equal(f.api.resolve(f.document,{strategy:'id',value:'ref'}).id,'ref');f.window.close();
});

test('username-first identifiers require private route with local sign-in heading',()=>{
 for(const html of ['<form><h1>Sign in</h1><label for="account">Identifier</label><input id="account"></form>','<section><h2>Logowanie</h2><div><label for="account">Identyfikator</label><input id="account"></div></section>']){
  const f=fixture(html);assert.throws(()=>f.api.snapshot(f.document),e=>e.code==='secureDocumentRequired');assert.equal(f.api.privateDocumentReady(f.document),false);f.window.close();
 }
 const f=fixture('<h1>Sign in help</h1><form><h2>Business payment</h2><label for="reference">Identifier</label><input id="reference"></form>');
 assert.equal(f.api.snapshot(f.document).nodes.find(n=>n.id==='reference').name,'Identifier');f.window.close();
});

test('bounded dense snapshots put visible controls before structural rows in DOM order',()=>{
 const rows=Array.from({length:130},(_,i)=>`<div role="listitem" id="row-${i}">Record ${i}</div>`).join('');
 const f=fixture(`<button hidden id="hidden-first">Hidden action</button><div role="list">${rows}</div><section><input type="search" aria-label="Find records" id="search"></section><button id="apply">Apply filter</button><a href="/records" id="all">All records</a><select id="range" aria-label="Range"><option>All</option></select><h2 id="heading">Details</h2>`);
 try{
  const result=f.api.snapshot(f.document);
  assert.equal(result.nodes.length,100);assert.equal(result.truncated,true);
  assert.deepEqual(Array.from(result.nodes.slice(0,4),n=>n.id),['search','apply','all','range']);
  assert.equal(result.nodes.some(n=>n.id==='hidden-first'),false);
  const structural=result.nodes.filter(n=>n.role==='listitem');assert.deepEqual(Array.from(structural,n=>n.id),Array.from(structural,(_,i)=>`row-${i}`));
  assert.equal(f.api.resolve(f.document,{strategy:'role',value:'searchbox',name:'Find records',exact:true}).id,'search');
  assert.equal(f.api.snapshot(f.document,{limit:1}).nodes[0].id,'search');
  const full=f.api.snapshot(f.document,{limit:200});assert.equal(full.truncated,false);assert.equal(full.nodes.at(-1).id,'hidden-first');assert.deepEqual(Array.from(result.coverage),Array.from(full.coverage));
 }finally{f.window.close();}
});
test('control prioritization preserves private redaction and never reads hidden secret values',()=>{
 const f=fixture('<h1>Public records</h1>');
 try{
  f.api.installPrivateDocumentRedactor(f.document,value=>String(value).replaceAll('KNOWN-CANARY','[redacted]'));
  f.document.body.insertAdjacentHTML('beforeend','<div role="listitem">Row</div>'.repeat(130)+'<input type="search" id="query" aria-label="Find records"><button id="known">KNOWN-CANARY</button><input hidden type="password" id="password" aria-label="HIDDEN-CANARY">');
  let secretReads=0;Object.defineProperty(f.document.getElementById('password'),'value',{get(){secretReads++;throw Error('SECRET-VALUE-CANARY');}});
  for(const limit of [100,200]){const result=f.api.snapshot(f.document,{limit});assert.equal(result.nodes[0].id,'query');assert.ok(!JSON.stringify(result).includes('CANARY'));assert.equal(secretReads,0);}
 }finally{f.window.close();}
 const masked=fixture('<div role="listitem">Row</div>'.repeat(130)+'<input type="search" aria-label="Find records"><input hidden type="password" id="password" value="PRIVATE-CANARY">');
 try{Object.defineProperty(masked.document.querySelector('#password'),'value',{get(){throw Error('secret read')}});const snapshot=masked.api.snapshot(masked.document);assert.ok(snapshot.nodes.some(n=>n.name==='Find records'));assert.ok(!JSON.stringify(snapshot).includes('CANARY'));assert.equal(masked.api.act(masked.document,'read',{strategy:'id',value:'password'},{attribute:'value'}).value,'[redacted]');}finally{masked.window.close();}
});

test('role discovery includes implicit main dialog and all heading levels',()=>{
 const f=fixture('<main aria-label="Workspace"></main><dialog style="display:block" aria-label="Details"></dialog><h3>Third heading</h3><h6>Sixth heading</h6>');
 for(const [role,name,tag] of [['main','Workspace','MAIN'],['dialog','Details','DIALOG'],['heading','Third heading','H3'],['heading','Sixth heading','H6']])assert.equal(f.api.resolve(f.document,{strategy:'role',value:role,name,exact:true}).tagName,tag);
 f.window.close();
});
test('direct and unnamed role resolution do not build name projection',()=>{
 const f=fixture('<button id="direct" data-testid="button">Action</button><main></main>');let calls=0;
 f.window.MechanizeAccessibility={...f.window.MechanizeAccessibility,createProjection:()=>{calls++;throw Error('projectionLimit');}};
 for(const locator of [{strategy:'id',value:'direct'},{strategy:'testId',value:'button'},{strategy:'css',value:'#direct'},{strategy:'role',value:'main',exact:true}])assert.ok(f.api.resolve(f.document,locator));
 assert.equal(calls,0);
 assert.throws(()=>f.api.resolve(f.document,{strategy:'role',value:'heading',name:'Absent',exact:true}),e=>e.code==='targetNotFound');assert.equal(calls,0);
 assert.throws(()=>f.api.resolve(f.document,{strategy:'role',value:'button',name:'Action',exact:true}),e=>e.code==='coverageIncomplete');assert.equal(calls,1);
 f.window.close();
});
test('privacy gate remains required before lazy direct resolution',()=>{
 const f=fixture('<input type="password"><button id="target">Action</button>');let calls=0;f.window.MechanizeAccessibility={...f.window.MechanizeAccessibility,createProjection:()=>{calls++;}};
 assert.throws(()=>f.api.resolve(f.document,{strategy:'id',value:'target'}),e=>e.code==='secureDocumentRequired');assert.equal(calls,0);f.window.close();
});

test('public placeholder fallback preserves labels and withholds private placeholders',()=>{
 const f=fixture('<input id="search" placeholder="Search public items"><textarea id="note" placeholder="Public note"></textarea><input id="labelled" aria-label="Preferred label" placeholder="Fallback">');
 assert.equal(f.api.snapshot(f.document).nodes.find(n=>n.id==='search').name,'Search public items');
 assert.equal(f.api.resolve(f.document,{strategy:'role',value:'textbox',name:'Search public items',exact:true}).id,'search');
 assert.equal(f.api.snapshot(f.document).nodes.find(n=>n.id==='note').name,'Public note');assert.equal(f.api.snapshot(f.document).nodes.find(n=>n.id==='labelled').name,'Preferred label');
 f.api.installPrivateDocumentRedactor(f.document,v=>String(v).replaceAll('KNOWN-CANARY','[redacted]'));
 f.document.body.insertAdjacentHTML('beforeend','<input id="ordinary" placeholder="KNOWN-CANARY"><input hidden id="otp" placeholder="PRIVATE-CANARY">');
 const output=JSON.stringify(f.api.snapshot(f.document));assert.ok(!output.includes('KNOWN-CANARY'));assert.ok(!output.includes('PRIVATE-CANARY'));assert.equal(f.api.snapshot(f.document).nodes.find(n=>n.id==='ordinary').name,undefined);f.window.close();
});

test('explicit textarea values preserve long Unicode and whitespace through content replies',t=>{
 const f=fixture('<label for="composer">Prompt</label><textarea id="composer"></textarea>');t.after(()=>f.window.close());
 const value='  \n\t'+('Zażółć 😀 public prompt\n  '.repeat(30))+'\t  ';
 f.document.getElementById('composer').value=value;f.send({type:'bind',binding});
 const reply=f.send(command('read',{locator:{strategy:'id',value:'composer'},args:{attribute:'value'}}));
 assert.equal(reply.value,value);assert.equal(reply.valueReadVersion,1);assert.equal(reply.valueReadBytes,Buffer.byteLength(value));
 const input=f.api.snapshot(f.document).nodes.find(n=>n.id==='composer');
 assert.equal(input.value,value.replace(/\s+/g,' ').trim().slice(0,256));
 assert.equal(f.api.act(f.document,'read',{strategy:'id',value:'composer'},{attribute:'name'}).value,'Prompt');
});
test('exact value limit uses UTF-8 bytes and oversized values never return a prefix',t=>{
 const f=fixture('<textarea id="composer"></textarea>');t.after(()=>f.window.close());f.send({type:'bind',binding});
 const read=()=>f.send(command('read',{locator:{strategy:'id',value:'composer'},args:{attribute:'value'}}));
 for(const value of ['', 'x'.repeat(256), '😀'.repeat(8192), '\t'.repeat(32768)]){
  f.document.getElementById('composer').value=value;const reply=read();
  assert.equal(reply.value,value);assert.equal(reply.valueReadBytes,Buffer.byteLength(value));assert.equal(reply.valueReadVersion,1);
 }
 for(const value of ['😀'.repeat(8192)+'x','x'.repeat(32769)]){
  f.document.getElementById('composer').value=value;const reply=read();
  assert.equal(reply.error.code,'readTooLarge');assert.equal(reply.error.dispatchState,'notDispatched');
  for(const key of ['value','valueReadVersion','valueReadBytes'])assert.equal(Object.hasOwn(reply,key),false);
 }
});
test('exact value reads redact before counting and retain sensitive-field denial',t=>{
 const f=fixture('<textarea id="composer"></textarea>');t.after(()=>f.window.close());
 f.api.installPrivateDocumentRedactor(f.document,value=>String(value).replaceAll('PRIVATE-CANARY','[redacted]'));
 const value=' \n'+('public '.repeat(60))+'PRIVATE-CANARY\t  ';f.document.getElementById('composer').value=value;
 const reply=f.api.act(f.document,'read',{strategy:'id',value:'composer'},{attribute:'value'});
 assert.equal(reply.value,value.replaceAll('PRIVATE-CANARY','[redacted]'));assert.equal(reply.valueReadBytes,Buffer.byteLength(reply.value));assert.equal(JSON.stringify(reply).includes('PRIVATE-CANARY'),false);
 f.document.body.insertAdjacentHTML('beforeend','<input id="password" type="password" value="OTHER-CANARY">');
 const denied=f.api.act(f.document,'read',{strategy:'id',value:'password'},{attribute:'value'});
 assert.equal(denied.value,'[redacted]');assert.equal(JSON.stringify(denied).includes('OTHER-CANARY'),false);
 const unpromoted=fixture('<textarea id="composer">PUBLIC</textarea><input type="password" value="OTHER-CANARY">');t.after(()=>unpromoted.window.close());
 assert.throws(()=>unpromoted.api.act(unpromoted.document,'read',{strategy:'id',value:'composer'},{attribute:'value'}),e=>e.code==='secureDocumentRequired'&&!JSON.stringify(e).includes('CANARY'));
});
test('redaction expansion is bounded and text reads keep snapshot semantics',t=>{
 const f=fixture('<textarea id="composer"></textarea><p id="paragraph"></p>');t.after(()=>f.window.close());
 f.api.installPrivateDocumentRedactor(f.document,value=>String(value).replaceAll('A','[redacted]'));
 f.document.getElementById('composer').value='A'.repeat(4000);
 assert.throws(()=>f.api.act(f.document,'read',{strategy:'id',value:'composer'},{attribute:'value'}),e=>e.code==='readTooLarge');
 f.document.getElementById('paragraph').textContent='  \n'+('public\t '.repeat(100));
 const text=f.api.act(f.document,'read',{strategy:'id',value:'paragraph'},{attribute:'text'});
 assert.equal(text.value.length,256);assert.equal(Object.hasOwn(text,'valueReadVersion'),false);
});
