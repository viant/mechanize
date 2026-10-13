const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {JSDOM} = require('jsdom');
function fixture(response = {connected:true}, failure = '', setupURL = '', options = {}) {
  const page = new JSDOM(fs.readFileSync(path.join(__dirname, '..', 'options.html'), 'utf8'));
  const document = page.window.document;
  document.getElementById('channel').value = 'profile1';
  document.getElementById('instance').value = 'browser1';
  document.getElementById('origins').value = 'https://fixture.example.test';
  document.getElementById('all-sites').checked = false;
  document.getElementById('selected-sites').checked = true;
  let connectClick, saveClick, enabledChange, onMessage, reloadClick, openWebsiteClick, accessibilityClick;
  let state = {enrollment: {profileChannel:"profile1",browserInstance:"browser1",origins:["https://fixture.example.test"]}};
  if (options.state) state = options.state;
  if (options.emptyFields) for (const id of ["channel", "instance", "origins"]) document.getElementById(id).value="";
  let granted = options.granted === true;
  let permissionAdded, permissionRemoved, storageChanged;
  const sent = [];
  const saved = [], requested = [];
  document.getElementById('enroll').addEventListener = (type, listener) => { if(type==='click') saveClick=listener; };
  document.getElementById('connect').addEventListener = (type, listener) => { if(type==='click') connectClick=listener; };
  document.getElementById('connection-enabled').addEventListener = (type, listener) => { if(type==='change') enabledChange=listener; };
  document.getElementById('reload-extension').addEventListener = (type, listener) => { if(type==='click') reloadClick=listener; };
  document.getElementById('open-accessibility').addEventListener = (type, listener) => { if(type==='click') accessibilityClick=listener; };
  document.getElementById('open-website').addEventListener = (type, listener) => { if(type==='click') openWebsiteClick=listener; };
  const chrome = {
    permissions:{onAdded:{addListener(fn){permissionAdded=fn;}},onRemoved:{addListener(fn){permissionRemoved=fn;}},async contains(){return granted;},async request(value) {requested.push(value); if(failure==='permissions') throw Error('private-credential-secret'); granted = failure!=='denied'; return granted;}},
    storage:{onChanged:{addListener(fn){storageChanged=fn;}},local:{async get(){return state;},async set(value) {if(failure==='storage') throw Error('private-credential-secret'); saved.push(value); state={...state,...value};}}},
    runtime:{id:'extension', getURL:value=>`chrome-extension://extension/${value}`, onMessage:{addListener(listener){onMessage=listener;}},
      async sendMessage(message) {sent.push(message); if(message.type==='connectionStatusLocal')return options.connectionStatus || {connected:false,enabled:true,qualified:false,retryScheduled:false,attentionCode:'none'}; if(failure==='message') throw Error('private-credential-secret'); return typeof response==='function'?response(onMessage):response;}}
  };
  const globals = {document, chrome, URL, URLSearchParams};
  setupURL ||= 'chrome-extension://extension/options.html';
  if (setupURL) { globals.location = new URL(setupURL); globals.history = {replaceState(_state,_title,url) { globals.location = new URL(url); }}; }
  const context = vm.createContext(globals);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'protocol.js'), 'utf8'), context);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'options.js'), 'utf8'), context);
  return {page, chrome, saved, requested, sent, permissionAdded, permissionRemoved, storageChanged, click:(event={isTrusted:true})=>connectClick(event), saveClick:(event={isTrusted:true})=>saveClick(event), enabledChange:(event={isTrusted:true})=>enabledChange(event), state:()=>state, setState:value=>{state=value;}, setGranted:value=>{granted=value;}, reloadClick, openWebsiteClick, accessibilityClick, onMessage, status:()=>document.getElementById('status').textContent};
}
const worker = {id:'extension', url:'chrome-extension://extension/worker.js'};
test('website bootstrap requires trusted activation, existing scope and origin-only public URL',async()=>{
 for(const mode of ['valid','synthetic','foreign','scope','permission','userinfo','query','fragment','path','scheme','failure']){
  const f=fixture({},'',mode==='foreign'?'https://foreign.example/options.html':'chrome-extension://extension/options.html'),opened=[];
  const origin='https://fixture.example.test';
  f.chrome.storage.local.get=async()=>({enrollment:{profileChannel:'fixture',browserInstance:'browser',origins:mode==='scope'?['https://other.example.test']:[origin]}});
  f.chrome.permissions.contains=async()=>mode!=='permission';
  f.chrome.tabs={async create(tab){if(mode==='failure')throw Error('PRIVATE_CANARY');opened.push(tab);return {id:7};}};
  const addresses={userinfo:'https://user:PRIVATE_CANARY@fixture.example.test/',query:origin+'/?secret=PRIVATE_CANARY',fragment:origin+'/#PRIVATE_CANARY',path:origin+'/PRIVATE_CANARY',scheme:'chrome://settings/'};
  f.page.window.document.getElementById('website-origin').value=addresses[mode]||origin;
  await f.openWebsiteClick({isTrusted:mode!=='synthetic'});
  assert.equal(opened.length,mode==='valid'?1:0,mode);
  if(mode==='valid')assert.deepEqual(JSON.parse(JSON.stringify(opened)),[{url:origin+'/',active:false}]);
  assert.equal(f.saved.length,0);assert.equal(f.requested.length,0);
  assert.doesNotMatch(f.page.window.document.getElementById('open-website-status').textContent,/PRIVATE_CANARY/);
  f.page.window.close();
 }
});
test('extension reload requires trusted own-page activation and opens only its management page',async()=>{
 for(const address of ['chrome-extension://extension/options.html','https://foreign.example/options.html','chrome-extension://foreign/options.html']){
  const f=fixture({connected:true},'',address),opened=[];let reloads=0;
  f.chrome.tabs={async create(tab){opened.push(tab);}};f.chrome.runtime.reload=()=>{reloads++;};
  await f.reloadClick({isTrusted:false});assert.equal(reloads,0);assert.equal(opened.length,0);
  await f.reloadClick({isTrusted:true});
  assert.equal(reloads,address==='chrome-extension://extension/options.html'?1:0);
  if(reloads)assert.deepEqual(JSON.parse(JSON.stringify(opened)),[{url:'chrome://extensions/?id=extension',active:true}]);
  assert.equal(f.saved.length,0);assert.equal(f.requested.length,0);f.page.window.close();
 }
});
test('connection diagnostics render only closed metadata and discard stale details on failure', async () => {
  let response={diagnostics:{version:3,journalVersion:1,grantRelation:'old',phase:'journal',reason:'none',credentialProtection:false,lifecyclePending:false,retirementPending:false,reconnectJournal:'pending'}};
  const f=fixture(()=>response),doc=f.page.window.document;
  try {
    doc.getElementById('read-connection-diagnostics').click();
    await new Promise(resolve=>setImmediate(resolve));
    assert.equal(doc.getElementById('connection-diagnostics').getAttribute('aria-label'),'Connection diagnostics ready');
    assert.match(doc.getElementById('connection-diagnostics-detail').getAttribute('aria-label'),/Reconnect journal: pending/);
    assert.equal(f.saved.length,0);assert.equal(f.requested.length,0);
    for(const version of [2,3,4,5,6]){
      response.diagnostics.journalVersion=version;
      doc.getElementById('read-connection-diagnostics').click();await new Promise(resolve=>setImmediate(resolve));
      assert.equal(doc.getElementById('connection-diagnostics').getAttribute('aria-label'),'Connection diagnostics ready');
      assert.ok(doc.getElementById('connection-diagnostics-detail').textContent.includes(`Journal version: ${version}.`));
    }
    for(const bad of [{...response.diagnostics,journalVersion:7},{...response.diagnostics,phase:'PRIVATE_CANARY'},{...response.diagnostics,extra:'PRIVATE_CANARY'},{...response.diagnostics,credentialProtection:'PRIVATE_CANARY'}]) {
      response={diagnostics:bad};
      doc.getElementById('read-connection-diagnostics').click();
      await new Promise(resolve=>setImmediate(resolve));
      assert.equal(doc.getElementById('connection-diagnostics').getAttribute('aria-label'),'Connection diagnostics unavailable');
      assert.equal(doc.getElementById('connection-diagnostics-detail').textContent,'');
      assert.doesNotMatch(doc.body.textContent,/PRIVATE_CANARY/);
    }
  } finally {f.page.window.close();}
});
test('connection failure codes use only fixed public descriptions', async () => {
  const cases = {
    hostNotRegistered: /cannot find/, hostLaunchFailed: /could not start/,
    hostExited: /stopped/, hostAccessDenied: /refused access/,
    lifecycleInhibited: /held for recovery/, enrollmentUnavailable: /details are unavailable/,
    'private-credential-secret': /disconnected/, toString: /disconnected/
  };
  for (const [attentionCode, expected] of Object.entries(cases)) {
    const f=fixture({connected:false,attentionCode,message:'private-credential-secret'});
    await f.click(); assert.match(f.status(),expected);
    assert.doesNotMatch(f.status(),/private-credential-secret/);
    f.onMessage({type:'nativeConnectionStatus',connected:false,attentionCode,message:'private-credential-secret'},worker);
    assert.match(f.status(),expected); assert.doesNotMatch(f.status(),/private-credential-secret/);
    f.page.window.close();
  }
});
test('all websites requests HTTP and HTTPS once and stores only explicit scope metadata', async () => {
  const f=fixture();
  f.page.window.document.getElementById('all-sites').checked=true;
  await f.saveClick();
  assert.deepEqual(Array.from(f.requested[0].origins), ['https://*/*','http://*/*']);
  assert.equal(f.saved[0].enrollment.allWebsites,true);
  assert.equal(f.saved[0].enrollment.origins.length,0);
  assert.equal(JSON.stringify(f.saved).includes('credential'),false);
  f.page.window.close();
});
test('all-site setup hint does not grant permissions and hides the per-site list', () => {
  const query=new URLSearchParams({channel:'desktop-123',instance:'chrome-123',access:'all'});
  const f=fixture({connected:true},'',`chrome-extension://extension/options.html#${query}`);
  assert.equal(f.page.window.document.getElementById('all-sites').checked,true);
  assert.equal(f.page.window.document.getElementById('origins').disabled,true);
  assert.equal(f.page.window.document.getElementById('selected-websites').hidden,true);
  assert.equal(f.requested.length,0); assert.equal(f.saved.length,0);
  f.page.window.close();
});
test('scope mismatch diagnostics are static and only accepted from the trusted worker', async () => {
  const f=fixture(); await f.click();const before=f.status();
  f.onMessage({type:'nativeConnectionStatus',connected:true,attentionCode:'websiteScopeMismatch'}, {id:'foreign',url:worker.url});
  assert.equal(f.status(),before);
  f.onMessage({type:'nativeConnectionStatus',connected:true,attentionCode:'websiteScopeMismatch',message:'private-credential-secret'},worker);
  assert.match(f.status(),/local browser scope/); assert.doesNotMatch(f.status(),/private-credential-secret/);
  f.page.window.close();
});
test('a delayed true connection reply cannot overwrite a scope mismatch', async () => {
  const f=fixture(onMessage=>{onMessage({type:'nativeConnectionStatus',connected:true,attentionCode:'websiteScopeMismatch'},worker);return {connected:true};});
  await f.click();assert.match(f.status(),/local browser scope/);assert.doesNotMatch(f.status(),/connection opened/);
  f.page.window.close();
});
test('disconnect after scope refusal preserves the cause until a new attempt', async () => {
  const f=fixture(onMessage=>{
    onMessage({type:'nativeConnectionStatus',connected:true,attentionCode:'websiteScopeMismatch'},worker);
    onMessage({type:'nativeConnectionStatus',connected:false,attentionCode:'hostExited'},worker);
    return {connected:false};
  });
  await f.click();assert.match(f.status(),/local browser scope/);
  f.chrome.runtime.sendMessage=async()=>({connected:false,attentionCode:'hostNotRegistered'});
  await f.click();assert.match(f.status(),/cannot find/);assert.doesNotMatch(f.status(),/local browser scope/);
  f.page.window.close();
});
test('options saves public enrollment separately from pending broker connection authority', async () => {
  const f=fixture();
  await f.saveClick();
  assert.equal(f.sent.filter(m=>m.type==='connect').length,0);
  await f.click();
  assert.match(f.status(), /Native host connection opened/);
  assert.match(f.status(), /broker authorization is still required/);
  assert.equal(f.page.window.document.getElementById('status').getAttribute('aria-label'),f.status());
  assert.equal(f.page.window.document.getElementById('status').dataset.state,'pending');
  assert.equal(f.saved.length,1);
  assert.equal(Object.keys(f.saved[0].enrollment).sort().join(), 'browserInstance,origins,profileChannel');
  assert.equal(JSON.stringify(f.saved).includes('credential'),false);
  f.page.window.close();
});
test('false, absent, malformed and rejected connection replies never claim connected success', async () => {
  for(const [response,failure] of [[{connected:false},''],[()=>undefined,''],[{},''],[{connected:'true'},''],[{connected:true},'message']]) {
    const f=fixture(response,failure);
    await f.click(); assert.match(f.status(), /disconnected/);
    assert.equal(f.page.window.document.getElementById('status').getAttribute('aria-label'),f.status());
    assert.equal(f.page.window.document.getElementById('status').dataset.state,'error');
    assert.doesNotMatch(f.status(), /connection opened|private-credential-secret/);
    f.page.window.close();
  }
});
test('refused setup context is distinguished from a native host that disconnected', async () => {
  const f=fixture({connected:false,attentionCode:'setupContextUnqualified',privateValue:'DO-NOT-DISPLAY'});
  await f.click();
  assert.match(f.status(), /native host was not opened/);
  assert.doesNotMatch(f.status(), /Native host disconnected|DO-NOT-DISPLAY/);
  assert.equal(f.page.window.document.getElementById('status').dataset.state,'error');
  f.page.window.close();
});
test('native disconnection updates status; web and foreign messages cannot', async () => {
  const f=fixture(); await f.click(); const connected=f.status();
  for(const sender of [{id:'foreign',url:worker.url},{id:'extension',url:'https://fixture.example.test'},{id:'extension',url:'chrome-extension://extension/options.html'},null]) {
    f.onMessage({type:'nativeConnectionStatus',connected:false},sender);
    assert.equal(f.status(),connected);
  }
  f.onMessage({type:'nativeConnectionStatus',connected:false,credential:'private-credential-secret'},worker);
  assert.match(f.status(), /disconnected/); assert.doesNotMatch(f.status(), /private-credential-secret/);
  f.page.window.close();
});
test('a disconnect during pending connect cannot be overwritten by a delayed true reply', async () => {
  const f=fixture(onMessage=>{onMessage({type:'nativeConnectionStatus',connected:false},worker);return {connected:true};});
  await f.click(); assert.match(f.status(), /disconnected/); assert.doesNotMatch(f.status(), /connection opened/);
  f.page.window.close();
});
test('unexpected permission and storage exceptions do not expose credential details in DOM', async () => {
  for(const failure of ['permissions','storage']) {
    const f=fixture({connected:true},failure); await f.saveClick();
    const access=f.page.window.document.getElementById('website-access-status').textContent;
    assert.match(access, /could not be saved/); assert.doesNotMatch(access, /private-credential-secret/);
    f.page.window.close();
  }
  const denied=fixture({connected:true},'denied'); await denied.saveClick();
  assert.equal(denied.page.window.document.getElementById('website-access-status').textContent,'Website permission denied'); assert.equal(denied.saved.length,0); denied.page.window.close();
});

test('public setup hints prefill without permissions, writes or connection and remove the fragment', () => {
  const query = new URLSearchParams({channel:'desktop-123',instance:'chrome-123',origins:'http://127.0.0.1:18771'});
  const f=fixture({connected:true},'',`chrome-extension://extension/options.html#${query}`);
  assert.equal(f.page.window.document.getElementById('channel').value,'desktop-123');
  assert.equal(f.page.window.document.getElementById('origins').value,'http://127.0.0.1:18771');
  assert.equal(f.requested.length,0); assert.equal(f.saved.length,0);
  assert.match(f.status(), /details prepared/); f.page.window.close();
});
test('foreign, duplicate, secret, path and invalid-origin setup hints leave fields unchanged', () => {
  const valid='channel=public-channel&instance=public-browser&origins=https%3A%2F%2Ffixture.example.test';
  for (const url of [
    `https://fixture.example.test/options.html#${valid}`,
    `chrome-extension://extension/options.html#${valid}&channel=other`,
    `chrome-extension://extension/options.html#${valid}&password=credential-canary`,
    `chrome-extension://extension/options.html#channel=public&instance=public&origins=https%3A%2F%2Ffixture.example.test%2Fpath`,
    `chrome-extension://extension/options.html#channel=public&instance=public&origins=https%3A%2F%2Fuser%3Acredential-canary%40fixture.example.test`,
  ]) {
    const f=fixture({connected:true},'',url);
    assert.equal(f.page.window.document.getElementById('channel').value,'profile1');
    assert.equal(f.requested.length,0); assert.equal(f.saved.length,0);
    assert.doesNotMatch(f.status(), /credential-canary/); assert.match(f.status(), /Setup link unavailable/);
    f.page.window.close();
  }
});


test('setup metadata renders only approved projection without permissions or enrollment writes', async () => {
  const metadata={version:1,extensionId:'a'.repeat(32),storageSHA256:'b'.repeat(64),storageScope:'extension-local-v1',storageStable:true,activeCommands:0,unknownAttempts:2,mutationBusy:false,lifecycleInhibited:true,nativeConnected:false,executorQualified:false,privateValue:'DO-NOT-DISPLAY'};
  const f=fixture({metadata});f.chrome.runtime.id='a'.repeat(32);
  f.page.window.document.getElementById('read-setup-metadata').click();await new Promise(resolve=>setImmediate(resolve));
  const shown=f.page.window.document.getElementById('setup-metadata').textContent;
  assert.equal(f.page.window.document.getElementById('setup-metadata').getAttribute('aria-label'),'Setup metadata ready');
  assert.ok(shown.includes('b'.repeat(64)));assert.ok(shown.includes('Unknown attempts: 2'));assert.equal(shown.includes('DO-NOT-DISPLAY'),false);
  assert.equal(f.requested.length,0);assert.equal(f.saved.length,0);f.page.window.close();
});

test('setup metadata failure exposes a fixed accessible state without response contents', async () => {
  const f=fixture({metadata:{privateValue:'DO-NOT-DISPLAY'}});
  const view=f.page.window.document.getElementById('setup-metadata');
  f.page.window.document.getElementById('read-setup-metadata').click();
  assert.equal(view.getAttribute('aria-label'),'Setup metadata reading');
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(view.getAttribute('aria-label'),'Setup metadata unavailable');
  assert.equal(view.textContent.includes('DO-NOT-DISPLAY'),false);
  assert.equal(f.requested.length,0);assert.equal(f.saved.length,0);
  f.page.window.close();
});

test('native startup diagnostics have fixed descriptions and preserve cause over generic exit',async()=>{
 const codes={brokerPeerUnavailable:/identify the local connector/,brokerPeerAuditUnavailable:/read the local connector/,brokerProcessUnqualified:/rejected the local connector/,brokerHelloUnavailable:/valid connection handshake/,brokerHelloRejected:/rejected the connection handshake/,brokerEnrollmentRefused:/saved connector enrollment/,brokerChannelBusy:/active connector/,brokerScopeUnqualified:/saved browser scope/,brokerHandshakeUnavailable:/complete the broker handshake/,configUnavailable:/configuration/,processTrustUnavailable:/Chrome process/,launchScopeUnavailable:/launch scope/,
 socketUnavailable:/broker connection/,brokerUnavailable:/broker is unavailable/,brokerTrustUnavailable:/signing identity/,
 enrollmentCredentialUnavailable:/enrollment credential/,helloIdentityMismatch:/identity does not match/,nativeHostStartupUnavailable:/unrecognized startup/};
 for(const [attentionCode,expected] of Object.entries(codes)){
  const f=fixture({connected:false,attentionCode,message:'PASSWORD-CANARY'});await f.click();assert.match(f.status(),expected);
  f.onMessage({type:'nativeConnectionStatus',connected:false,attentionCode:'hostExited'},worker);assert.match(f.status(),expected);
  f.onMessage({type:'nativeConnectionStatus',connected:false,attentionCode:'PASSWORD-CANARY'},worker);assert.match(f.status(),expected);assert.doesNotMatch(f.status(),/CANARY/);
  f.chrome.runtime.sendMessage=async()=>({connected:false,attentionCode:'hostNotRegistered'});await f.click();assert.match(f.status(),/cannot find/);f.page.window.close();
 }
});
test('non-string diagnostic cannot invoke arbitrary conversion or expose payload',()=>{
 const f=fixture();const hostile={toString(){throw Error('PASSWORD-CANARY');}};
 assert.doesNotThrow(()=>f.onMessage({type:'nativeConnectionStatus',connected:false,attentionCode:hostile},worker));
 assert.match(f.status(),/disconnected/);assert.doesNotMatch(f.status(),/CANARY/);f.page.window.close();
});

test('precise process diagnostics remain fixed accessible status after attempt processing',async()=>{
 const codes={runningImageMismatch:/does not match the enrolled executable/,nativeHostSignatureUnavailable:/installed signature/,
 chromeSignatureUnavailable:/Chrome’s signing identity/,nativeHostProcessUnavailable:/process identity could not be read/,
 nativeHostUIDUnavailable:/unexpected user/,nativeHostDynamicSignatureUnavailable:/running connector’s signing identity/,
 chromeAncestryUnavailable:/Chrome process ancestry/,chromeParentUnavailable:/direct Chrome parent/,
 ancestryChanged:/ancestry changed during verification/};
 for(const [attentionCode,expected] of Object.entries(codes)){
  const f=fixture({connected:false,attentionCode,message:'PRIVATE-CANARY'});await f.click();
  const status=f.page.window.document.getElementById('status');
  assert.match(f.status(),expected);assert.equal(status.getAttribute('aria-label'),f.status());
  assert.equal(status.getAttribute('aria-live'),'polite');assert.equal(status.getAttribute('aria-atomic'),'true');
  assert.equal(status.dataset.processedAttempt,'1');assert.doesNotMatch(status.getAttribute('aria-label'),/attempt.*processed|PRIVATE-CANARY/);
  f.onMessage({type:'nativeConnectionStatus',connected:false,attentionCode:'hostExited'},worker);
  assert.match(f.status(),expected);assert.equal(status.getAttribute('aria-label'),f.status());f.page.window.close();
 }
});
test('later connection status updates accessible diagnostic independently from attempt count',async()=>{
 const f=fixture();await f.click();const status=f.page.window.document.getElementById('status');
 assert.equal(status.dataset.processedAttempt,'1');assert.equal(status.getAttribute('aria-label'),f.status());
 f.onMessage({type:'nativeConnectionStatus',connected:false,attentionCode:'nativeHostProcessUnavailable'},worker);
 assert.match(status.getAttribute('aria-label'),/process identity could not be read/);assert.equal(status.dataset.processedAttempt,'1');f.page.window.close();
});

test('local accessibility maintenance opens only fixed Chrome page after trusted options click',async()=>{
 for(const mode of ['trusted','synthetic','foreign']) {
  const f=fixture(undefined,undefined,mode==='foreign'?'https://foreign.invalid/':'chrome-extension://extension/options.html');
  const opened=[];f.chrome.tabs={async create(value){opened.push(value);}};
  await f.accessibilityClick({isTrusted:mode!=='synthetic'});
  assert.equal(opened.length,mode==='trusted'?1:0);
  if(opened.length)assert.equal(opened[0].url,'chrome://accessibility/');
 }
});
test('new Connect attempts clear prior diagnostic snapshots even before worker messaging',async()=>{
 for(const mode of ['permission','invalidFields','valid']){
  const f=fixture({connected:true},mode==='permission'?'denied':'');
  try{
   const doc=f.page.window.document;doc.getElementById('connection-diagnostics').textContent='Connection diagnostics ready.';doc.getElementById('connection-diagnostics-detail').textContent='Reconnect phase: idle. Reason: none. Reconnect journal: pending. Journal version: 3.';
   if(mode==='invalidFields')f.setState({});
   await f.click();assert.equal(doc.getElementById('connection-diagnostics-detail').textContent,'');assert.equal(doc.getElementById('connection-diagnostics').getAttribute('aria-label'),'Connection diagnostics not read');
   if(mode!=='valid')assert.equal(f.saved.length,0);
  }finally{f.page.window.close();}
 }
});
test('closed inventory subreason explains omitted tab metadata without exposing tab details',async()=>{
 const base={version:3,journalVersion:3,grantRelation:'old',phase:'inventory',reason:'inventoryChanged',credentialProtection:true,lifecyclePending:false,retirementPending:false,reconnectJournal:'pending'};
 let response={diagnostics:{...base,inventoryReason:'tabURLUnavailable'}};const f=fixture(()=>response),doc=f.page.window.document;
 try{
  doc.getElementById('read-connection-diagnostics').click();await new Promise(resolve=>setImmediate(resolve));
  assert.match(doc.getElementById('connection-diagnostics-detail').textContent,/Inventory reason: tabURLUnavailable/);assert.match(doc.getElementById('connection-diagnostics-detail').textContent,/Chrome withheld a tab URL/);assert.equal(f.saved.length,0);
  response={diagnostics:{...base,inventoryReason:'PRIVATE_CANARY'}};doc.getElementById('read-connection-diagnostics').click();await new Promise(resolve=>setImmediate(resolve));assert.equal(doc.getElementById('connection-diagnostics-detail').textContent,'');assert.doesNotMatch(doc.body.textContent,/PRIVATE_CANARY/);
 }finally{f.page.window.close();}
});

const settle = () => new Promise(resolve => setImmediate(resolve));
test('saved approved scope loads without permission prompts or connection mutations', async () => {
  const f=fixture(undefined,undefined,undefined,{granted:true,emptyFields:true});
  try {
    await settle();
    const doc=f.page.window.document;
    assert.equal(doc.getElementById('channel').value,'profile1');
    assert.equal(doc.getElementById('origins').value,'https://fixture.example.test');
    assert.equal(doc.getElementById('connection-enabled').checked,true);
    assert.match(doc.getElementById('website-access-status').textContent,/approved in Chrome/);
    assert.equal(f.requested.length,0);assert.equal(f.saved.length,0);
    assert.deepEqual(f.sent.map(m=>m.type),['connectionStatusLocal']);
    await f.saveClick();await f.saveClick();
    assert.equal(f.requested.length,0);
    assert.equal(f.saved.length,2);
    assert.deepEqual(f.sent.map(m=>m.type),['connectionStatusLocal']);
  } finally {f.page.window.close();}
});
test('connect retries only saved enrollment and neither saves drafts nor requests permission',async()=>{
  const f=fixture(undefined,undefined,undefined,{granted:true});
  try {
    const doc=f.page.window.document;
    doc.getElementById('channel').value='';doc.getElementById('instance').value='UNSAVED';
    doc.getElementById('origins').value='https://unsaved.example.test';
    await f.click();await f.click();
    assert.equal(f.saved.length,0);assert.equal(f.requested.length,0);
    assert.equal(f.state().enrollment.browserInstance,'browser1');
    assert.deepEqual(f.sent.filter(m=>m.type==='connect').map(m=>JSON.parse(JSON.stringify(m))),[{type:'connect'},{type:'connect'}]);
    assert.match(f.status(),/broker authorization is still required/);
    f.setState({});await f.click();
    assert.match(f.status(),/Saved connection details are unavailable/);
    assert.equal(f.sent.filter(m=>m.type==='connect').length,2);
  }finally{f.page.window.close();}
});
test('scope expansion alone requests missing access and persists exactly the approved draft',async()=>{
  const f=fixture(undefined,undefined,undefined,{granted:true});
  try {
    f.chrome.permissions.contains=async value=>!value.origins.includes('https://added.example.test/*');
    const doc=f.page.window.document;
    doc.getElementById('origins').value+='\nhttps://added.example.test';
    doc.getElementById('channel').value='new-channel';
    await f.saveClick();
    assert.equal(f.requested.length,1);
    assert.deepEqual(Array.from(f.requested[0].origins),['https://fixture.example.test/*','https://added.example.test/*']);
    assert.equal(f.state().enrollment.profileChannel,'new-channel');
    assert.equal(f.sent.filter(m=>m.type==='connect').length,0);
  }finally{f.page.window.close();}
});
test('revoked Chrome permission updates saved access independently from transport state',async()=>{
  const f=fixture(undefined,undefined,undefined,{granted:true,connectionStatus:{connected:true,enabled:true,qualified:false,retryScheduled:false,attentionCode:'none'}});
  try {
    await settle();const doc=f.page.window.document;
    assert.match(f.status(),/connection opened/);
    f.setGranted(false);await f.permissionRemoved();
    assert.match(doc.getElementById('website-access-status').textContent,/permission is missing/);
    assert.match(f.status(),/connection opened/);
    await f.click();assert.equal(f.requested.length,0);assert.equal(f.saved.length,0);
    f.setGranted(true);await f.permissionAdded();
    assert.match(doc.getElementById('website-access-status').textContent,/approved in Chrome/);
  }finally{f.page.window.close();}
});
test('save, retry and automatic preference require trusted own-options gestures',async()=>{
  for(const address of ['chrome-extension://extension/options.html','https://foreign.example/options.html','chrome-extension://other/options.html']){
    const f=fixture(undefined,undefined,address);
    try{
      for(const action of [f.saveClick,f.click,f.enabledChange])await action({isTrusted:false});
      assert.equal(f.requested.length,0);assert.equal(f.saved.length,0);assert.equal(f.sent.filter(m=>m.type==='connect').length,0);
      if(address!=='chrome-extension://extension/options.html'){
        for(const action of [f.saveClick,f.click,f.enabledChange])await action({isTrusted:true});
        assert.equal(f.requested.length,0);assert.equal(f.saved.length,0);assert.equal(f.sent.length,0);
      }
      await settle();
    }finally{f.page.window.close();}
  }
});
test('automatic preference stores only a boolean and disabled retry keeps saved approvals',async()=>{
  const f=fixture(undefined,undefined,undefined,{granted:true});
  try{
    await settle();const doc=f.page.window.document;
    doc.getElementById('connection-enabled').checked=false;await f.enabledChange();
    assert.deepEqual(JSON.parse(JSON.stringify(f.saved)),[{connectionEnabled:false}]);
    assert.match(f.status(),/disabled/);
    await f.click();assert.equal(f.sent.filter(m=>m.type==='connect').length,0);
    assert.equal(f.requested.length,0);assert.ok(f.state().enrollment);
    assert.match(doc.getElementById('website-access-status').textContent,/approved/);
    doc.getElementById('connection-enabled').checked=true;await f.enabledChange();
    assert.equal(f.state().connectionEnabled,true);
    assert.equal(f.sent.filter(m=>m.type==='connect').length,0);
  }finally{f.page.window.close();}
});
test('saved disabled preference and closed read-only status load without automatic connect requests',async()=>{
  const f=fixture(undefined,undefined,undefined,{emptyFields:true,state:{connectionEnabled:false,enrollment:{profileChannel:'saved',browserInstance:'saved',origins:['https://fixture.example.test']}},connectionStatus:{connected:false,enabled:false,qualified:false,retryScheduled:false,attentionCode:'connectionDisabled'}});
  try{await settle();assert.equal(f.page.window.document.getElementById('connection-enabled').checked,false);assert.match(f.status(),/disabled/);assert.equal(f.saved.length,0);assert.equal(f.requested.length,0);assert.deepEqual(f.sent.map(m=>m.type),['connectionStatusLocal']);}finally{f.page.window.close();}
});
test('concurrent save clicks do not repeat website approval',async()=>{
 const f=fixture();
 try{await Promise.all([f.saveClick(),f.saveClick()]);assert.equal(f.requested.length,1);assert.equal(f.saved.length,1);assert.equal(f.sent.filter(m=>m.type==='connect').length,0);}finally{f.page.window.close();}
});

test('delayed initial transport read cannot replace a newer connection failure or preference edit',async()=>{
  for(const mode of ['connect','preference']){
    let finish;
    const connectionStatus=new Promise(resolve=>{finish=resolve;});
    const f=fixture({connected:false,attentionCode:'hostNotRegistered'},undefined,undefined,{connectionStatus});
    try{
      if(mode==='connect')await f.click();
      else{f.page.window.document.getElementById('connection-enabled').checked=false;await f.enabledChange();}
      finish({connected:true,enabled:true,qualified:false,retryScheduled:false,attentionCode:'none'});await settle();
      assert.match(f.status(),mode==='connect'?/cannot find/:/disabled/);
      assert.equal(f.requested.length,0);
    }finally{f.page.window.close();}
  }
});
test('preference storage notification during save still reports the saved choice',async()=>{
 const f=fixture();
 try{
  await settle();
  const set=f.chrome.storage.local.set;
  f.chrome.storage.local.set=async value=>{
    await set(value);
    f.storageChanged({connectionEnabled:{newValue:value.connectionEnabled}},'local');
  };
  f.page.window.document.getElementById('connection-enabled').checked=false;
  await f.enabledChange();
  assert.match(f.status(),/Automatic connection disabled/);
  assert.equal(f.page.window.document.getElementById('connection-enabled').checked,false);
  assert.equal(f.requested.length,0);
 }finally{f.page.window.close();}
});
test('read-only connection status never renders arbitrary provider payloads',async()=>{
 for(const connectionStatus of [
  {connected:false,enabled:true,qualified:false,retryScheduled:false,attentionCode:'PRIVATE_CANARY'},
  {connected:true,enabled:true,qualified:false,retryScheduled:false,attentionCode:'none',message:'PRIVATE_CANARY'},
  {connected:'PRIVATE_CANARY',enabled:true,qualified:false,retryScheduled:false,attentionCode:'none'}
 ]){
  const f=fixture(undefined,undefined,undefined,{connectionStatus});
  try{await settle();assert.doesNotMatch(f.page.window.document.body.textContent,/PRIVATE_CANARY/);assert.equal(f.saved.length,0);assert.equal(f.requested.length,0);}finally{f.page.window.close();}
 }
});

test('restoring valid saved enrollment collapses connection details without hiding access or retry',async()=>{
 for(const scope of [{origins:['https://fixture.example.test']},{origins:[],allWebsites:true}]){
  const enrollment={profileChannel:'saved-profile',browserInstance:'saved-browser',...scope};
  const f=fixture(undefined,undefined,undefined,{emptyFields:true,granted:true,state:{enrollment}});
  try{
   await settle();const doc=f.page.window.document;
   assert.equal(doc.getElementById('connection-details').open,false);
   assert.equal(doc.getElementById('channel').value,'saved-profile');
   assert.equal(doc.getElementById('instance').value,'saved-browser');
   assert.equal(doc.getElementById('origins').value,scope.origins.join('\n'));
   assert.equal(doc.getElementById('all-sites').checked,scope.allWebsites===true);
   assert.equal(doc.getElementById('website-access-status').closest('details'),null);
   assert.equal(doc.getElementById('connection-enabled').closest('details'),null);
   assert.equal(doc.getElementById('connect').closest('details'),null);
   doc.getElementById('connection-details').open=true;
   assert.equal(doc.getElementById('channel').value,'saved-profile');
   assert.equal(f.saved.length,0);assert.equal(f.requested.length,0);
  }finally{f.page.window.close();}
 }
});
test('saved settings never replace a draft or collapse incomplete connection details',async()=>{
 for(const mode of ['draft','editDuringRead','invalidSaved']){
  const f=fixture(undefined,undefined,undefined,{emptyFields:mode!=='draft',state:{enrollment:{profileChannel:mode==='invalidSaved'?'':'saved-profile',browserInstance:'saved-browser',origins:['https://saved.example.test']}}});
  try{
   const doc=f.page.window.document;
   if(mode==='editDuringRead')doc.getElementById('channel').value='fresh-draft';
   await settle();
   assert.equal(doc.getElementById('connection-details').open,true);
   assert.equal(doc.getElementById('channel').value,mode==='draft'?'profile1':mode==='editDuringRead'?'fresh-draft':'');
   assert.equal(f.saved.length,0);assert.equal(f.requested.length,0);
  }finally{f.page.window.close();}
 }
});


test('qualified connected status is ready and clears a prior scope mismatch',async()=>{
 const f=fixture();
 try{
  await settle();
  f.onMessage({type:'nativeConnectionStatus',connected:true,qualified:false,attentionCode:'websiteScopeMismatch'},worker);
  assert.match(f.status(),/local browser scope/);
  f.onMessage({type:'nativeConnectionStatus',connected:true,qualified:true,attentionCode:'none'},worker);
  assert.equal(f.status(),'Connected; executor qualified.');
  assert.equal(f.page.window.document.getElementById('status').dataset.state,'ready');
  f.onMessage({type:'nativeConnectionStatus',connected:false,qualified:false,attentionCode:'hostExited'},worker);
  assert.match(f.status(),/stopped/);assert.doesNotMatch(f.status(),/local browser scope/);
 }finally{f.page.window.close();}
});
test('five-field status distinguishes executor qualification from transport and connected attention',async()=>{
 for(const [qualified,attentionCode,expected,state] of [
  [true,'none',/^Connected; executor qualified\.$/,'ready'],
  [false,'none',/broker authorization is still required/,'pending'],
  [false,'storedFenceMismatch',/could not be independently quiesced/,'error'],
  [false,'lifecycleInhibited',/held for recovery/,'error'],
  [true,'storedFenceMismatch',/could not be independently quiesced/,'error']
 ]){
  const f=fixture(undefined,undefined,undefined,{connectionStatus:{connected:true,qualified,enabled:true,retryScheduled:false,attentionCode}});
  try{
   await settle();assert.match(f.status(),expected);assert.equal(f.page.window.document.getElementById('status').dataset.state,state);
   f.onMessage({type:'nativeConnectionStatus',connected:true,qualified,attentionCode,message:'PRIVATE_CANARY'},worker);
   assert.match(f.status(),expected);assert.doesNotMatch(f.status(),/PRIVATE_CANARY/);
   assert.equal(f.saved.length,0);assert.equal(f.requested.length,0);
  }finally{f.page.window.close();}
 }
});
test('manual connection reply retains qualified status and reports connected attention',async()=>{
 for(const response of [{connected:true,qualified:true,attentionCode:'none'},{connected:true,qualified:false,attentionCode:'storedFenceMismatch'}]){
  const f=fixture(response);
  try{await f.click();assert.match(f.status(),response.qualified?/executor qualified/:/could not be independently quiesced/);}finally{f.page.window.close();}
 }
});
test('Options renders only closed missing-receipt hashes and never raw identity fields',async()=>{
 let response={diagnostics:{version:3,journalVersion:2,grantRelation:'old',phase:'inspect',reason:'unknownReceipts',credentialProtection:false,lifecyclePending:false,retirementPending:false,reconnectJournal:'pending',missingReceiptSources:{version:1,count:1,hashes:['a'.repeat(64)],truncated:false}}};
 const f=fixture(()=>response),doc=f.page.window.document;
 try{doc.getElementById('read-connection-diagnostics').click();await new Promise(r=>setImmediate(r));assert.ok(doc.getElementById('connection-diagnostics-detail').getAttribute('aria-label').includes('a'.repeat(64)));assert.equal(f.saved.length,0);
 response.diagnostics.missingReceiptSources.hashes=['PRIVATE_CANARY'];doc.getElementById('read-connection-diagnostics').click();await new Promise(r=>setImmediate(r));assert.equal(doc.getElementById('connection-diagnostics-detail').textContent,'');assert.ok(!doc.body.textContent.includes('PRIVATE_CANARY'));}finally{f.page.window.close();}
});
