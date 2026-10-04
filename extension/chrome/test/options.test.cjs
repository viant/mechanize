const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {JSDOM} = require('jsdom');
function fixture(response = {connected:true}, failure = '') {
  const page = new JSDOM(fs.readFileSync(path.join(__dirname, '..', 'options.html'), 'utf8'));
  const document = page.window.document;
  document.getElementById('channel').value = 'profile1';
  document.getElementById('instance').value = 'browser1';
  document.getElementById('origins').value = 'https://fixture.example.test';
  let click, onMessage;
  const saved = [], requested = [];
  document.getElementById('enroll').addEventListener = (type, listener) => { if(type==='click') click=listener; };
  const chrome = {
    permissions:{async request(value) {requested.push(value); if(failure==='permissions') throw Error('private-credential-secret'); return failure!=='denied';}},
    storage:{local:{async set(value) {if(failure==='storage') throw Error('private-credential-secret'); saved.push(value);}}},
    runtime:{id:'extension', getURL:value=>`chrome-extension://extension/${value}`, onMessage:{addListener(listener){onMessage=listener;}},
      async sendMessage(message) {if(failure==='message') throw Error('private-credential-secret'); return typeof response==='function'?response(onMessage):response;}}
  };
  const context = vm.createContext({document, chrome, URL});
  vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'options.js'), 'utf8'), context);
  return {page, saved, requested, click, onMessage, status:()=>document.getElementById('status').textContent};
}
const worker = {id:'extension', url:'chrome-extension://extension/worker.js'};
test('options records only public enrollment and reports opened connection pending broker authority', async () => {
  const f=fixture();
  await f.click();
  assert.match(f.status(), /Native host connection opened/);
  assert.match(f.status(), /broker authorization is still required/);
  assert.equal(f.saved.length,1);
  assert.equal(Object.keys(f.saved[0].enrollment).sort().join(), 'browserInstance,origins,profileChannel');
  assert.equal(JSON.stringify(f.saved).includes('credential'),false);
  f.page.window.close();
});
test('false, absent, malformed and rejected connection replies never claim connected success', async () => {
  for(const [response,failure] of [[{connected:false},''],[()=>undefined,''],[{},''],[{connected:'true'},''],[{connected:true},'message']]) {
    const f=fixture(response,failure);
    await f.click(); assert.match(f.status(), /disconnected/);
    assert.doesNotMatch(f.status(), /connection opened|private-credential-secret/);
    f.page.window.close();
  }
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
    const f=fixture({connected:true},failure); await f.click();
    assert.match(f.status(), /Enrollment unavailable/); assert.doesNotMatch(f.status(), /private-credential-secret/);
    f.page.window.close();
  }
  const denied=fixture({connected:true},'denied'); await denied.click();
  assert.equal(denied.status(),'Origin permission denied'); assert.equal(denied.saved.length,0); denied.page.window.close();
});
