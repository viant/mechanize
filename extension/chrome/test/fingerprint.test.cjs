const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const vectors = JSON.parse(fs.readFileSync(path.join(__dirname,'../../../testdata/chrome-command-fingerprint-v2.json'),'utf8'));
// Expose the private canonical encoder only in this inert VM test. Production
// exports only mutationV2's version/digest result and has no raw payload API.
const source = fs.readFileSync(path.join(__dirname,'../fingerprint.js'),'utf8').replace('return Object.freeze({mutationV2});','globalThis.testCanonicalEnvelope=canonicalEnvelope; return Object.freeze({mutationV2});');
const context = vm.createContext({TextEncoder,crypto:require('node:crypto').webcrypto});
vm.runInContext(source,context);
const fingerprint = context.MechanizeFingerprint.mutationV2;
test('v2 canonical bytes and SHA256 match independent cross-language vectors',async()=>{
  for(const vector of vectors.cases){
    assert.equal(context.testCanonicalEnvelope(vector.command),vector.canonical,vector.name);
    const result=await fingerprint(vector.command);
    assert.deepEqual(JSON.parse(JSON.stringify(result)),{version:2,sha256:vector.sha256},vector.name);
    assert.deepEqual(Object.keys(result).sort(),['sha256','version']);
  }
  const digests=new Map(vectors.cases.map(c=>[c.name,c.sha256]));
  assert.equal(digests.get('press'),digests.get('press-reordered'));
  assert.equal(digests.get('press'),digests.get('press-excluded-fields'));
  assert.notEqual(digests.get('fill-unicode-html-separators'),digests.get('fill-logical-value-change'));
});
test('v2 rejects malformed unicode unsafe identities and unsupported logical payloads',async()=>{
  for(const mode of ['unknown action','unknown field','missing lease','missing locator','child frame','unsafe generation','fractional tab','unknown args','float value','lone high','lone low','nonexact','CSS','role name on id']){
    const c=structuredClone(vectors.cases[0].command);
    if(mode==='unknown action')c.action='browser.navigate';
    if(mode==='unknown field')c.script='private value';
    if(mode==='missing lease')c.controlLease=null;
    if(mode==='missing locator')c.locator=null;
    if(mode==='child frame')c.identity.frameId=1;
    if(mode==='unsafe generation')c.identity.documentGeneration=9007199254740992;
    if(mode==='fractional tab')c.identity.tabId=1.5;
    if(mode==='unknown args')c.args={script:'private value'};
    if(mode==='float value'){c.action='element.fill';c.args={value:1.5};}
    if(mode==='lone high'){c.action='element.fill';c.args={value:'\ud800'};}
    if(mode==='lone low')c.locator.value='\udc00';
    if(mode==='nonexact')c.locator.exact=false;
    if(mode==='CSS')c.locator.strategy='css';
    if(mode==='role name on id')c.locator.name='private value';
    await assert.rejects(fingerprint(c),e=>e.message==='Invalid qualified logical mutation envelope',mode);
  }
});
test('v2 is packaged for injection and exposes only digest API',()=>{
  assert.deepEqual(Object.keys(context.MechanizeFingerprint),['mutationV2']);
  const worker=fs.readFileSync(path.join(__dirname,'../worker.js'),'utf8');
  const content=fs.readFileSync(path.join(__dirname,'../content.js'),'utf8');
  assert.equal(worker.includes('fingerprint.js'),true);
  assert.equal(content.includes('JSON.stringify({...command, requestId:null, deadlineUnixMs:null})'),true);
});
