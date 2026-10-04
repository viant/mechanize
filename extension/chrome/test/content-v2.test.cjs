const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {webcrypto}=require('node:crypto');
const {JSDOM}=require('jsdom');
const identity={profileChannel:'profile1',browserInstance:'browser1',tabId:7,frameId:0,documentId:'doc1',documentGeneration:1};
const lease={id:'lease1',generation:7};
function fixture(version=2){
 const dom=new JSDOM('<button id="save">Save</button><input id="field">',{url:'https://fixture.test',runScripts:'outside-only'}),w=dom.window,listeners=[];
 w.TextEncoder=TextEncoder;Object.defineProperty(w,'crypto',{value:webcrypto,configurable:true});w.HTMLElement.prototype.getClientRects=()=>[{width:100,height:20}];
 w.chrome={runtime:{id:'fixture',onMessage:{addListener:f=>listeners.push(f)}}};
 for(const file of ['protocol.js','fingerprint.js','dom.js','recorder.js','content.js'])w.eval(fs.readFileSync(path.join(__dirname,'..',file),'utf8'));
 const binding={identity,brokerEpoch:'broker1',channelEpoch:'channel1',scopeHash:'a'.repeat(64),leaseRequired:true,mutationFingerprintVersion:version};
 const send=message=>new Promise(resolve=>listeners[0](message,{id:'fixture'},resolve));
 const command=(action,extra={})=>({requestId:'request1',action,identity,brokerEpoch:binding.brokerEpoch,channelEpoch:binding.channelEpoch,scopeHash:binding.scopeHash,deadlineUnixMs:Date.now()+5000,...extra});
 const ready=async()=>{const ack=await send({type:'bind',binding});await send(command('executor.acquire',{controlLease:lease}));return ack};
 const mutation=async(action='element.press',extra={})=>{let cmd=command(action,{attemptId:'a'.repeat(64),locator:{strategy:'id',value:action==='element.fill'?'field':'save',exact:true},controlLease:lease,...extra});cmd.fingerprintVersion=2;cmd.fingerprintSHA256=(await w.MechanizeFingerprint.mutationV2(cmd)).sha256;return cmd};
 return {w,binding,send,command,ready,mutation,close:()=>w.close()};
}
test('negotiated v2 press/fill retain exact digest receipts and execute once',async t=>{
 const f=fixture();t.after(f.close);assert.equal((await f.ready()).mutationFingerprintVersion,2);let clicks=0;f.w.document.querySelector('#save').addEventListener('click',()=>clicks++);
 const cmd=await f.mutation();const first=await f.send(cmd);assert.equal(first.dispatchState,'dispatched');assert.equal(first.fingerprintVersion,2);assert.equal(first.fingerprintSHA256,cmd.fingerprintSHA256);
 assert.equal((await f.send({...cmd,requestId:'again'})).fingerprintSHA256,cmd.fingerprintSHA256);assert.equal(clicks,1);
 const queried=await f.send(f.command('receipt.query',{attemptId:cmd.attemptId}));assert.equal(queried.fingerprintVersion,2);assert.equal(queried.fingerprintSHA256,cmd.fingerprintSHA256);
 const filled=await f.mutation('element.fill',{attemptId:'b'.repeat(64),args:{value:'nonsecret "literal" <&>\u2028'}});const result=await f.send(filled);assert.equal(result.dispatchState,'dispatched');assert.equal(f.w.document.querySelector('#field').value,filled.args.value);
 const exported=await f.send(f.command('executor.receipts',{args:{offset:0,limit:64}}));assert.equal(exported.version,2);assert.equal(exported.receipts[0].fingerprintVersion,2);assert.equal(exported.receipts[0].fingerprintSHA256,cmd.fingerprintSHA256);assert.equal(JSON.stringify(exported).includes(filled.args.value),false);
});
test('v2 payload substitution or legacy mutation cannot act on negotiated executor',async t=>{
 const f=fixture();t.after(f.close);await f.ready();let clicks=0;f.w.document.querySelector('#save').addEventListener('click',()=>clicks++);
 const cmd=await f.mutation();const changed={...cmd,locator:{...cmd.locator,value:'field'}};assert.equal((await f.send(changed)).error.code,'fingerprintMismatch');assert.equal(clicks,0);
 const legacy={...cmd};delete legacy.fingerprintVersion;delete legacy.fingerprintSHA256;assert.equal((await f.send(legacy)).error.code,'fingerprintMismatch');assert.equal(clicks,0);
});
test('v1 immutable binding/history cannot be relabeled as v2',async t=>{
 const f=fixture(1);t.after(f.close);await f.ready();let clicks=0;f.w.document.querySelector('#save').addEventListener('click',()=>clicks++);
 const legacy=f.command('element.press',{attemptId:'legacy',locator:{strategy:'id',value:'save',exact:true},controlLease:lease});await f.send(legacy);assert.equal(clicks,1);
 const refused=await f.send({type:'bind',binding:{...f.binding,mutationFingerprintVersion:2}});assert.equal(refused.error.code,'executorNotQuiescent');const query=await f.send(f.command('receipt.query',{attemptId:'legacy'}));assert.equal(query.fingerprintVersion,undefined);
 const exportV1=await f.send(f.command('executor.receipts',{args:{offset:0,limit:64}}));assert.equal(exportV1.version,1);assert.equal(exportV1.receipts[0].fingerprintVersion,undefined);
});
test('lease retirement DOM change and deadline expiry during v2 hashing prevent input',async t=>{
 for(const mode of ['retire','DOM','deadline']){
  const f=fixture();t.after(f.close);await f.ready();let clicks=0;f.w.document.querySelector('#save').addEventListener('click',()=>clicks++);const cmd=await f.mutation();
  let release,entered;const wait=new Promise(resolve=>release=resolve),started=new Promise(resolve=>entered=resolve);Object.defineProperty(f.w,'crypto',{value:{subtle:{digest:async(...args)=>{entered();await wait;return webcrypto.subtle.digest(...args)}}},configurable:true});
  const pending=f.send(cmd);await started;if(mode==='retire')await f.send(f.command('executor.retire',{controlLease:lease}));else if(mode==='DOM')f.w.document.body.appendChild(f.w.document.createElement('div'));else cmd.deadlineUnixMs=Date.now()-1;release();const result=await pending;assert.ok(result.error);assert.equal(clicks,0);assert.equal(result.fingerprintVersion,2);
 }
});
