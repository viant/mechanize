const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {fixture,grant}=require('./worker-fixture.cjs');
const qualify=label=>({type:'processQualified',...grant,brokerEpoch:label,channelEpoch:label,trustScope:'desktop',scopeQualified:true,profileQualified:false,fixtureOnly:false,executorChallenge:'challenge-'+label,mutationFingerprintVersion:2,reconnectBindingsVersion:1});
const root=()=>({frameId:0,parentFrameId:-1,documentId:'new-tab-root',url:'chrome://new-tab-page/',frameType:'outermost_frame',documentLifecycle:'active'});
const child=()=>({frameId:3,parentFrameId:2,documentId:'builtin-child',url:'chrome-untrusted://new-tab-page/',frameType:'sub_frame',documentLifecycle:'active'});
const parent=()=>({frameId:2,parentFrameId:0,documentId:'builtin-parent',url:'chrome-untrusted://new-tab-page/',frameType:'sub_frame',documentLifecycle:'active'});
const hash=value=>crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
const retained=(tabId,documentId)=>({attemptId:'b'.repeat(64),fingerprintSHA256:'c'.repeat(64),dispatchState:'dispatched',fence:{...grant,brokerEpoch:'original',channelEpoch:'original'},identity:{profileChannel:'p1',browserInstance:'b1',tabId,frameId:0,documentId,documentGeneration:1}});
async function pending(rows=[]){
 const f=await fixture({}, {enroll:false});await f.receive(qualify('original'));f.disconnect();
 const old={...grant,brokerEpoch:'original',channelEpoch:'original'},next={...grant,brokerEpoch:'interrupted',channelEpoch:'interrupted'};
 f.storage.mechanizeReconnect={format:'activeHandoff',version:1,phase:'pending',nonce:'a'.repeat(64),oldFence:old,newFence:next,history:[],recoveryFences:[old,next],sourceInventory:{version:1,kind:'eligibleDocuments',documents:[]}};
 f.state.inventoryTabs=[{id:11,url:'chrome://newtab/',status:'complete'}];
 f.state.nativePost=message=>{if(message.type==='reconnectBindings')queueMicrotask(()=>f.receive({type:'reconnectBindingsResult',requestId:message.requestId,pendingDigest:hash(message.pending),bindingsDigest:hash(rows),total:rows.length,offset:0,nextOffset:rows.length,bindings:rows}));if(message.type==='reconnectBindingsDone'&&message.complete)queueMicrotask(()=>f.receive({type:'reconnectBindingsCommitReady',requestId:message.requestId,complete:true}));};
 await f.connect();f.messages.length=0;return f;
}
test('per-tab metadata reread recovers transient built-in child missing parent without losing any identity',async()=>{
 const f=await pending();let reads=0;f.chrome.webNavigation.getAllFrames=async()=>++reads===1?[root(),child()]:[root(),parent(),child()];
 await f.receive(qualify('fresh'));assert.ok(f.messages.some(m=>m.type==='executorPrepared'),JSON.stringify(f.diagnostic()));assert.ok(reads>=2);assert.equal(f.state.deliveries,0);assert.equal(f.state.debuggerInputs,undefined);
});
test('unrelated persistent built-in orphan remains non-executable metadata and qualifies',async()=>{
 const f=await pending([retained(12,'absent-on-other-tab')]);let reads=0;
 f.chrome.webNavigation.getAllFrames=async()=>{reads++;return [root(),child()];};
 await f.receive(qualify('fresh'));
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'),JSON.stringify(f.diagnostic()));
 assert.equal(f.storage.mechanizeReconnect.sourceInventory.documents.length,0);
 assert.equal(f.state.injections,undefined);assert.equal(f.state.deliveries,0);assert.ok(reads<=16);
});
for(const [name,documentId,reason] of [
 ['orphan is retained original source','builtin-child','executorRefused'],
 ['absent retained parent of orphan','builtin-parent','inventoryChanged'],
 ['other absent retained source on incomplete tab','absent-root','inventoryChanged']
])test(name+' never supplies source absence or admits input',async()=>{
 const f=await pending([retained(11,documentId)]);f.chrome.webNavigation.getAllFrames=async()=>[root(),child()];
 const original=JSON.stringify(f.storage.mechanizeReconnect);
 await f.receive(qualify('fresh'));
 assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.diagnostic().reason,reason);
 if(reason==='inventoryChanged')assert.equal(f.inventoryReason(),'childSourceIdentityUnavailable');
 assert.equal(JSON.stringify(f.storage.mechanizeReconnect),original);assert.equal(f.state.injections,undefined);assert.equal(f.state.deliveries,0);
});
test('reread cannot hide an observed orphan input identity',async()=>{
 const f=await pending([retained(11,'builtin-child')]);let reads=0;
 f.chrome.webNavigation.getAllFrames=async()=>++reads<=2?[root(),child()]:[root()];
 await f.receive(qualify('fresh'));
 assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.state.deliveries,0);
});
test('missing parent does not relax cycle or conflicting parent-document metadata',async t=>{
 for(const [name,frames,reason] of [
  ['cycle',[root(),{...child(),parentFrameId:3}],'frameCycle'],
  ['parent document mismatch',[root(),parent(),{...child(),parentDocumentId:'foreign'}],'frameParentDocumentMismatch']
 ])await t.test(name,async()=>{
  const f=await pending();f.chrome.webNavigation.getAllFrames=async()=>frames;await f.receive(qualify('fresh'));
  assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.inventoryReason(),reason);assert.equal(f.state.deliveries,0);
 });
});
for(const frameType of ['sub_frame','fenced_frame'])test('orphan website '+frameType+' keeps identity without injecting an executor into its incomplete tree',async()=>{
 const f=await pending();f.state.inventoryTabs=[{id:11,url:'https://fixture.example.test/page',status:'complete'}];
 f.state.reconnectSupported=true;f.state.emptyRendererReceipts=true;f.state.boundFingerprintVersion=2;
 f.chrome.webNavigation.getAllFrames=async()=>[{...root(),documentId:'web-root',url:'https://fixture.example.test/page'}, {...child(),frameType,url:'https://fixture.example.test/child'}];
 await f.receive(qualify('fresh'));
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'),JSON.stringify(f.diagnostic()));
 assert.equal(f.storage.mechanizeReconnect.sourceInventory.documents.length,1);
 assert.equal(f.storage.mechanizeReconnect.sourceInventory.documents[0].documentId,'web-root');
 assert.ok(f.state.reconnectCalls.every(c=>c.newBinding.identity.documentId==='web-root'));assert.equal(f.state.lastRendererMessage.action,'executor.receipts');assert.equal(f.state.debuggerInputs,undefined);
});
test('URL-omitted internal tab retains incomplete tree as non-executable metadata',async()=>{
 const f=await pending();f.state.inventoryTabs=[{id:11,status:'complete'}];f.chrome.webNavigation.getAllFrames=async()=>[root(),child()];
 await f.receive(qualify('fresh'));
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'),JSON.stringify(f.diagnostic()));
 assert.equal(f.state.injections,undefined);assert.equal(f.state.deliveries,0);
});
