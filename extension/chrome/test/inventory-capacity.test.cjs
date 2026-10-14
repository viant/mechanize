const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {fixture,grant}=require('./worker-fixture.cjs');
const digest=v=>crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex');
const qualification=()=>({type:'processQualified',...grant,trustScope:'desktop',scopeQualified:true,profileQualified:false,fixtureOnly:false,executorQualified:false,executorChallenge:'first',mutationFingerprintVersion:2,reconnectBindingsVersion:1});
async function inventoryFixture(counts,{recovery=false,title='Generic fixture'}={}){
 const f=await fixture({}, {enroll:false});f.state.boundFingerprintVersion=2;f.state.boundDynamicIdentity=true;f.state.reconnectSupported=true;f.state.emptyRendererReceipts=true;await f.receive(qualification());f.disconnect();await f.connect();f.messages.length=0;
 const next={...grant,brokerEpoch:'second',channelEpoch:'second'};
 if(recovery)f.storage.mechanizeReconnect={version:1,phase:'pending',nonce:'a'.repeat(64),oldFence:grant,newFence:next,history:[]};
 f.state.inventoryTabs=counts.map((_,i)=>({id:7+i,url:'https://fixture.example.test/',title}));f.state.framesByTab={};
 counts.forEach((count,t)=>{f.state.framesByTab[7+t]=Array.from({length:count},(_,i)=>({frameId:i,parentFrameId:i===0?-1:0,documentId:`generic-${t}-${i}`,url:'https://fixture.example.test/',frameType:i===0?'outermost_frame':'sub_frame',documentLifecycle:'active'}));});
 f.state.nativePost=m=>{if(m.type==='reconnectBindings')queueMicrotask(()=>f.nativeMessage({type:'reconnectBindingsResult',requestId:m.requestId,pendingDigest:digest(m.pending),bindingsDigest:digest([]),total:0,offset:0,nextOffset:0,bindings:[]}));if(m.type==='reconnectBindingsDone'&&m.complete)queueMicrotask(()=>f.nativeMessage({type:'reconnectBindingsCommitReady',requestId:m.requestId,complete:true}));};
 return {f,next};
}
test('complete multitab 211-document recovery qualifies without dropping child identities',async()=>{
 const {f,next}=await inventoryFixture([53,53,53,52],{recovery:true}),inputs=f.state.deliveries;
 await f.receive({...qualification(),...next,executorChallenge:'next'});
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'),JSON.stringify(f.messages.filter(m=>m.type==='attention')));
 const inventory=f.messages.filter(m=>m.type==='documents').at(-1);assert.equal(inventory.truncated,false);assert.equal(inventory.documents.length,211);assert.equal(new Set(inventory.documents.map(d=>d.documentId)).size,211);assert.equal((f.state.debuggerInputs||[]).filter(v=>v.method.startsWith('Input.')).length,0);assert.ok(!f.messages.some(m=>m.dispatchState==='dispatched'));assert.equal(f.state.permissionRequests||0,0);assert.equal(f.storage.enrollment.origins[0],'https://fixture.example.test');
});
test('count and unchanged serialized byte overflow never publish partial executor readiness or adopt history',async t=>{
 for(const kind of ['documents','bytes'])await t.test(kind,async()=>{
 const {f,next}=await inventoryFixture(kind==='documents'?Array(6).fill(171):Array(5).fill(190),{title:kind==='bytes'?'x'.repeat(256):'Generic fixture'}),journal=JSON.stringify(f.storage.mechanizeReconnect),lastGrant=JSON.stringify(f.storage.lastGrant),inputs=f.state.deliveries;
 if(kind==='bytes')f.state.renderer=(_,message)=>{assert.equal(message.type,'bind');return {identity:Object.fromEntries(['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'].map(k=>[k,message.binding.identity[k]])),mutationFingerprintVersion:2};};
 await f.receive({...qualification(),...(kind==='bytes'?grant:next),executorChallenge:'next'});
 if(kind==='bytes'){
 const result=await new Promise(resolve=>{const sender={id:'extension',url:'chrome-extension://extension/options.html',origin:'chrome-extension://extension',frameId:0,tab:{id:1}};for(const listener of f.state.runtimeListeners)if(listener({type:'connectionDiagnosticsLocal'},sender,resolve)===true)break;});
 assert.ok(result.diagnostics.inventoryLimit,'byte refusal diagnostic missing '+JSON.stringify(result.diagnostics));assert.equal(result.diagnostics.inventoryLimit.bound,'inventoryBytes');assert.equal(result.diagnostics.inventoryLimit.limit,262144);assert.ok(result.diagnostics.inventoryLimit.count>262144);
 }
 assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.ok(!f.messages.some(m=>m.type==='documents'&&m.truncated===false));assert.equal(JSON.stringify(f.storage.mechanizeReconnect),journal);assert.equal(JSON.stringify(f.storage.lastGrant),lastGrant);assert.equal(f.state.deliveries,inputs);
 });
});
