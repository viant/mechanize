const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {fixture,grant}=require('./worker-fixture.cjs');
const digest=v=>crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex');
const qualification=()=>({type:'processQualified',...grant,trustScope:'desktop',scopeQualified:true,profileQualified:false,fixtureOnly:false,executorQualified:false,executorChallenge:'first',mutationFingerprintVersion:2,reconnectBindingsVersion:1});
test('worker distinguishes eligible document bound from full recovery census total without URLs',async t=>{
 for(const bound of ['eligibleDocuments','censusTotal'])await t.test(bound,async()=>{
 const f=await fixture({}, {enroll:false});f.state.boundFingerprintVersion=2;f.state.reconnectSupported=true;await f.receive(qualification());f.disconnect();await f.connect();f.messages.length=0;
 const next={...grant,brokerEpoch:'second',channelEpoch:'second'};
 if(bound==='censusTotal')f.storage.mechanizeReconnect={version:1,phase:'pending',nonce:'a'.repeat(64),oldFence:grant,newFence:next,history:[]};
 f.state.inventoryTabs=Array.from({length:6},(_,i)=>({id:7+i,url:'https://fixture.example.test/',title:'Generic fixture'}));f.state.framesByTab={};
 for(let t=0;t<6;t++)f.state.framesByTab[7+t]=Array.from({length:171},(_,i)=>({frameId:i,parentFrameId:i===0?-1:0,documentId:`generic-${t}-${i}`,url:'https://fixture.example.test/',frameType:i===0?'outermost_frame':'sub_frame',documentLifecycle:'active'}));
 f.state.nativePost=m=>{if(m.type==='reconnectBindings')queueMicrotask(()=>f.nativeMessage({type:'reconnectBindingsResult',requestId:m.requestId,pendingDigest:digest(m.pending),bindingsDigest:digest([]),total:0,offset:0,nextOffset:0,bindings:[]}));};
 await f.receive({...qualification(),...next,executorChallenge:'next'});
 assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));
 const result=await new Promise(resolve=>{const sender={id:'extension',url:'chrome-extension://extension/options.html',origin:'chrome-extension://extension',frameId:0,tab:{id:1}};for(const listener of f.state.runtimeListeners)if(listener({type:'connectionDiagnosticsLocal'},sender,resolve)===true)break;});
 assert.deepEqual(JSON.parse(JSON.stringify(result.diagnostics.inventoryLimit)),{bound,count:bound==='censusTotal'?1026:1025,limit:1024});assert.ok(!JSON.stringify(result).includes('fixture.example.test'));
 });
});
