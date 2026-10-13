const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {fixture,grant}=require('./worker-fixture.cjs');
const qualify=label=>({type:'processQualified',...grant,brokerEpoch:label,channelEpoch:label,trustScope:'desktop',scopeQualified:true,profileQualified:false,fixtureOnly:false,executorChallenge:'challenge-'+label,mutationFingerprintVersion:2,reconnectBindingsVersion:1});
async function initial(){const f=await fixture({}, {enroll:false});await f.receive(qualify('original'));f.state.reconnectSupported=true;f.disconnect();return f;}
async function interrupt(f,label){await f.connect();f.state.afterPendingWrite=()=>f.disconnect();await f.receive(qualify(label));delete f.state.afterPendingWrite;assert.equal(f.storage.mechanizeReconnect.phase,'pending');}
const auditKeys=f=>Object.keys(f.storage).filter(key=>key.startsWith('mechanizeReconnectAudit:'));
const head=f=>f.storage['mechanizeReconnectAudit:'+f.storage.mechanizeReconnect.audit.digest];
function seedLegacy(f){
 const old={brokerEpoch:'original',channelEpoch:'original',scopeHash:grant.scopeHash};
 const history=Array.from({length:37},(_,n)=>({nonce:(100+n).toString(16).padStart(64,'0'),oldFence:{...old,brokerEpoch:'history-'+n,channelEpoch:'history-'+n},newFence:n===36?old:{...old,brokerEpoch:'history-'+(n+1),channelEpoch:'history-'+(n+1)},executors:[]}));
 let record={version:1,phase:'pending',nonce:'1'.repeat(64),oldFence:old,newFence:{...old,brokerEpoch:'abandoned-1',channelEpoch:'abandoned-1'},history};
 for(let n=2;n<=6;n++)record={version:n,phase:'pending',nonce:String(n).repeat(64),oldFence:old,newFence:{...old,brokerEpoch:'abandoned-'+n,channelEpoch:'abandoned-'+n},history,recovery:{kind:'emptySetupDocuments',originalPending:record}};
 f.storage.mechanizeReconnect=record;return JSON.stringify(record);
}
test('legacy v6 migrates once to a bounded active handoff preserving exact prior history and receipts',async()=>{
 const f=await initial(),original=seedLegacy(f);
 f.sessionState['browserIntent:original-receipt']={attemptId:'original-receipt'};f.sessionState['browserReceipt:original-receipt']={dispatchState:'dispatched'};
 const receipts=JSON.stringify(f.sessionState);
 await f.connect();f.messages.length=0;await f.receive(qualify('migrated'));
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'));
 const current=f.storage.mechanizeReconnect;assert.equal(current.format,'activeHandoff');assert.equal(current.version,1);assert.equal(current.history.length,1);assert.equal(current.recovery,undefined);
 assert.equal(head(f).journalJSON,original);assert.equal(current.audit.digest,crypto.createHash('sha256').update(original).digest('hex'));
 assert.equal(JSON.stringify(f.sessionState),receipts);assert.equal(f.state.deliveries,0);assert.equal(f.state.permissionRequests||0,0);
});
test('many failed handoffs and cold restart use constant immediate audit reads and bounded current fences',async()=>{
 const counts=[];
 for(const count of [2,32]){
  const original=await initial();for(let n=0;n<count;n++)await interrupt(original,'interrupted-'+n);
  const storage=structuredClone(original.storage),evidence=Object.fromEntries(auditKeys(original).map(k=>[k,JSON.stringify(storage[k])]));
  original.disconnect();const f=await fixture({}, {enroll:false,localState:storage});f.state.reconnectSupported=true;
  let reads=0,ancestorReads=0;const get=f.chrome.storage.local.get;
  f.chrome.storage.local.get=async key=>{if(typeof key==='string'&&key.startsWith('mechanizeReconnectAudit:'))reads++;if(typeof key==='string'&&key.startsWith('mechanizeReconnectPendingArchive:'))ancestorReads++;return get(key);};
  await f.connect();f.messages.length=0;await f.receive(qualify('fresh-'+count));assert.ok(f.messages.some(m=>m.type==='executorPrepared'),JSON.stringify(f.diagnostic()));
  assert.equal(f.storage.mechanizeReconnect.history.length,1);assert.equal(f.storage.mechanizeReconnect.recoveryFences.length,1);assert.equal(ancestorReads,0);
  assert.equal(f.auditCacheSize(),0,'qualification drain clears audit proof cache');
  for(const [key,bytes]of Object.entries(evidence))assert.equal(JSON.stringify(f.storage[key]),bytes);
  assert.equal(f.state.deliveries,0);counts.push(reads);
 }
 assert.equal(counts[0],counts[1],'old audit count must not increase current admission work');
 assert.ok(counts[1]<=16,'only the immediate audit may be checked at bounded admission checkpoints');
});
test('missing/tampered immediate evidence refuses while ancient audit availability is not current authority',async()=>{
 for(const mode of ['immediateMissing','immediateTampered','referenceSubstitution','ancientMissing']){
  const original=await initial();for(let n=0;n<4;n++)await interrupt(original,'interrupted-'+n);
  const storage=structuredClone(original.storage),current=storage.mechanizeReconnect,key='mechanizeReconnectAudit:'+current.audit.digest;
  if(mode==='immediateMissing')delete storage[key];if(mode==='immediateTampered')storage[key].journalJSON+=' ';
  if(mode==='referenceSubstitution')current.audit.oldFence.brokerEpoch='foreign';
  if(mode==='ancientMissing')delete storage[auditKeys(original).find(k=>k!==key)];
  original.disconnect();const f=await fixture({}, {enroll:false,localState:storage});f.state.reconnectSupported=true;
  await f.connect();const before=JSON.stringify(f.storage);f.messages.length=0;await f.receive(qualify('fresh'));
  assert.equal(f.messages.some(m=>m.type==='executorPrepared'),mode==='ancientMissing');
  if(mode!=='ancientMissing')assert.equal(JSON.stringify(f.storage),before);
  assert.equal(f.state.deliveries,0);assert.equal(f.state.permissionRequests||0,0);
 }
});
test('fresh current proof keeps each witnessed predecessor fence across mixed partial adoption',async()=>{
 const f=await initial(),old={...grant,brokerEpoch:'original',channelEpoch:'original'},partial={...grant,brokerEpoch:'partial',channelEpoch:'partial'},abandoned={...grant,brokerEpoch:'abandoned',channelEpoch:'abandoned'};
 const identities=[{profileChannel:'p1',browserInstance:'b1',tabId:7,frameId:0,documentId:'d1',documentGeneration:1},{profileChannel:'p1',browserInstance:'b1',tabId:8,frameId:0,documentId:'d2',documentGeneration:1}];
 f.state.inventoryTabs=identities.map(i=>({id:i.tabId,url:'https://fixture.example.test/page'}));f.state.framesByTab=Object.fromEntries(identities.map(i=>[i.tabId,[{frameId:0,parentFrameId:-1,documentId:i.documentId,url:'https://fixture.example.test/page',frameType:'outermost_frame',documentLifecycle:'active'}]]));
 f.storage.mechanizeReconnect={format:'activeHandoff',version:1,phase:'pending',nonce:'a'.repeat(64),oldFence:old,newFence:abandoned,history:[],recoveryFences:[old,partial,abandoned],sourceInventory:{version:1,kind:'eligibleDocuments',documents:identities.map(i=>({...i,origin:'https://fixture.example.test'}))}};
 const current=new Map([[7,old],[8,partial]]),prepared=new Map(),seen=[];
 f.state.renderer=async(tab,message)=>{
  if(message.type==='brokerReconnect'){
   const bound=current.get(tab);if(JSON.stringify(bound)!==JSON.stringify(message.oldFence))return{error:{code:'wrongFence'}};
   const identity={...message.newBinding.identity};seen.push({tab,phase:message.phase,fence:message.oldFence});
   if(message.phase==='inspect')return{nonce:message.nonce,phase:'inspected',version:1,identity};
   if(message.phase==='prepare')prepared.set(tab,JSON.stringify(message.oldFence));
   if(message.phase==='adopt'){assert.equal(prepared.get(tab),JSON.stringify(message.oldFence));current.set(tab,{brokerEpoch:message.newBinding.brokerEpoch,channelEpoch:message.newBinding.channelEpoch,scopeHash:message.newBinding.scopeHash});}
   return{nonce:message.nonce,phase:message.phase==='prepare'?'prepared':'adopted',identity,quiescent:true,receiptRevision:0,receiptCount:0};
  }
  if(message.action==='executor.receipts')return{version:2,requestId:message.requestId,identity:message.identity,total:0,revision:0,offset:0,nextOffset:0,truncated:false,receipts:[],readiness:{recording:false}};
  throw Error('input must not be issued');
 };
 const hash=value=>crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
 f.state.nativePost=message=>{if(message.type==='reconnectBindings')queueMicrotask(()=>f.receive({type:'reconnectBindingsResult',requestId:message.requestId,pendingDigest:hash(message.pending),bindingsDigest:hash([]),total:0,offset:0,nextOffset:0,bindings:[]}));if(message.type==='reconnectBindingsDone'&&message.complete)queueMicrotask(()=>f.receive({type:'reconnectBindingsCommitReady',requestId:message.requestId,complete:true}));};
 await f.connect();f.messages.length=0;await f.receive(qualify('fresh-mixed'));assert.ok(f.messages.some(m=>m.type==='executorPrepared'),JSON.stringify(f.diagnostic()));
 assert.equal(seen.find(x=>x.tab===7&&x.phase==='prepare').fence.brokerEpoch,'original');assert.equal(seen.find(x=>x.tab===8&&x.phase==='prepare').fence.brokerEpoch,'partial');
 assert.deepEqual(Array.from(f.storage.mechanizeReconnect.recoveryFences,x=>x.brokerEpoch),['fresh-mixed']);assert.equal(f.state.deliveries,0);assert.equal(f.state.debuggerInputs,undefined);
});
