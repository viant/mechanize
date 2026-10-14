const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs'),path=require('node:path');
function fixture(){
 const state={saved:{},updates:0,focuses:0,reads:0,current:true,permitted:true,active:false,focused:false,url:'https://fixture.test/public/error?token=PRIVATE-CANARY#PRIVATE-CANARY'};
 const api={permissions:{async contains(){return state.permitted}},storage:{session:{async get(){return structuredClone(state.saved)},async set(x){if(state.failReceipt&&Object.keys(x)[0].startsWith('browserReceipt:'))throw Error('PRIVATE-CANARY');Object.assign(state.saved,structuredClone(x));if(Object.keys(x)[0].startsWith('browserReceipt:'))await state.afterReceipt?.()}}},tabs:{async get(id){state.reads++;if(state.absent)throw Error();return{id,windowId:state.move&&state.reads>1?9:8,active:state.active,incognito:false,discarded:false,status:'complete',url:state.url,title:'PRIVATE-CANARY',pendingUrl:state.pending}},async update(id,args){assert.equal(id,7);assert.deepEqual({...args},{active:true});state.updates++;state.active=true;if(state.loseTab)throw Error('PRIVATE-CANARY')}},windows:{async get(id){return{id,type:'normal',state:'normal',focused:state.focused}},async update(id,args){assert.equal(id,8);assert.deepEqual({...args},{focused:true});state.focuses++;state.onFocus?.();if(state.neverFocus){}else if(state.delayFocus)setTimeout(()=>{state.focused=true;},50);else state.focused=true;if(state.loseWindow)throw Error('PRIVATE-CANARY')}}};
 const context=vm.createContext({URL,Date,TextEncoder,setTimeout,clearTimeout,crypto:require('node:crypto').webcrypto});for(const file of ['protocol.js','tab-metadata.js'])vm.runInContext(fs.readFileSync(path.join(__dirname,'..',file),'utf8'),context);
 const enrollment={profileChannel:'p',browserInstance:'b',origins:['https://fixture.test','https://other.test']},fence={brokerEpoch:'be',channelEpoch:'ce',scopeHash:'f'.repeat(64)};
 const query={type:'tabLocation',requestId:'a'.repeat(64),tabId:7,expectedOrigin:enrollment.origins[0],expectedPath:'/public/error',...fence,deadlineUnixMs:Date.now()+2000};
 const command={type:'browser.activateTab',requestId:'a'.repeat(64),attemptId:'b'.repeat(64),origin:enrollment.origins[0],...fence,deadlineUnixMs:Date.now()+3000,tabId:7};
 return{state,command,query,api,inventory:(r={type:'tabInventory',requestId:query.requestId,expectedOrigin:query.expectedOrigin,...fence,deadlineUnixMs:Date.now()+1000},config=enrollment)=>context.MechanizeTabMetadata.inventory(api,r,fence,config,()=>state.current),match:(r=query)=>context.MechanizeTabMetadata.match(api,r,fence,enrollment,()=>state.current),activate:(r=command)=>context.MechanizeTabMetadata.activate(api,r,fence,enrollment,()=>state.current),status:()=>{const intent=state.saved["browserIntent:"+command.attemptId];return context.MechanizeTabMetadata.activationStatus(api,{type:"browser.activationStatus",requestId:"e".repeat(64),attemptId:command.attemptId,...fence,deadlineUnixMs:Date.now()+1000,originalBrokerEpoch:fence.brokerEpoch,originalChannelEpoch:fence.channelEpoch,originalScopeHash:fence.scopeHash,origin:command.origin,tabId:command.tabId,fingerprintSHA256:intent?.fingerprint||"0".repeat(64)},fence,enrollment,()=>state.current);},safePath:context.MechanizeTabMetadata.safePath};
}
test('exact background tab origin/path comparison ignores private query fragment and title',async()=>{const f=fixture(),r=await f.match();assert.equal(r.available,true);assert.equal(r.matchesExpectedOrigin,true);assert.equal(r.pathChecked,true);assert.equal(r.matchesExpectedPath,true);assert.ok(!JSON.stringify(r).includes('PRIVATE-CANARY'));assert.ok(!JSON.stringify(r).includes('/public/error'));assert.equal(f.state.updates,0);assert.equal(f.state.focuses,0);const mismatch=await f.match({...f.query,expectedOrigin:'https://other.test'});assert.equal(mismatch.available,true);assert.equal(mismatch.pathChecked,true);assert.equal(mismatch.matchesExpectedOrigin,false);assert.equal(mismatch.matchesExpectedPath,false)});
test('path validation is canonical and bounded, metadata errors are value-free',async()=>{const f=fixture();for(const value of ['/../x','/%2e%2e/x','/x/%2E','/%00','/%0a','/%7f','/%C2%85','/x?key=value','/x#y','//foreign','/x\\y','/x\u0001','/%zz'])assert.equal(f.safePath('https://fixture.test',value),false,value);for(const value of ['','/','/public/error','/encoded%20path'])assert.equal(f.safePath('https://fixture.test',value),true);f.state.pending='https://fixture.test/new?PRIVATE-CANARY';const r=await f.match();assert.equal(r.reason,'pendingNavigation');assert.equal(r.pathChecked,false);assert.ok(!JSON.stringify(r).includes('PRIVATE-CANARY'))});
test('stable committed URL metadata remains readable while resources load without authorizing document access',async()=>{
 const f=fixture(),get=f.api.tabs.get;f.api.tabs.get=async(...args)=>({...await get(...args),status:'loading'});
 const result=await f.match();
 assert.equal(result.available,true);assert.equal(result.matchesExpectedOrigin,true);assert.equal(result.matchesExpectedPath,true);assert.equal(result.reason,'none');
 assert.equal(f.state.reads,2);assert.equal(f.state.updates+f.state.focuses,0);assert.deepEqual(f.state.saved,{});
 assert.ok(!JSON.stringify(result).includes('PRIVATE-CANARY'));
 f.state.pending='https://other.test/provisional?PRIVATE-CANARY';
 const pending=await f.match();assert.equal(pending.available,false);assert.equal(pending.reason,'pendingNavigation');assert.equal(pending.pathChecked,false);
});
test('loading URL metadata still refuses changing targets permission or ownership across samples',async()=>{
 for(const mode of ['url','window','pending','permission','authority']){
  const f=fixture(),get=f.api.tabs.get;let reads=0;
  f.api.tabs.get=async(...args)=>{
   if(++reads===2){
    if(mode==='url')f.state.url='https://fixture.test/changed?PRIVATE-CANARY';
    if(mode==='window')f.state.move=true;
    if(mode==='pending')f.state.pending='https://other.test/provisional?PRIVATE-CANARY';
    if(mode==='permission')f.state.permitted=false;
    if(mode==='authority')f.state.current=false;
   }
   return {...await get(...args),status:'loading'};
  };
  const result=await f.match();assert.equal(result.available,false,mode);assert.equal(result.pathChecked,false,mode);assert.equal(f.state.updates+f.state.focuses,0);
  assert.ok(!JSON.stringify(result).includes('PRIVATE-CANARY'));
 }
});
test('activation changes only exact tab active state and window focus, never repeats receipt',async()=>{const f=fixture(),r=await f.activate();assert.equal(r.dispatchState,'dispatched');assert.equal(r.tabId,7);assert.equal(f.state.updates,1);assert.equal(f.state.focuses,1);assert.ok(!JSON.stringify(r).includes('PRIVATE-CANARY'));assert.ok(!JSON.stringify(f.state.saved).includes('/public/error'));assert.equal((await f.activate({...f.command,requestId:'c'.repeat(64)})).dispatchState,'dispatched');assert.equal(f.state.updates,1);assert.equal(f.state.focuses,1)});
test('partial activation and lost persisted receipt remain unknown and never replay',async()=>{for(const flag of ['loseTab','loseWindow','failReceipt']){const f=fixture();f.state[flag]=true;const r=await f.activate();assert.equal(r.dispatchState,'unknown');f.state[flag]=false;assert.equal((await f.activate()).dispatchState,'unknown');assert.equal(f.state.updates,1);const next=await f.activate({...f.command,attemptId:'d'.repeat(64)});assert.equal(next.errorCode,'unknownEffect');assert.equal(f.state.updates,1)}});
test('permission, target origin, moved window and stale authority deny before activation',async()=>{for(const flag of ['permitted','current','move','origin']){const f=fixture();if(flag==='origin')f.state.url='https://foreign.test/PRIVATE-CANARY';else f.state[flag]=flag==='move';const r=await f.activate();assert.equal(r.dispatchState,'notDispatched');assert.equal(f.state.updates,0);assert.equal(f.state.focuses,0);assert.ok(!JSON.stringify(r).includes('PRIVATE-CANARY'))}});

test('delayed focus settles under the original deadline without repeating either update',async()=>{
 const f=fixture();f.state.delayFocus=true;const result=await f.activate();
 assert.equal(result.dispatchState,'dispatched');assert.equal(result.errorCode,'none');assert.equal(f.state.updates,1);assert.equal(f.state.focuses,1);
 assert.equal(f.state.active,true);assert.equal(f.state.focused,true);
 const retained=await f.activate();assert.equal(retained.dispatchState,'dispatched');assert.equal(f.state.updates,1);assert.equal(f.state.focuses,1);
});

test('focus settling stays bounded and stops on authority origin window or permission change',async()=>{
 for(const mode of ['deadline','authority','origin','window','permission']){
  const f=fixture();f.state.neverFocus=true;f.command.deadlineUnixMs=Date.now()+90;
  f.state.onFocus=()=>{if(mode==='deadline')return;setTimeout(()=>{if(mode==='authority')f.state.current=false;if(mode==='origin')f.state.url='https://other.test/PRIVATE-CANARY';if(mode==='window')f.state.move=true;if(mode==='permission')f.state.permitted=false;},15);};
  const deadline=f.command.deadlineUnixMs,started=Date.now(),r=await f.activate();assert.equal(r.dispatchState,'unknown',mode);assert.equal(f.command.deadlineUnixMs,deadline);assert.ok(Date.now()-started<300,mode);assert.equal(f.state.updates,1);assert.equal(f.state.focuses,1);assert.ok(!JSON.stringify(r).includes('CANARY'));
  if(mode==='authority')assert.equal(r.errorCode,'authorityChanged');if(mode==='origin')assert.equal(r.errorCode,'originDenied');if(mode==='permission')assert.equal(r.errorCode,'permissionUnavailable');
 }
});

test('terminal receipt is write-once when deadline or authority changes after persistence',async()=>{
 for(const mode of ['deadline','authority','lostStorageAck']){
  const f=fixture();f.command.deadlineUnixMs=Date.now()+80;
  f.state.afterReceipt=async()=>{if(mode==='deadline')await new Promise(r=>setTimeout(r,90));if(mode==='authority')f.state.current=false;if(mode==='lostStorageAck')throw Error('PRIVATE-CANARY');};
  const result=await f.activate(),retained=f.state.saved['browserReceipt:'+f.command.attemptId];
  assert.equal(retained.dispatchState,'dispatched',mode);assert.equal(retained.errorCode,'none');assert.equal(f.state.updates,1);assert.equal(f.state.focuses,1);
  if(mode!=='lostStorageAck')assert.equal(result.dispatchState,'dispatched');else assert.equal(result.dispatchState,'unknown');
  f.state.current=true;f.state.afterReceipt=null;const replay=await f.activate({...f.command,requestId:'c'.repeat(64),deadlineUnixMs:Date.now()+1000});assert.equal(replay.dispatchState,'dispatched');assert.equal(f.state.updates,1);assert.equal(f.state.focuses,1);
 }
});

test('activation status authenticates terminal journal without changing outcome or replaying input',async()=>{
 for(const mode of ['dispatched','unknown','missingReceipt','pending','wrongAction','wrongFingerprint','extraReceipt','staleAuthority','restartMissingJournal']){
  const f=fixture();if(mode==='unknown')f.state.loseWindow=true;
  await f.activate();const key='browserReceipt:'+f.command.attemptId,intent='browserIntent:'+f.command.attemptId;
  if(mode==='missingReceipt')delete f.state.saved[key];
  if(mode==='pending')f.state.saved[key].dispatchState='pending';
  if(mode==='wrongAction')f.state.saved[intent].action='browser.openOrigin';
  if(mode==='wrongFingerprint')f.state.saved[intent].fingerprint='0'.repeat(64);
  if(mode==='extraReceipt')f.state.saved[key].privateValue='PRIVATE-CANARY';
  if(mode==='staleAuthority')f.state.current=false;
  if(mode==='restartMissingJournal')f.state.saved={};
  const before=JSON.stringify(f.state.saved),updates=f.state.updates,focuses=f.state.focuses,result=await f.status();
  assert.equal(result.quiescent,['dispatched','unknown'].includes(mode),mode);
  assert.equal(JSON.stringify(f.state.saved),before);assert.equal(f.state.updates,updates);assert.equal(f.state.focuses,focuses);
  assert.ok(!JSON.stringify(result).includes('PRIVATE-CANARY'));
 }
});

const inventoryRow=(id,extra={})=>({id,status:'complete',incognito:false,discarded:false,url:'https://fixture.test/path?PRIVATE-CANARY#PRIVATE-CANARY',title:'PRIVATE-CANARY',...extra});
const inventoryRequest=()=>({type:'tabInventory',requestId:'a'.repeat(64),expectedOrigin:'https://fixture.test',brokerEpoch:'be',channelEpoch:'ce',scopeHash:'f'.repeat(64),deadlineUnixMs:Date.now()+1000});
test('fresh tab inventory emits only bounded canonical IDs from exact eligible origin',async()=>{
 const f=fixture();f.api.tabs.query=async q=>{assert.equal(q.url,'https://fixture.test/*');return [inventoryRow(9),inventoryRow(7),inventoryRow(10,{incognito:true}),inventoryRow(11,{discarded:true}),inventoryRow(12,{status:'loading'}),inventoryRow(13,{pendingUrl:'https://fixture.test/PRIVATE-CANARY'}),inventoryRow(14,{url:'https://foreign.test/'}),inventoryRow(15,{url:'https://user:PRIVATE-CANARY@fixture.test/'})];};
 const r=await f.inventory();assert.equal(JSON.stringify(r),JSON.stringify({type:'tabInventoryResult',requestId:'a'.repeat(64),brokerEpoch:'be',channelEpoch:'ce',scopeHash:'f'.repeat(64),tabIds:[7,9,11,12,13],complete:true,reason:'none'}));
 assert.equal(f.state.updates+f.state.focuses+f.state.reads,0);assert.deepEqual(f.state.saved,{});assert.ok(!JSON.stringify(r).includes('PRIVATE-CANARY'));
 f.api.tabs.query=async()=>Array.from({length:201},(_,i)=>inventoryRow(2147483447+i));const limited=await f.inventory();assert.equal(limited.tabIds.length,200);assert.equal(limited.complete,false);assert.equal(limited.reason,'inventoryLimit');assert.ok(Buffer.byteLength(JSON.stringify(limited))<=4096);
});
test('tab inventory rejects stale authority permission and malformed metadata with closed reasons',async()=>{
 for(const mode of ['permission','scope','origin','deadline','future','authority','duplicate','invalidID','throw','malformed']){
  const f=fixture(),q=inventoryRequest();f.api.tabs.query=async()=>[inventoryRow(7)];
  if(mode==='permission')f.state.permitted=false;if(mode==='scope')q.scopeHash='e'.repeat(64);if(mode==='origin')q.expectedOrigin='https://foreign.test';if(mode==='deadline')q.deadlineUnixMs=Date.now()-1;if(mode==='future')q.deadlineUnixMs=Date.now()+11000;if(mode==='authority')f.state.current=false;
  if(mode==='duplicate')f.api.tabs.query=async()=>[inventoryRow(7),inventoryRow(7)];if(mode==='invalidID')f.api.tabs.query=async()=>[inventoryRow(2147483648)];if(mode==='throw')f.api.tabs.query=async()=>{throw Error('PRIVATE-CANARY')};if(mode==='malformed')q.nativeWindow=7;
  const r=await f.inventory(q);if(mode==='malformed'){assert.equal(r,null);continue;}
  assert.equal(r.complete,false,mode);assert.equal(r.tabIds.length,0,mode);assert.ok(['permissionUnavailable','authorityChanged','inventoryUnavailable'].includes(r.reason));assert.ok(!JSON.stringify(r).includes('PRIVATE-CANARY'));assert.equal(f.state.updates+f.state.focuses,0);
 }
});
test('tab inventory bounds hung config and Chrome metadata and rechecks permission and current fence',async()=>{
 for(const mode of ['config','query','permission','revoke','port']){
  const f=fixture(),q={...inventoryRequest(),deadlineUnixMs:Date.now()+35};let release;
  const held=new Promise(resolve=>{release=resolve;});f.api.tabs.query=async()=>[inventoryRow(7)];
  if(mode==='query')f.api.tabs.query=()=>held;if(mode==='permission')f.api.permissions.contains=()=>held;
  if(mode==='revoke'||mode==='port')f.api.tabs.query=async()=>{if(mode==='revoke')f.state.permitted=false;else f.state.current=false;return[inventoryRow(7)];};
  const start=Date.now(),r=await f.inventory(q,mode==='config'?()=>held:undefined);assert.equal(r.complete,false,mode);assert.equal(r.tabIds.length,0);assert.ok(Date.now()-start<250);release([inventoryRow(7)]);assert.equal(f.state.updates+f.state.focuses,0);
 }
});
