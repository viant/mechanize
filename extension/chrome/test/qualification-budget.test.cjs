const test = require('node:test');
const assert = require('node:assert/strict');
const {fixture, grant} = require('./worker-fixture.cjs');
const qualify = channelEpoch => ({type:'processQualified', ...grant, channelEpoch,
  trustScope:'desktop', scopeQualified:true, profileQualified:false, fixtureOnly:false,
  executorChallenge:'fixture-challenge-'+channelEpoch, mutationFingerprintVersion:2});
const flush = async () => { for(let i=0;i<20;i++) await new Promise(resolve=>setImmediate(resolve)); };
const until = async predicate => { const deadline=process.hrtime.bigint()+2000000000n;while(!predicate()&&process.hrtime.bigint()<deadline)await new Promise(resolve=>setImmediate(resolve));assert.ok(predicate(),'bounded asynchronous metadata proof did not settle'); };
async function historicalFixture() {
  const f = await fixture({}, {enroll:false});
  f.state.inventoryTabs = [{id:7,url:f.state.url}];
  f.state.boundFingerprintVersion=2; f.state.reconnectSupported=true;
  await f.receive(qualify('historical-channel'));
  f.disconnect(); await f.connect();
  await f.receive(qualify('current-channel'));
  assert.equal(f.storage.mechanizeReconnect.history.length,1);
  assert.equal(f.publicReadCounts().documents,1);
  f.disconnect(); await f.connect(); f.messages.length=0;
  return f;
}
test('a drained qualification commit deadline automatically requests metadata recovery without input',async t=>{
  t.mock.timers.enable({apis:['setTimeout','Date']});
  const f=await historicalFixture(); let release;
  f.sessionState['browserIntent:fixture-original']={attemptId:'fixture-original'};
  f.sessionState['browserReceipt:fixture-original']={dispatchState:'dispatched',effectState:'dispatched'};
  const originalReceipts=JSON.stringify(f.sessionState);
  const originalHistory=JSON.stringify(f.storage.mechanizeReconnect.history);
  f.state.blockReconnectCommit=new Promise(resolve=>release=resolve);
  const pending=f.receive(qualify('replacement-channel'));
  for(let i=0;i<200&&!f.state.commitEntered;i++) await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.state.commitEntered,true); assert.equal(f.diagnostic().phase,'commit');
  t.mock.timers.tick(10001); await flush();
  assert.ok(f.messages.some(m=>m.type==='attention'&&m.reconnectPhase==='commit'&&m.reconnectReason==='deadline'));
  assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));
  const connections=f.state.nativeConnections;
  f.state.nativePost=message=>{if(message.type==='hello')queueMicrotask(()=>f.nativeMessage(qualify('fresh-retry-channel')));};
  release(); delete f.state.blockReconnectCommit; await pending; await flush();
  assert.equal(f.storage.lastGrant.channelEpoch,'replacement-channel');
  assert.equal(f.storage.mechanizeReconnect.history.length,1);
  assert.equal(JSON.stringify(f.sessionState),originalReceipts);
  assert.equal(f.state.deliveries,0); assert.equal(f.state.debuggerInputs,undefined);
  t.mock.timers.tick(60000); await flush();
  await until(()=>f.messages.some(m=>m.type==='executorPrepared'&&m.executorChallenge==='fixture-challenge-fresh-retry-channel'));
  assert.equal(f.state.nativeConnections,connections+1,'metadata qualification must recover once after the original commit drains');
  assert.ok(f.messages.some(m=>m.type==='executorPrepared'&&m.executorChallenge==='fixture-challenge-fresh-retry-channel'));
  assert.equal(f.storage.lastGrant.channelEpoch,'fresh-retry-channel');
  assert.ok(Object.entries(f.storage).some(([key,value])=>key.startsWith('mechanizeReconnectAudit:')&&JSON.stringify(JSON.parse(value.journalJSON).history)===originalHistory));
  assert.equal(JSON.stringify(f.sessionState),originalReceipts);
  assert.equal(f.state.permissionRequests||0,0); assert.equal(f.state.deliveries,0);
});

test('qualification owner remains draining while an expired commit API is unresolved',async t=>{
  t.mock.timers.enable({apis:['setTimeout','Date']});
  const f=await historicalFixture(); let release;
  f.state.blockReconnectCommit=new Promise(resolve=>release=resolve);
  let settled=false;
  const pending=f.receive(qualify('replacement-channel')).finally(()=>{settled=true;});
  for(let i=0;i<200&&!f.state.commitEntered;i++) await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.state.commitEntered,true);
  t.mock.timers.tick(10001); await flush();
  const settledBeforeUnderlyingCommitDrained=settled;
  const connections=f.state.nativeConnections;
  t.mock.timers.tick(60000); await flush();
  assert.equal(f.state.nativeConnections,connections,'unresolved Chrome work cannot overlap a recovery port');
  assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));
  release(); delete f.state.blockReconnectCommit; await pending; await flush();
  assert.equal(settledBeforeUnderlyingCommitDrained,false,'metadata lane must remain owned until the original Chrome write drains');
});

test('one unsuccessful deadline recovery cannot turn into an infinite reconnect loop',async t=>{
  t.mock.timers.enable({apis:['setTimeout','Date']});
  const f=await historicalFixture(); let firstRelease,secondRelease;
  f.state.blockReconnectCommit=new Promise(resolve=>firstRelease=resolve);
  const pending=f.receive(qualify('replacement-channel'));
  for(let i=0;i<200&&!f.state.commitEntered;i++) await new Promise(resolve=>setImmediate(resolve));
  t.mock.timers.tick(10001); await flush(); firstRelease(); await pending; await flush();
  f.state.commitEntered=false;
  f.state.blockReconnectCommit=new Promise(resolve=>secondRelease=resolve);
  f.state.nativePost=message=>{if(message.type==='hello')queueMicrotask(()=>f.nativeMessage(qualify('fresh-retry-channel')));};
  const connections=f.state.nativeConnections;
  t.mock.timers.tick(1000); await flush();
  for(let i=0;i<200&&!f.state.commitEntered;i++) await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.state.nativeConnections,connections+1); assert.equal(f.state.commitEntered,true);
  t.mock.timers.tick(10001); await flush();
  secondRelease(); delete f.state.blockReconnectCommit; await flush();
  t.mock.timers.tick(60000); await flush();
  assert.equal(f.state.nativeConnections,connections+1);
  assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));
  assert.equal(f.state.permissionRequests||0,0); assert.equal(f.state.deliveries,0);
});

test('a settlement that observes deadline before the timer callback still schedules one metadata recovery',async t=>{
  t.mock.timers.enable({apis:['setTimeout','Date']});
  const f=await historicalFixture(); let release;
  f.state.blockReconnectCommit=new Promise(resolve=>release=resolve);
  const pending=f.receive(qualify('replacement-channel'));
  for(let i=0;i<200&&!f.state.commitEntered;i++) await new Promise(resolve=>setImmediate(resolve));
  const connections=f.state.nativeConnections;
  t.mock.timers.setTime(Date.now()+10001);
  release(); delete f.state.blockReconnectCommit; await pending; await flush();
  assert.ok(f.messages.some(m=>m.type==='attention'&&m.reconnectReason==='deadline'));
  t.mock.timers.tick(1000); await flush();
  assert.equal(f.state.nativeConnections,connections+1);
  assert.equal(f.state.permissionRequests||0,0); assert.equal(f.state.deliveries,0);
});

test('historical ordinary document qualification records repeated metadata checks',async()=>{
  for(const documentCount of [1,16]) {
  const f=await historicalFixture(), calls=[];
  f.state.frameRows=Array.from({length:documentCount},(_,n)=>({frameId:n,documentId:n?'fixture-document-'+n:'d1',url:f.state.frameURL,frameType:n?'sub_frame':'outermost_frame'}));
  for(const [label,object,key] of [['local.get',f.chrome.storage.local,'get'],['local.set',f.chrome.storage.local,'set'],
    ['session.get',f.chrome.storage.session,'get'],['tabs.query',f.chrome.tabs,'query'],
    ['frames',f.chrome.webNavigation,'getAllFrames'],['renderer',f.chrome.tabs,'sendMessage']]) {
    const original=object[key]; object[key]=async(...args)=>{
      calls.push({api:label,phase:f.diagnostic().phase}); return original(...args);
    };
  }
  await f.receive(qualify('profile-channel'));
  assert.ok(f.messages.some(m=>m.type==='executorPrepared'));
  const counts={}; for(const row of calls){const key=row.phase+':'+row.api;counts[key]=(counts[key]||0)+1;}
  console.log(JSON.stringify({fixture:'retained historical adoption',documentCount,metadataAPICalls:calls.length,counts}));
  assert.equal(f.state.deliveries,0); assert.equal(f.state.debuggerInputs,undefined);
  }
});
