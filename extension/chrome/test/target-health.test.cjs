const test=require('node:test'),assert=require('node:assert/strict');
const {identity,grant,command,privateFixture,playwrightNative,playwrightCommand}=require('./worker-fixture.cjs');
async function lostAck(){
 const f=await privateFixture(true),a=await playwrightCommand({requestId:'A-open',attemptId:'d'.repeat(64)});
 await playwrightNative(f,a,'open',{command:a,origin:'https://fixture.example.test'});
 f.state.debuggerHook=method=>{if(method==='Input.dispatchMouseEvent')throw Error('fixture lost actual input ACK');};
 const result=await playwrightNative(f,a,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
 delete f.state.debuggerHook;
 assert.equal(result.dispatchState,'unknown');
 assert.equal(f.state.debuggerInputs.filter(x=>x.method==='Input.dispatchMouseEvent').length,1);
 assert.equal(f.storage.mechanizePlaywrightJournalV1.records[a.attemptId].receipt.dispatchState,'unknown');
 return {f,a};
}
async function acquire(f,i,lease,requestId){
 f.registerDocument(i,'https://fixture.example.test');
 f.state.framesByTab ||= {};f.state.framesByTab[i.tabId]=[{frameId:0,documentId:i.documentId,url:f.state.frameURL}];
 f.state.publicReply={requestId,identity:i,validated:true,controlLease:lease};
 await f.receive(command(requestId,'executor.acquire',{identity:i,attemptId:undefined,locator:undefined,controlLease:lease}));
 delete f.state.publicReply;
 return f.messages.at(-1);
}
test('actual lost A input ACK keeps A blocked while another tab acquires and runs normal and Playwright input',async()=>{
 const {f,a}=await lostAck(),before=JSON.stringify(f.storage.mechanizePlaywrightJournalV1.records[a.attemptId]);
 const bIdentity={...identity,tabId:8,documentId:'B'},lease={id:'B-lease',generation:2};
 assert.equal((await acquire(f,bIdentity,lease,'B-acquire')).validated,true);
 assert.equal((await acquire(f,identity,{id:'A-replacement',generation:2},'A-acquire')).error.code,'unknownEffect');
 const normal=command('B-normal','element.select',{identity:bIdentity,attemptId:'e'.repeat(64),controlLease:lease,locator:{strategy:'id',value:'color',exact:true},args:{value:'blue'},fingerprintVersion:2});
 normal.fingerprintSHA256=(await require('../fingerprint.js').mutationV2(normal)).sha256;
 f.state.publicReply={requestId:normal.requestId,identity:bIdentity,attemptId:normal.attemptId,dispatchState:'dispatched',effectState:'unverified'};
 const deliveries=f.state.deliveries;await f.receive(normal);delete f.state.publicReply;
 assert.equal(f.messages.at(-1).dispatchState,'dispatched');assert.equal(f.state.deliveries,deliveries+1);
 const b=await playwrightCommand({requestId:'B-playwright',identity:bIdentity,controlLease:lease,attemptId:'b'.repeat(64)});
 assert.equal((await playwrightNative(f,b,'open',{command:b,origin:'https://fixture.example.test'})).result.opened,true);
 await playwrightNative(f,b,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
 await playwrightNative(f,b,'send',{method:'Input.dispatchMouseEvent',params:{type:'mouseReleased',button:'left',buttons:0,modifiers:0,clickCount:1,x:20,y:20}});
 assert.equal((await playwrightNative(f,b,'receipt',{dispatchState:'dispatched',effectState:'unverified'})).result.persisted,true);
 await playwrightNative(f,b,'close');
 assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1.records[a.attemptId]),before);
 assert.equal(f.unknownCount(),1);
 const inputs=f.state.debuggerInputs.filter(x=>x.method.startsWith('Input.')).length;
 f.state.inventoryTabs=[{id:8,url:f.state.url}];
 await f.receive(command('A-death','executor.retire',{identity:a.identity,attemptId:a.attemptId,locator:undefined,controlLease:a.controlLease,fingerprintVersion:2,fingerprintSHA256:a.fingerprintSHA256}));
 assert.equal(f.messages.at(-1).retiredAuthorityQuiesced,true);
 const next=await playwrightCommand({requestId:'B-again',identity:bIdentity,controlLease:lease,attemptId:'c'.repeat(64)});
 assert.equal((await playwrightNative(f,next,'open',{command:next,origin:'https://fixture.example.test'})).result.opened,true,'A death must not revoke B lease');
 await playwrightNative(f,next,'close');
 assert.equal(f.state.debuggerInputs.filter(x=>x.method.startsWith('Input.')).length,inputs);
 assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1.records[a.attemptId]),before);
 f.disconnect();assert.equal(f.unknownCount(),1,'disconnect rearms original A history');
 f.nativeMessage({type:'playwright.open',requestId:'offline-open',relayId:'offline-relay',deadlineUnixMs:next.deadlineUnixMs,command:next,origin:'https://fixture.example.test'});
 for(let n=0;n<20;n++)await new Promise(resolve=>setImmediate(resolve));
 assert.equal(f.state.debuggerInputs.filter(x=>x.method.startsWith('Input.')).length,inputs);
 assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1.records[a.attemptId]),before);
});
test('same-tab successor document cannot bypass an old uncertain CDP input',async()=>{
 const {f}=await lostAck();
 const successor={...identity,documentId:'successor',documentGeneration:2};
 const result=await acquire(f,successor,{id:'successor-lease',generation:2},'successor');
 assert.equal(result.error.code,'unknownEffect');
 assert.equal(f.unknownCount(),1);
});
module.exports={lostAck,acquire};

test('legacy unbound hazards and qualification attention still inhibit another tab',async()=>{
 const f=await privateFixture(true),other={...identity,tabId:8,documentId:'B'};
 f.reconnectBarrier('unknown');
 assert.equal((await acquire(f,other,{id:'B-lease',generation:1},'legacy-B')).error.code,'unknownEffect');
 const {f:g,a}=await lostAck(),before=JSON.stringify(g.storage.mechanizePlaywrightJournalV1.records[a.attemptId]);
 await g.receive({type:'processQualified',...grant,trustScope:'desktop',scopeQualified:true,profileQualified:false,fixtureOnly:false,executorChallenge:'retry-challenge',mutationFingerprintVersion:2});
 assert.equal(g.messages.at(-1).type,'attention');
 const candidate=await playwrightCommand({identity:other,requestId:'unqualified-B',attemptId:'c'.repeat(64),controlLease:{id:'B-lease',generation:1}});
 assert.ok((await playwrightNative(g,candidate,'open',{command:candidate,origin:'https://fixture.example.test'})).errorCode);
 assert.equal(JSON.stringify(g.storage.mechanizePlaywrightJournalV1.records[a.attemptId]),before);
 assert.equal(g.state.debuggerInputs.filter(x=>x.method.startsWith('Input.')).length,1);
});
