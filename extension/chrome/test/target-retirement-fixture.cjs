const assert=require('node:assert/strict');
const {identity,grant,command,fixture,privateFixture,playwrightNative,playwrightCommand}=require('./worker-fixture.cjs');
async function unknownFixture(extra={}){
 const f=await privateFixture(true),c=await playwrightCommand({attemptId:'d'.repeat(64),...extra});
 await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'});
 await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
 await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
 assert.equal(f.storage.mechanizePlaywrightJournalV1.records[c.attemptId].receipt.dispatchState,'unknown');
 return {f,c};
}
const retire=(c,fence=grant)=>command('retire-original','executor.retire',{attemptId:c.attemptId,locator:undefined,controlLease:c.controlLease,fingerprintVersion:2,fingerprintSHA256:c.fingerprintSHA256,...fence});
async function restartUnknown(extra={}){
 const original=await unknownFixture(extra),before=JSON.stringify(original.f.storage.mechanizePlaywrightJournalV1);
 original.f.disconnect();
 const f=await fixture({}, {enroll:false,localState:structuredClone(original.f.storage)});
 f.state.inventoryTabs=[{id:8,url:'https://fixture.example.test/fresh'}];
 f.state.framesByTab={8:[{frameId:0,parentFrameId:-1,documentId:'fresh-document',url:'https://fixture.example.test/fresh',frameType:'outermost_frame',documentLifecycle:'active'}]};
 f.state.emptyRendererReceipts=true;f.state.reconnectSupported=true;f.state.boundFingerprintVersion=2;f.state.boundDynamicIdentity=true;
 return {f,c:original.c,before};
}

module.exports={unknownFixture,restartUnknown,retire};
