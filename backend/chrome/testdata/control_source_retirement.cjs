const fs=require('node:fs'),assert=require('node:assert/strict');
const {identity,privateFixture,privateFrame,privateSubmitFrame,privacyFrame,command,playwrightCommand,playwrightNative}=require('../../../extension/chrome/test/worker-fixture.cjs');
let stage="start";
(async()=>{
 const retire=JSON.parse(fs.readFileSync(0,'utf8'));
 const f=await privateFixture(true);
 if(retire.identity.documentId==='privacy-doc'){
  stage="privateFill";await f.receive(privateFrame());stage="privateSubmit";await f.receive(privateSubmitFrame());f.state.documentId='privacy-doc';
  stage="privacy";const proof=privacyFrame();await f.receive(proof);const promoted=f.messages.at(-1);assert.equal(promoted.ready,true);
  stage="privacyCommit";await f.receive({...proof,type:'credentialPrivacyCommit',requestId:'e'.repeat(64),identity:promoted.identity});assert.equal(f.messages.at(-1).ready,true);
  f.state.boundDynamicIdentity=true;f.state.publicReply={requestId:'new-public-lease',identity:retire.identity,validated:true,controlLease:retire.controlLease};
  stage='newLease';await f.receive(command('new-public-lease','executor.acquire',{identity:retire.identity,attemptId:undefined,locator:undefined,controlLease:retire.controlLease}));assert.equal(f.messages.at(-1).validated,true);f.state.publicReply=null;
 }
 const original=await playwrightCommand({attemptId:'a'.repeat(64),identity:retire.identity,controlLease:retire.controlLease});
 assert.equal(retire.identity.tabId,identity.tabId);assert.equal(retire.identity.frameId,0);
 stage="open";const open=await playwrightNative(f,original,'open',{command:original,origin:'https://fixture.example.test'});assert.equal(open.result.opened,true);
 stage='down';await playwrightNative(f,original,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
 stage='up';await playwrightNative(f,original,'send',{method:'Input.dispatchMouseEvent',params:{type:'mouseReleased',button:'left',buttons:0,modifiers:0,clickCount:1,x:20,y:20}});
 stage="receipt";const saved=await playwrightNative(f,original,'receipt',{dispatchState:'dispatched',effectState:'unverified'});assert.equal(saved.result.persisted,true);
 await playwrightNative(f,original,'close');
 f.state.documentId='retirement-successor';f.state.frameRows=[{frameId:0,parentFrameId:-1,documentId:f.state.documentId,url:f.state.frameURL,documentLifecycle:'active',frameType:'outermost_frame'}];
 for(const listener of f.state.committedListeners)listener({tabId:7,frameId:0,documentId:f.state.documentId});
 const before={journal:JSON.stringify(f.storage.mechanizePlaywrightJournalV1),input:f.state.debuggerInputs.length,deliveries:f.state.deliveries};
 stage="retire";await f.receive(retire);
 const result=f.messages.find(m=>m.requestId===retire.requestId);assert.equal(result?.retiredAuthorityQuiesced,true);
 assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before.journal);assert.equal(f.state.debuggerInputs.length,before.input);assert.equal(f.state.deliveries,before.deliveries);
 stage='redaction';if(retire.identity.documentId==='privacy-doc')assert.ok(!f.privacyState().redacted.includes('CANARY'));
 assert.equal(f.storage.mechanizePlaywrightJournalV1.records[original.attemptId].fingerprintSHA256,original.fingerprintSHA256);
 process.stdout.write(JSON.stringify(result));
})().catch(()=>{process.stderr.write('production source retirement fixture failed: '+stage);process.exitCode=1;});
