import {test} from 'node:test';
import assert from 'node:assert/strict';
import {errors as playwrightErrors} from 'playwright-core';
import {PlaywrightEngine} from '../engine.mjs';
import fingerprint from '../fingerprint.cjs';

async function mutation(attempt='attempt-one') {
 const c={requestId:attempt,action:'element.press',identity:{profileChannel:'fixture',browserInstance:'isolated',tabId:1,frameId:0,documentId:'document',documentGeneration:1},brokerEpoch:'broker',channelEpoch:'channel',scopeHash:'a'.repeat(64),deadlineUnixMs:Date.now()+2000,locator:{strategy:'id',value:'public-control',exact:true},attemptId:attempt,controlLease:{id:'lease',generation:1},fingerprintVersion:2};
 c.fingerprintSHA256=(await fingerprint.mutationV2(c)).sha256;return c;
}
function host(admit) {
 const calls={current:0,relay:0,intent:0,receipt:0,redact:0};
 return {calls,admit,current:async()=>{calls.current++;return false;},openRelay:async()=>{calls.relay++;throw Error('Unexpected relay');},commitIntent:async()=>{calls.intent++;return false;},persistReceipt:async()=>{calls.receipt++;return false;},redact:async()=>{calls.redact++;throw Error('Unexpected read');}};
}
for(const sameAttempt of [false,true])test(`execution lane is acquired before asynchronous fingerprint (${sameAttempt?'same':'different'} attempt)`,{timeout:5000},async()=>{
 const first=await mutation(),second=sameAttempt?structuredClone(first):await mutation('attempt-two');
 let release,entered,admissions=0;const entry=new Promise(resolve=>{entered=resolve;});
 const fixture=host(async()=>{admissions++;if(admissions>1)return null;entered();return new Promise(resolve=>{release=resolve;});});
 const engine=new PlaywrightEngine(fixture),active=engine.execute(first);
 try{
  const denied=await engine.execute(second);
  assert.equal(denied.errorCode,'playwrightBusy');assert.equal(denied.dispatchState,'notDispatched');assert.equal(denied.effectState,'none');
  await entry;assert.equal(admissions,1);
  // The refused call's finally block must not clear the first caller's lane.
  assert.equal((await engine.execute(second)).errorCode,'playwrightBusy');assert.equal(admissions,1);
  assert.deepEqual(fixture.calls,{current:0,relay:0,intent:0,receipt:0,redact:0});
 }finally{release?.(null);await active;}
 assert.equal((await engine.execute(second)).errorCode,'playwrightAuthorityDenied');assert.equal(admissions,2);
});
test('trusted Playwright timeout and bounded admission expiry use a closed deadline reason', {timeout:5000},async()=>{
 for(const kind of ['playwright','lookalike','bounded']){
  const fixture=host(async()=>{
   if(kind==='bounded')return new Promise(()=>{});
   if(kind==='playwright')throw new playwrightErrors.TimeoutError('PRIVATE-CANARY');
   throw Object.assign(Error('PRIVATE-CANARY'),{name:'TimeoutError'});
  });
  const engine=new PlaywrightEngine(fixture),command=await mutation();
  if(kind==='bounded'){command.deadlineUnixMs=Date.now()+50;command.fingerprintSHA256=(await fingerprint.mutationV2(command)).sha256;}
  const result=await engine.execute(command);
  assert.equal(result.errorCode,kind==='lookalike'?'playwrightUnavailable':'playwrightDeadline');assert.equal(result.dispatchState,'notDispatched');assert.equal(result.effectState,'none');assert.ok(!JSON.stringify(result).includes('CANARY'));assert.deepEqual(fixture.calls,{current:0,relay:0,intent:0,receipt:0,redact:0});
 }
});
