import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import fingerprint from '../fingerprint.cjs';

test('actual sidecar and production worker relay complete the protected synthetic workflow',{timeout:45000},async()=>{
  const env=Object.fromEntries(['PATH','HOME','TMPDIR','MECHANIZE_FIXTURE_CHROMIUM'].filter(k=>process.env[k]).map(k=>[k,process.env[k]]));
  const peer=spawn(process.execPath,[new URL('./native-fixture-peer.mjs',import.meta.url).pathname],{env,stdio:['pipe','pipe','pipe']});
  const sidecar=spawn(process.execPath,[new URL('../sidecar.mjs',import.meta.url).pathname],{env,stdio:['pipe','pipe','pipe']});
  const pending=new Map(),results=new Map(),trace=[];let readyResolve,command,sequence=0,privacyReady=false;
  let sidecarError='';sidecar.stderr.on('data',chunk=>{sidecarError=(sidecarError+String(chunk)).slice(0,4000);});sidecar.on('exit',code=>trace.push('sidecar-exit:'+code));
  const ready=new Promise(resolve=>{readyResolve=resolve});
  const peerWrite=m=>peer.stdin.write(JSON.stringify(m)+'\n'),sidecarWrite=m=>sidecar.stdin.write(JSON.stringify(m)+'\n');
  const peerLines=createInterface({input:peer.stdout}),sidecarLines=createInterface({input:sidecar.stdout});
  peerLines.on('line',line=>{
    const m=JSON.parse(line);
    trace.push('peer:'+m.type+(m.errorCode?':'+m.errorCode:''));
    if(m.type==='documents'){document=m.documents[0];return;}
    if(m.type==='playwright.event'){sidecarWrite({type:'relayEvent',relayId:m.relayId,method:m.method,params:m.params});return;}
    if(m.type==='fixture.ready'){readyResolve(m);return;}
    const key=m.requestId||m.type;pending.get(key)?.(m);pending.delete(key);
  });
  function peerCall(message,responseType){return new Promise((resolve,reject)=>{
    const key=message.requestId||responseType,timer=setTimeout(()=>{pending.delete(key);reject(Error('Fixture native response deadline'));},5000);
    pending.set(key,result=>{clearTimeout(timer);resolve(result)});peerWrite(message);
  });}
  sidecarLines.on('line',async line=>{
    const m=JSON.parse(line);
    trace.push('sidecar:'+m.type+(m.method?':'+m.method:''));
    if(m.type==='result'){results.get(m.id)?.(m.result);results.delete(m.id);return;}
    if(m.type!=='callback')return;
    try{
      let result;
      if(m.method==='admit')result={identity:command.identity,origin:document.origin,brokerEpoch:command.brokerEpoch,channelEpoch:command.channelEpoch,scopeHash:command.scopeHash,controlLease:command.controlLease,fingerprintSHA256:command.fingerprintSHA256,committed:true,privateQuarantined:!privacyReady,protectedOrigin:true,privacyState:'redacted-dom',domReadQualified:privacyReady,privacyRevision:'fixture-private-ready-1'};
      else if(m.method==='current')result=privacyReady&&Date.now()<command.deadlineUnixMs;
      else if(m.method==='intent.confirm')result=true;
      else {
        const native={type:'playwright.'+({'relay.open':'open','relay.send':'send','relay.redact':'redact','relay.close':'close','receipt.persist':'receipt'}[m.method]),requestId:'native-'+(++sequence),relayId:'fixture-relay',deadlineUnixMs:command.deadlineUnixMs};
        if(m.method==='relay.open'){native.command=command;native.origin=document.origin;}
        if(m.method==='relay.send'){native.method=m.params.method;native.params=m.params.params;}
        if(m.method==='relay.redact')native.value=m.params.value;
        if(m.method==='receipt.persist')Object.assign(native,{dispatchState:m.params.dispatchState,effectState:m.params.effectState,...(m.params.errorCode?{errorCode:m.params.errorCode}:{}),...(m.params.inputSemantics?{inputSemantics:m.params.inputSemantics}:{})});
        const reply=await peerCall(native);
        if(reply.errorCode){sidecarWrite({type:'callbackResult',id:m.id,errorCode:reply.errorCode,dispatchState:reply.dispatchState});return;}
        result=m.method==='relay.open'?{relayId:native.relayId}:m.method==='relay.redact'?reply.result.value:m.method==='receipt.persist'?reply.result.persisted:m.method==='relay.close'?reply.result.closed:reply.result;
      }
      sidecarWrite({type:'callbackResult',id:m.id,result});
    }catch{sidecarWrite({type:'callbackResult',id:m.id,errorCode:'playwrightHostDenied',dispatchState:'notDispatched'});}
  });
  let document;
  async function execute(action,target,args){
    command={requestId:'command-'+(++sequence),action,identity:Object.fromEntries(['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'].map(k=>[k,document[k]])),brokerEpoch:'fixture-broker',channelEpoch:'fixture-channel',scopeHash:'a'.repeat(64),deadlineUnixMs:Date.now()+3000,locator:target.startsWith('details-')?{strategy:'role',value:'region',name:'Expanded record',exact:true,index:target.endsWith('A')?0:1,order:'document'}:target.startsWith('expand-')||target.startsWith('select-')?{strategy:'role',value:'button',name:target.startsWith('expand-')?'Expand current row':'Select current row',exact:true,index:target.endsWith('A')?0:1,order:'document'}:{strategy:'id',value:target,exact:true},...(args?{args}:{})};
    if(action!=='read'){Object.assign(command,{attemptId:'attempt-'+sequence,controlLease:{id:'fixture-lease',generation:1},fingerprintVersion:2});command.fingerprintSHA256=(await fingerprint.mutationV2(command)).sha256;}
    return new Promise((resolve,reject)=>{
      const id='execute-'+sequence,timer=setTimeout(()=>reject(Error('Fixture sidecar response deadline '+action+' '+target+' '+trace.slice(-30).join(',')+'; diagnostic='+sidecarError.split('\n').slice(0,3).join(' ').replace(/fixture-private-value|private-input-must-not-route/g,'[redacted]'))),7000);
      results.set(id,result=>{clearTimeout(timer);resolve(result)});sidecarWrite({type:'execute',id,command});
    });
  }
  try{
    document=(await ready).document;
    const denied=await execute('element.fill','password',{value:'private-input-must-not-route'});assert.equal(denied.dispatchState,'notDispatched');
    privacyReady=(await peerCall({type:'fixture.private-login'},'fixture.private-ready')).privacyReady;assert.equal(privacyReady,true);
    const timings=[];
    for(const [action,target,args] of [['read','ready',{attribute:'text'}],['element.fill','filter',{value:'group-blue'}],['element.press','expand-A'],['read','details-A',{attribute:'text'}],['element.press','select-A'],['element.press','expand-B'],['read','details-B',{attribute:'text'}],['element.press','select-B'],['element.press','expand-A'],['element.press','expand-A'],['element.press','review'],['read','review-result',{attribute:'text'}]]){
      if(target==='filter')await peerCall({type:'fixture.arm-timer'},'fixture.timer-armed');
      const began=performance.now(),traceStart=trace.length,result=await execute(action,target,args);
      const operationTrace=trace.slice(traceStart),currentCallbacks=operationTrace.filter(item=>item==='sidecar:callback:current').length,sendCallbacks=operationTrace.filter(item=>item==='sidecar:callback:relay.send').length;
      assert.ok(currentCallbacks<=sendCallbacks+12,'authority checks must not duplicate the same IPC callback at each local layer');
      timings.push({action,target,elapsedMs:Math.round(performance.now()-began),currentCallbacks,sendCallbacks});
      assert.equal(result.errorCode,undefined,JSON.stringify({action,target,result}));
      if(target==='filter'){const timer=await peerCall({type:'fixture.stop-timer'},'fixture.timer-stopped');assert.ok(timer.timerPublications>0);}
      if(target.startsWith('details-'))assert.match(result.value,new RegExp(target.endsWith('A')?'Record A':'Record B'));
      if(target==='review-result')assert.equal(result.value,'Review: Record A, Record B; total 2 items');
      assert.equal(JSON.stringify(result).includes('fixture-private-value'),false);
    }
    await peerCall({type:'fixture.reflect'},'fixture.reflected');const redacted=await execute('read','review-result',{attribute:'text'});assert.equal(redacted.value,'[redacted]');
    const state=await peerCall({type:'fixture.peek'},'fixture.state');assert.equal(state.reviewMatched,true);assert.equal(state.inputCount,8);assert.equal(state.attachCount,1);assert.equal(state.unknownCount,0);
    await peerCall({type:'fixture.arm-target-replacement'},'fixture.target-replacement-armed');
    const replacement=await execute('element.press','review');assert.equal(replacement.dispatchState,'notDispatched');
    let negativeState=await peerCall({type:'fixture.peek'},'fixture.state');assert.equal(negativeState.inputCount,8);assert.equal(negativeState.unknownCount,0);
    await peerCall({type:'fixture.observe'},'fixture.observed');
    await peerCall({type:'fixture.arm-sensitive-switch'},'fixture.sensitive-switch-armed');
    const sensitive=await execute('element.fill','filter',{value:'group-green'});assert.equal(sensitive.dispatchState,'notDispatched');
    negativeState=await peerCall({type:'fixture.peek'},'fixture.state');assert.equal(negativeState.inputCount,8);assert.equal(negativeState.unknownCount,0);
    console.log(JSON.stringify({fixture:'actual-sidecar+production-worker+headless-CDP',protectedDOMQualified:privacyReady,reviewMatched:true,credentialCanaryRedacted:true,inputCount:state.inputCount,attachCount:state.attachCount,timerPublications:state.timerPublications,replacementAndSensitiveInputDenied:true,maxNativeFrameBytes:state.maxNativeFrameBytes,timings}));
  }finally{
    sidecar.kill();peerWrite({type:'fixture.stop'});await new Promise(resolve=>peer.once('exit',resolve));
  }
});
