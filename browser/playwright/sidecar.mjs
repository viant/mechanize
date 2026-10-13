import {createInterface} from 'node:readline';
import {randomBytes} from 'node:crypto';
import {PlaywrightEngine} from './engine.mjs';

// Private child-process IPC. stdout contains protocol frames only. Native Go
// owns principal/consent, exact bindings, quarantine and durable receipts.
const limit=512*1024,pending=new Map(),relays=new Map();
let active;
const emit=value=>{const wire=JSON.stringify(value);if(Buffer.byteLength(wire)<=limit)process.stdout.write(wire+'\n');};
const fail=(code,dispatchState='notDispatched')=>Object.assign(Error('Local Playwright IPC unavailable'),{code,dispatchState});
function callback(execution,method,params,cleanup=false){
  if(active!==execution)return Promise.reject(fail('playwrightExecutionRequired'));
  const id=randomBytes(16).toString('hex');
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{pending.delete(id);reject(fail('playwrightHostDeadline',method==='relay.send'?'unknown':'notDispatched'));},Math.max(1,(cleanup?Date.now()+1000:execution.deadline)-Date.now()));
    pending.set(id,{resolve,reject,timer,execution});
    emit({type:'callback',id,executionId:execution.id,method,params});
  });
}
// Only runtime/module code survives an invocation; the engine's authority and
// attempt/result state must have the same lifetime as its original command.
const newEngine=execution=>{
  const call=(method,params,cleanup)=>callback(execution,method,params,cleanup);
  return new PlaywrightEngine({
    admit:command=>call('admit',{command}),
    current:()=>call('current',{executionId:execution.executionId}),
    async openRelay(authority){
      const opened=await call('relay.open',{executionId:execution.executionId});
      if(active!==execution||!opened||typeof opened.relayId!=='string'||!/^[A-Za-z0-9._:-]{1,128}$/.test(opened.relayId))throw fail('playwrightRelayDenied');
      const listeners=new Set();relays.set(opened.relayId,listeners);
      execution.relayId=opened.relayId;
      // host.current owns the native authority RPC. The local transport check
      // verifies only this exact relay lifetime instead of sending it twice.
      return {origin:authority.origin,current:async()=>active===execution&&execution.relayId===opened.relayId&&Date.now()<execution.deadline,
        onEvent(listener){listeners.add(listener);return()=>listeners.delete(listener);},
        send:(method,params,deadlineUnixMs)=>call('relay.send',{relayId:opened.relayId,method,params,deadlineUnixMs}),
        async close(){if(active!==execution)return;relays.delete(opened.relayId);await call('relay.close',{relayId:opened.relayId},true);execution.relayId=undefined;},
      };
    },
    // Confirmation of the already committed upstream intent, never reservation.
    commitIntent:descriptor=>call('intent.confirm',descriptor),
    persistReceipt:receipt=>call('receipt.persist',receipt,true),
    redact:value=>call('relay.redact',{relayId:execution.relayId,value}),
  });
};
const lines=createInterface({input:process.stdin,crlfDelay:Infinity});
lines.on('line',line=>{
  if(Buffer.byteLength(line)>limit){lines.close();process.exitCode=1;return;}
  let message;try{message=JSON.parse(line);}catch{return;}
  if(message.type==='callbackResult'){
    const held=pending.get(message.id);if(!held||held.execution!==active||message.executionId!==undefined&&message.executionId!==active.id)return;
    pending.delete(message.id);clearTimeout(held.timer);
    if(message.errorCode)held.reject(fail(/^playwright[A-Za-z]+$/.test(message.errorCode)?message.errorCode:'playwrightHostDenied',message.dispatchState==='unknown'?'unknown':'notDispatched'));
    else held.resolve(message.result);return;
  }
  if(message.type==='relayEvent'){
    if(!active||message.executionId!==undefined&&message.executionId!==active.id||typeof message.method!=='string'||Buffer.byteLength(JSON.stringify(message.params||{}))>limit)return;
    for(const listener of relays.get(message.relayId)||[])listener({method:message.method,params:message.params});return;
  }
  if(message.type!=='execute'||Object.keys(message).some(k=>!['type','id','executionId','command'].includes(k))||typeof message.id!=='string'||!/^[A-Za-z0-9._:-]{1,128}$/.test(message.id))return;
  if(active){emit({type:'result',id:message.id,result:{requestId:message.command?.requestId,dispatchState:'notDispatched',effectState:'none',errorCode:'playwrightBusy'}});return;}
  if(message.executionId!==undefined&&(typeof message.executionId!=='string'||!/^[A-Za-z0-9._:-]{1,128}$/.test(message.executionId)))return;
  active={id:message.id,executionId:message.executionId??message.id,deadline:message.command?.deadlineUnixMs};
  const execution=active;
  const finish=result=>{
    for(const [id,held] of pending){if(held.execution===execution){pending.delete(id);clearTimeout(held.timer);held.reject(fail('playwrightExecutionRequired'));}}
    relays.clear();execution.relayId=undefined;active=undefined;
    // Terminal frames establish that no old relay/callback/authority remains.
    emit({type:'result',id:message.id,result});
  };
  newEngine(execution).execute(message.command).then(finish,()=>finish({dispatchState:'unknown',effectState:'unknown',errorCode:'playwrightUnavailable'}));
});
lines.on('close',()=>{for(const p of pending.values()){clearTimeout(p.timer);p.reject(fail('playwrightHostDisconnected'));}pending.clear();});
