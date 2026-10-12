import {createInterface} from 'node:readline';
import {randomBytes} from 'node:crypto';
import {PlaywrightEngine} from './engine.mjs';

// Private child-process IPC. stdout contains protocol frames only. Native Go
// owns principal/consent, exact bindings, quarantine and durable receipts.
const limit=512*1024,pending=new Map(),relays=new Map();
let active,activeRelay;
const emit=value=>{const wire=JSON.stringify(value);if(Buffer.byteLength(wire)<=limit)process.stdout.write(wire+'\n');};
const fail=(code,dispatchState='notDispatched')=>Object.assign(Error('Local Playwright IPC unavailable'),{code,dispatchState});
function callback(method,params,cleanup=false){
  if(!active)return Promise.reject(fail('playwrightExecutionRequired'));
  const id=randomBytes(16).toString('hex');
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{pending.delete(id);reject(fail('playwrightHostDeadline',method==='relay.send'?'unknown':'notDispatched'));},Math.max(1,(cleanup?Date.now()+1000:active.deadline)-Date.now()));
    pending.set(id,{resolve,reject,timer});
    emit({type:'callback',id,executionId:active.id,method,params});
  });
}
const engine=new PlaywrightEngine({
  admit:command=>callback('admit',{command}),
  current:()=>callback('current',{executionId:active.id}),
  async openRelay(authority){
    const execution=active;
    const opened=await callback('relay.open',{executionId:active.id});
    if(!opened||typeof opened.relayId!=='string'||!/^[A-Za-z0-9._:-]{1,128}$/.test(opened.relayId))throw fail('playwrightRelayDenied');
    const listeners=new Set();relays.set(opened.relayId,listeners);
    activeRelay=opened.relayId;
    // host.current owns the native authority RPC. The local transport check
    // verifies only this exact relay lifetime instead of sending it twice.
    return {origin:authority.origin,current:async()=>active===execution&&activeRelay===opened.relayId&&Date.now()<execution.deadline,
      onEvent(listener){listeners.add(listener);return()=>listeners.delete(listener);},
      send:(method,params,deadlineUnixMs)=>callback('relay.send',{relayId:opened.relayId,method,params,deadlineUnixMs}),
      async close(){relays.delete(opened.relayId);await callback('relay.close',{relayId:opened.relayId},true);activeRelay=undefined;},
    };
  },
  // Confirmation of the already committed upstream intent, never reservation.
  commitIntent:descriptor=>callback('intent.confirm',descriptor),
  persistReceipt:receipt=>callback('receipt.persist',receipt,true),
  redact:value=>callback('relay.redact',{relayId:activeRelay,value}),
});
const lines=createInterface({input:process.stdin,crlfDelay:Infinity});
lines.on('line',line=>{
  if(Buffer.byteLength(line)>limit){lines.close();process.exitCode=1;return;}
  let message;try{message=JSON.parse(line);}catch{return;}
  if(message.type==='callbackResult'){
    const held=pending.get(message.id);if(!held)return;
    pending.delete(message.id);clearTimeout(held.timer);
    if(message.errorCode)held.reject(fail(/^playwright[A-Za-z]+$/.test(message.errorCode)?message.errorCode:'playwrightHostDenied',message.dispatchState==='unknown'?'unknown':'notDispatched'));
    else held.resolve(message.result);return;
  }
  if(message.type==='relayEvent'){
    if(typeof message.method!=='string'||Buffer.byteLength(JSON.stringify(message.params||{}))>limit)return;
    for(const listener of relays.get(message.relayId)||[])listener({method:message.method,params:message.params});return;
  }
  if(message.type!=='execute'||Object.keys(message).some(k=>!['type','id','command'].includes(k))||typeof message.id!=='string'||!/^[A-Za-z0-9._:-]{1,128}$/.test(message.id))return;
  if(active){emit({type:'result',id:message.id,result:{requestId:message.command?.requestId,dispatchState:'notDispatched',effectState:'none',errorCode:'playwrightBusy'}});return;}
  active={id:message.id,deadline:message.command?.deadlineUnixMs};
  engine.execute(message.command).then(result=>emit({type:'result',id:message.id,result}),()=>emit({type:'result',id:message.id,result:{dispatchState:'unknown',effectState:'unknown',errorCode:'playwrightUnavailable'}})).finally(()=>{active=undefined;});
});
lines.on('close',()=>{for(const p of pending.values()){clearTimeout(p.timer);p.reject(fail('playwrightHostDisconnected'));}pending.clear();});
