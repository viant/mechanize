const {test}=require('node:test');const assert=require('node:assert/strict');
const {create,KEY,ALARM,DELAYS}=require('../connection-lifecycle.js');
const flush=async()=>{for(let i=0;i<25;i++)await Promise.resolve();};
function fixture(shared={}){
 let now=100000,sequence=0;const timers=new Map(),alarms=shared.alarms||new Map(),saved=shared.saved||{},listeners=[];
 const state={enabled:true,configured:true,online:false,available:false,opens:0,closes:0,token:null,dispatched:[],permissionRequests:0};
 const clock={now:()=>now,setTimeout(fn,delay){const id=++sequence;timers.set(id,{fn,at:now+delay});return id;},clearTimeout:id=>timers.delete(id)};
 const api={storage:{local:{get:async key=>({[key]:saved[key]}),set:async value=>Object.assign(saved,structuredClone(value))}},alarms:{create:async(name,value)=>alarms.set(name,value),clear:async name=>alarms.delete(name),onAlarm:{addListener:fn=>listeners.push(fn)}}};
 const hooks={settings:async()=>({enabled:state.enabled,configured:state.configured,blocked:state.blocked}),isOpen:()=>state.online,close(){state.online=false;state.closes++;},async open(token,valid){state.opens++;state.token=token;if(state.wait)await state.wait;if(!valid())return false;state.online=state.available;return state.online;}};
 const lifecycle=create(api,hooks,clock);
 const advance=async delay=>{now+=delay;for(let round=0;round<50;round++){const due=[...timers].filter(([,v])=>v.at<=now);if(!due.length){await flush();if(![...timers.values()].some(v=>v.at<=now))break;continue;}for(const [id,v] of due){timers.delete(id);v.fn();}await flush();}};
 return {state,lifecycle,saved,alarms,timers,advance,now:()=>now,setNow:value=>{now=value;},alarm:async()=>{for(const fn of listeners)fn({name:ALARM});await flush();},shared:{saved,alarms}};
}
test('offline startup retries with capped backoff and no command or permission replay',async()=>{
 const f=fixture();await f.lifecycle.start();assert.equal(f.state.opens,1);
 for(const delay of DELAYS){assert.equal(f.lifecycle.status().nextAt-f.now(),delay);assert.equal(f.alarms.get(ALARM).when,Math.max(f.lifecycle.status().nextAt,f.now()+60000));await f.advance(delay);}
 assert.equal(f.lifecycle.status().attempt,DELAYS.length);assert.equal(f.lifecycle.status().nextAt-f.now(),900000);assert.deepEqual(Object.keys(f.saved[KEY]).sort(),['attempt','nextAt','phase','version']);assert.deepEqual(f.state.dispatched,[]);assert.equal(f.state.permissionRequests,0);
 f.state.available=true;await f.advance(900000);assert.equal(f.lifecycle.status().phase,'handshake');await f.lifecycle.acknowledged(f.state.token);assert.equal(f.lifecycle.status().nextAt,0);assert.equal(f.alarms.size,0);
});
test('duplicate disconnect and retry events create only one connection attempt',async()=>{
 const f=fixture();f.state.available=true;await Promise.all([f.lifecycle.start(),f.lifecycle.request(),f.lifecycle.request()]);assert.equal(f.state.opens,1);await f.lifecycle.acknowledged(f.state.token);
 f.state.online=false;await Promise.all([f.lifecycle.failed(f.state.token),f.lifecycle.failed(f.state.token)]);assert.equal(f.lifecycle.status().attempt,1);await f.advance(1000);assert.equal(f.state.opens,2);
 await f.lifecycle.acknowledged(f.state.token);await f.alarm();assert.equal(f.state.opens,2);f.state.online=false;await f.lifecycle.failed(f.state.token);assert.equal(f.lifecycle.status().attempt,1);
});
test('worker suspension recreates its lost alarm from bounded saved retry metadata',async()=>{
 const first=fixture();await first.lifecycle.start();first.alarms.clear();
 const resumed=fixture(first.shared);await resumed.lifecycle.start();assert.equal(resumed.state.opens,0);assert.equal(resumed.alarms.size,1);
 resumed.state.available=true;resumed.setNow(160000);await resumed.alarm();assert.equal(resumed.state.opens,1);await resumed.lifecycle.acknowledged(resumed.state.token);assert.equal(resumed.saved[KEY].phase,'idle');
});
test('unanswered native handshake expires without leaving an immortal stale port',async()=>{
 const f=fixture();f.state.available=true;await f.lifecycle.start();await f.advance(15000);assert.equal(f.state.closes,1);assert.equal(f.state.online,false);assert.equal(f.lifecycle.status().phase,'retry');await f.advance(1000);assert.equal(f.state.opens,2);
});
test('disabled or unconfigured connection cancels wake-ups and never opens a native host',async()=>{
 for(const key of ['enabled','configured']){const f=fixture();f.state[key]=false;await f.lifecycle.start();assert.equal(f.state.opens,0);assert.equal(f.alarms.size,0);assert.equal(f.timers.size,0);f.state[key]=true;await f.lifecycle.reconfigure();assert.equal(f.state.opens,1);f.state[key]=false;await f.lifecycle.reconfigure();assert.equal(f.timers.size,0);assert.equal(f.alarms.size,0);}
});
test('scope change during an in-flight startup invalidates the stale attempt before replacement',async()=>{
 const f=fixture();f.state.available=true;let release;f.state.wait=new Promise(resolve=>release=resolve);const first=f.lifecycle.start();await flush();const changed=f.lifecycle.reconfigure();f.state.wait=null;release();await Promise.all([first,changed]);assert.equal(f.state.opens,2);assert.equal(f.state.online,true);assert.equal(f.state.closes,1);assert.equal(f.lifecycle.status().phase,'handshake');
});
test('private or unknown runtime state does not suppress metadata transport scheduling',async()=>{
 for(const mode of ['private','unknown','lifecycle']){const f=fixture();f.state.mode=mode;await f.lifecycle.start();await f.advance(1000);assert.equal(f.state.opens,2);assert.deepEqual(f.state.dispatched,[]);assert.equal(f.state.permissionRequests,0);}
});
test('stale acknowledgement cannot overwrite a replacement retry or alarm',async()=>{
 let release;const gate=new Promise(r=>release=r),saved={},alarms=new Map();let block=false,online=false,token;
 const api={storage:{local:{get:async()=>saved,set:async value=>Object.assign(saved,structuredClone(value))}},alarms:{clear:async key=>{if(block){block=false;await gate;}alarms.delete(key);},create:async(key,value)=>alarms.set(key,value),onAlarm:{addListener(){}}}};
 const lifecycle=create(api,{settings:async()=>({enabled:true,configured:true}),isOpen:()=>online,close(){online=false;},async open(t){token=t;online=true;return true;},changed(){throw Error('UI observer failure');}});
 await lifecycle.start();block=true;const ack=lifecycle.acknowledged(token);await flush();const changed=lifecycle.reconfigure();release();await Promise.all([ack,changed]);assert.equal(lifecycle.status().phase,'handshake');assert.equal(saved[KEY].phase,'handshake');assert.equal(alarms.size,1);online=false;await lifecycle.failed(token);assert.equal(saved[KEY].phase,'retry');await lifecycle.stop();
});
test('restart during a persisted handshake opens fresh metadata immediately',async()=>{
 const f=fixture({saved:{[KEY]:{version:1,attempt:4,nextAt:999999,phase:'handshake'}}});f.state.available=true;await f.lifecycle.start();assert.equal(f.state.opens,1);assert.equal(f.lifecycle.status().phase,'handshake');await f.lifecycle.acknowledged(f.state.token);assert.equal(f.lifecycle.status().attempt,0);
});
test('late saved retry read cannot overwrite disabled state during startup',async()=>{
 let release;const gate=new Promise(r=>release=r),saved={},alarms=new Map();let enabled=true,opens=0,reads=0;
 const api={storage:{local:{get:async()=>{reads++;await gate;return {[KEY]:{version:1,attempt:8,nextAt:Date.now()+900000,phase:'retry'}};},set:async value=>Object.assign(saved,structuredClone(value))}},alarms:{clear:async key=>alarms.delete(key),create:async(key,value)=>alarms.set(key,value),onAlarm:{addListener(){}}}};
 const lifecycle=create(api,{settings:async()=>({enabled,configured:true}),isOpen:()=>false,close(){},open:async()=>{opens++;return false;}});
 const first=lifecycle.start();await flush();enabled=false;const disabled=lifecycle.reconfigure();await flush();release();await Promise.all([first,disabled]);assert.equal(reads,1);assert.equal(opens,0);assert.equal(lifecycle.status().phase,'idle');assert.equal(lifecycle.status().retryScheduled,false);assert.equal(saved[KEY].phase,'idle');assert.equal(alarms.size,0);
});
