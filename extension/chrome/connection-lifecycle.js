// Transport scheduling only. This module never requests website permission,
// inspects a document, grants a lease, or retries an application command.
globalThis.MechanizeConnectionLifecycle=(()=>{
 const KEY='mechanizeConnectionRetryV1',ALARM='mechanize-native-reconnect',DELAYS=[1000,2000,4000,60000,120000,240000,480000,900000];
 function create(api,hooks,clock={now:()=>Date.now(),setTimeout:(fn,delay)=>setTimeout(fn,delay),clearTimeout:id=>clearTimeout(id)}){
  let attempt=0,nextAt=0,phase='idle',timer=null,generation=0,flight=null,loaded=false,active=null,failedToken=null;
  const changed=()=>{try{hooks.changed?.();}catch{}};
  const cancelTimer=()=>{if(timer!==null)clock.clearTimeout(timer);timer=null;};
  let io=Promise.resolve();
  const ordered=fn=>{const result=io.then(fn,fn);io=result.catch(()=>{});return result;};
  const clearAlarm=()=>{const epoch=generation;return ordered(async()=>{if(epoch!==generation)return;try{await api.alarms?.clear(ALARM);}catch{}});};
  const persist=()=>{const epoch=generation,record={version:1,attempt,nextAt,phase};return ordered(async()=>{if(epoch!==generation)return;try{await api.storage.local.set({[KEY]:record});}catch{}});};
  let loading=null;
  async function load(){
   if(loaded)return;if(loading)return loading;const epoch=generation;
   loading=(async()=>{try{const saved=(await api.storage.local.get(KEY))[KEY];if(epoch===generation&&saved&&Object.keys(saved).sort().join()==='attempt,nextAt,phase,version'&&saved.version===1&&Number.isInteger(saved.attempt)&&saved.attempt>=0&&saved.attempt<=DELAYS.length&&Number.isSafeInteger(saved.nextAt)&&saved.nextAt>=0&&['idle','retry','handshake'].includes(saved.phase)){attempt=saved.attempt;nextAt=saved.nextAt;phase=saved.phase;}}catch{}finally{loaded=true;}})();
   return loading;
  }

  async function arm(token){
   if(token!==generation||!nextAt)return;cancelTimer();
   const delay=Math.max(0,nextAt-clock.now());
   // Chrome 106 supports minute alarms. Short timers improve responsiveness;
   // the named alarm is the durable wake-up if MV3 suspends this worker.
   const when=Math.max(nextAt,clock.now()+60000);await ordered(async()=>{if(token!==generation)return;try{await api.alarms?.create(ALARM,{when});}catch{}});
   if(token!==generation)return;
   timer=clock.setTimeout(()=>{timer=null;void wake();},delay);timer?.unref?.();
  }
  async function stop(){generation++;active=null;cancelTimer();attempt=0;nextAt=0;phase='idle';await clearAlarm();await persist();}
  async function failed(token){
   if(token!==active||failedToken===token)return;failedToken=token;
   const settings=await hooks.settings();if(token!==active)return;
   if(!settings.enabled||!settings.configured){await stop();return;}
   attempt=Math.min(attempt+1,DELAYS.length);nextAt=clock.now()+DELAYS[attempt-1];phase='retry';await persist();if(token!==active)return;await arm(generation);changed();
  }
  async function acknowledged(token){
   if(token!==active)return;token.acknowledged=true;failedToken=null;attempt=0;nextAt=0;phase='idle';cancelTimer();await clearAlarm();if(token!==active)return;await persist();if(token!==active)return;changed();
  }
  async function run(force=false){
   if(flight)return flight;if(hooks.isOpen())return;
   const token={generation:++generation,acknowledged:false};active=token;failedToken=null;cancelTimer();
   flight=(async()=>{
    await load();const settings=await hooks.settings();if(active!==token)return;
    if(!settings.enabled||!settings.configured){await stop();changed();return;}
    if(settings.blocked){await failed(token);return;}
    if(hooks.isOpen()){nextAt=0;phase='idle';await clearAlarm();return;}
    if(!force&&phase==='retry'&&nextAt>clock.now()){await arm(generation);return;}
    await clearAlarm();const valid=()=>active===token&&generation===token.generation;
    let opened=false;try{opened=await hooks.open(token,valid);}catch{}
    if(!valid())return;
    if(!opened){await failed(token);return;}
    if(!token.acknowledged){phase='handshake';nextAt=clock.now()+15000;await persist();await arm(generation);}
   })().finally(()=>{flight=null;});return flight;
  }
  async function wake(){
   if(phase==='handshake'&&nextAt<=clock.now()&&hooks.isOpen()){
    const token=active;hooks.close();await failed(token);return;
   }
   return run(false);
  }
  async function request(){
   await load();if(hooks.isOpen())return;
   attempt=0;nextAt=0;phase='idle';return run(true);
  }
  async function reconfigure(){const previous=flight,stopping=stop();hooks.close();await stopping;if(previous)await previous;return run(true);}
  async function start(){await load();if(phase==='handshake'){nextAt=0;phase='idle';}return run(false);}
  api.alarms?.onAlarm?.addListener(alarm=>{if(alarm?.name===ALARM)void wake();});
  return {start,request,reconfigure,failed,acknowledged,stop,status:()=>({retryScheduled:nextAt>0,phase,attempt,nextAt}),key:KEY,alarm:ALARM};
 }
 return {create,KEY,ALARM,DELAYS};
})();
if(typeof module!=='undefined')module.exports=globalThis.MechanizeConnectionLifecycle;
