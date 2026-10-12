// Closed browser input adapter. No evaluate, page reads, screenshots, text,
// network, cookies or arbitrary CDP methods. Never log command parameters.
globalThis.MechanizeBrowserInput = (() => {
  const fail = (code, state='notDispatched') => Object.assign(new Error('Browser input unavailable'), {code,dispatchState:state});
  function create(api) {
    const busy=new Set(), uncertain=new Set();
    const transport=globalThis.MechanizeCDP.create(api,method=>['Input.dispatchMouseEvent','Input.dispatchKeyEvent'].includes(method));
    async function bounded(promise,deadline,state='notDispatched') {
      let timer;
      try {return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(fail('browserInputTimeout',state)),Math.max(0,deadline-Date.now()));})]);}
      catch(error) {throw fail(error?.code==='browserInputTimeout'?'browserInputTimeout':'browserInputUnavailable',state);}
      finally {clearTimeout(timer);}
    }
    async function validate(target,admit,deadline) {
      if(!Number.isSafeInteger(target.tabId)||target.tabId<0||target.frameId!==0||typeof target.documentId!=='string'||!target.documentId||typeof admit!=='function')throw fail('browserInputTargetDenied');
      if(!Number.isSafeInteger(deadline)||deadline<=Date.now()||deadline>Date.now()+3000)throw fail('browserInputDeadlineDenied');
      if(admit()!==true)throw fail('browserInputAuthorityChanged');
      const frames=await bounded(api.webNavigation.getAllFrames({tabId:target.tabId}),deadline);
      const root=frames?.find(f=>f.frameId===0);
      if(!root||root.documentId!==target.documentId||root.errorOccurred===true||root.frameType==='fenced_frame')throw fail('browserInputDocumentChanged');
      if(Date.now()>=deadline)throw fail('browserInputDeadlineDenied');
      if(admit()!==true)throw fail('browserInputAuthorityChanged');
    }
    async function execute(target,kind,value,deadline,admit) {
      let started=false, release, session, phase="frame";
      if(busy.has(target.tabId)||uncertain.has(target.tabId))throw fail('browserInputInhibited');
      busy.add(target.tabId);
      try {
        await validate(target,admit,deadline);
        phase="attach";
        session=await transport.attach(target.tabId,deadline);
        phase="frame";
        await validate(target,admit,deadline);
        let commands;
        if(kind==='click') {
          if(!value||Object.keys(value).sort().join()!=='x,y'||![value.x,value.y].every(v=>Number.isFinite(v)&&v>=0&&v<=100000))throw fail('browserInputDenied');
          const point={x:value.x,y:value.y,button:'left',clickCount:1};
          commands=[['Input.dispatchMouseEvent',{...point,type:'mouseMoved',buttons:0}],['Input.dispatchMouseEvent',{...point,type:'mousePressed',buttons:1}],['Input.dispatchMouseEvent',{...point,type:'mouseReleased',buttons:0}]];
        } else {
          const keys={Return:{key:'Enter',code:'Enter',windowsVirtualKeyCode:13},Space:{key:' ',code:'Space',windowsVirtualKeyCode:32},Tab:{key:'Tab',code:'Tab',windowsVirtualKeyCode:9},Escape:{key:'Escape',code:'Escape',windowsVirtualKeyCode:27}};
          if(!Object.hasOwn(keys,value))throw fail('browserInputDenied');
          commands=[['Input.dispatchKeyEvent',{...keys[value],type:'rawKeyDown'}],['Input.dispatchKeyEvent',{...keys[value],type:'keyUp'}]];
        }
        release=commands.at(-1);
        for(let i=0;i<commands.length;i++) {
          if(i!==commands.length-1) {if(admit()!==true||Date.now()>=deadline)throw fail('browserInputDenied',started?'unknown':'notDispatched');}
          phase=commands[i][1].type;
          try { await session.send(...commands[i],deadline); started=true; }
          catch(error) { if(error?.dispatchState==='unknown')started=true; throw error; }
        }
        return {dispatchState:'dispatched',effectState:'unverified',inputSemantics:'Browser protocol input v1'};
      } catch(error) {
        if(started) {
          uncertain.add(target.tabId);
          // Release only; never repeat move/down or the original action. A
          // separate bounded cleanup budget survives action cancellation.
          if(release && session?.current()) {
            try {await session.send(...release,Date.now()+1000);}catch{}
          }
        }
        const errorCode=error?.code?.startsWith('cdp')?(error.code==='cdpTimeout'?'browserInputTimeout':'browserInputUnavailable'):(error?.code||'browserInputUnavailable');
        const timeoutCodes={frame:'browserInputFrameTimeout',attach:'browserInputAttachTimeout',mouseMoved:'browserInputMouseMoveTimeout',mousePressed:'browserInputMousePressTimeout',mouseReleased:'browserInputMouseReleaseTimeout',rawKeyDown:'browserInputKeyDownTimeout',keyUp:'browserInputKeyUpTimeout'};
        return {dispatchState:started?'unknown':'notDispatched',effectState:started?'unknown':'none',errorCode:errorCode==='browserInputTimeout'?(timeoutCodes[phase]||errorCode):errorCode};
      } finally {busy.delete(target.tabId);}
    }
    return {click:(target,point,deadline,admit)=>execute(target,'click',point,deadline,admit),key:(target,key,deadline,admit)=>execute(target,'key',key,deadline,admit)};
  }
  return {create};
})();
if(typeof module!=='undefined')module.exports=globalThis.MechanizeBrowserInput;
