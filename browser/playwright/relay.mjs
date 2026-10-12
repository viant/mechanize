import {randomBytes} from 'node:crypto';

// Public Playwright 1.64 transport: no TCP listener, endpoint or web-page access.
export const pageEvents=[
  'Runtime.executionContextCreated','Runtime.executionContextDestroyed','Runtime.executionContextsCleared',
  'Page.frameNavigated','Page.frameAttached','Page.frameDetached','Page.lifecycleEvent',
  'Page.loadEventFired','Page.domContentEventFired','Page.frameStoppedLoading',
  'Page.javascriptDialogOpening','Page.javascriptDialogClosed','Inspector.detached','Inspector.targetCrashed',
];
export const isInputBoundary=(method,params={})=>method==='Input.insertText'||method==='Input.dispatchMouseEvent'&&params.type==='mousePressed'||method==='Input.dispatchKeyEvent'&&['rawKeyDown','keyDown','char'].includes(params.type);
export function bounded(promise,deadline){
  let timer;return Promise.race([Promise.resolve(promise),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Object.assign(Error('Scoped deadline exceeded'),{code:'playwrightDeadline',dispatchState:'unknown'})),Math.max(1,deadline-Date.now()));})]).finally(()=>clearTimeout(timer));
}
export async function createScopedRelay(adapter,{deadlineUnixMs,onDispatch=()=>{}}) {
  if(!adapter||typeof adapter.send!=='function'||typeof adapter.current!=='function'||typeof adapter.onEvent!=='function')throw Error('Scoped relay adapter required');
  if(!await bounded(adapter.current(),deadlineUnixMs))throw Error('Scoped authority unavailable');
  const initial=await bounded(adapter.send('Page.getFrameTree',{},deadlineUnixMs),deadlineUnixMs);
  const targetId=initial.frameTree?.frame?.id,sessionId=randomBytes(16).toString('hex');
  const targetInfo={targetId,browserContextId:'mechanize-scoped-context',type:'page',title:'',url:adapter.origin,attached:true,canAccessOpener:false};
  let closed=false,closePromise,rootFrameId=initial.frameTree?.frame?.id,mutation=false,dispatched=false,sequence=Promise.resolve();
  if(!rootFrameId)throw Error('Bound main frame required');
  const transport={send(message){
    sequence=sequence.then(async()=>{
      adapter.onMethod?.(message.method);
      try{
        if(!Number.isSafeInteger(message.id)||message.id<=0||typeof message.method!=='string'||Object.keys(message).some(k=>!['id','method','params','sessionId'].includes(k)))throw Error('Invalid CDP envelope');
        const result=await route(message);emit({id:message.id,result,...(message.sessionId?{sessionId:message.sessionId}:{})});
      }catch{
        emit({id:message.id,error:{code:-32000,message:'Scoped Playwright relay unavailable'},...(message.sessionId?{sessionId:message.sessionId}:{})});
        // Playwright may queue move/down/up concurrently. Stop the whole relay
        // on a preparation error before any already queued input can dispatch.
        void close().catch(()=>{});
      }
    });
  },close(){void close().catch(()=>{});}};
  const emit=value=>{if(!closed&&Buffer.byteLength(JSON.stringify(value))<=512*1024)queueMicrotask(()=>{if(!closed)transport.onmessage?.(value);});};
  const unsubscribe=adapter.onEvent(event=>{
    if(closed||!pageEvents.includes(event.method))return;
    const p=event.params||{};
    if(event.method==='Runtime.executionContextCreated'&&p.context?.auxData?.frameId!==rootFrameId)return;
    if(event.method==='Page.frameAttached'||event.method==='Page.frameDetached')return;
    if(event.method==='Page.frameNavigated'&&p.frame?.parentId)return;
    if(event.method==='Page.lifecycleEvent'&&p.frameId!==rootFrameId)return;
    emit({method:event.method,params:p,sessionId});
  });
  const deadlineTimer=setTimeout(()=>{void close().catch(()=>{});},Math.max(1,deadlineUnixMs-Date.now()));
  function close(){
    if(closePromise)return closePromise;
    closed=true;clearTimeout(deadlineTimer);
    closePromise=(async()=>{unsubscribe();transport.onclose?.('Scoped transport closed');await adapter.close?.();})();
    return closePromise;
  }
  async function route(message){
    if(closed||Date.now()>=deadlineUnixMs||!await bounded(adapter.current(),deadlineUnixMs))throw Error('Scoped authority unavailable');
    const {method,params={},sessionId:incoming}=message;
    if(!incoming){
      switch(method){
        case 'Browser.getVersion':return {protocolVersion:'1.3',product:'Chrome/149.0.0.0',revision:'mechanize-local-relay',userAgent:'Chrome/149.0.0.0 Macintosh',jsVersion:'V8'};
        case 'Target.setDiscoverTargets':return {};
        case 'Target.setAutoAttach':
          if(params.autoAttach!==true||params.flatten!==true)throw Error('Scoped attachment required');
          emit({method:'Target.attachedToTarget',params:{sessionId,targetInfo,waitingForDebugger:false}});return {};
        case 'Target.getTargetInfo':if(params.targetId&&params.targetId!==targetId)throw Error('Foreign target');return {targetInfo};
        case 'Target.getTargets':return {targetInfos:[targetInfo]};
        case 'Target.attachToTarget':if(params.targetId!==targetId)throw Error('Foreign target');return {sessionId};
        case 'Target.detachFromTarget':if(params.sessionId!==sessionId)throw Error('Foreign session');return {};
        default:throw Error('Browser-wide CDP denied');
      }
    }
    if(incoming!==sessionId)throw Error('Foreign session');
    const input=mutation&&isInputBoundary(method,params);
    let result;
    try{result=await bounded(adapter.send(method,params,deadlineUnixMs),deadlineUnixMs);}
    catch(error){if(input&&error?.dispatchState!=='notDispatched'){dispatched=true;onDispatch();}throw error;}
    if(input){dispatched=true;onDispatch();}
    if(method==='Page.getFrameTree'){
      if(result.frameTree?.frame?.id!==rootFrameId)throw Error('Bound main frame changed');
      return {frameTree:{frame:result.frameTree.frame}};
    }
    return result;
  }
  return {transport,targetId,beginMutation(){mutation=true;},close};
}
