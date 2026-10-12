// Internal local-host relay, behind native authority, privacy and receipt gates.
// No web-page message handler, MCP execute-code tool or browser-wide CDP endpoint.
globalThis.MechanizePlaywrightRelay = (() => {
  const methods = new Set([
    'Page.enable','Page.getFrameTree','Page.setLifecycleEventsEnabled','Page.addScriptToEvaluateOnNewDocument',
    'Page.createIsolatedWorld','Page.bringToFront','Page.getLayoutMetrics',
    'Runtime.enable','Runtime.evaluate','Runtime.callFunctionOn','Runtime.getProperties','Runtime.releaseObject',
    'Runtime.releaseObjectGroup','Runtime.runIfWaitingForDebugger',
    'DOM.enable','DOM.getDocument','DOM.describeNode','DOM.resolveNode','DOM.getContentQuads','DOM.getBoxModel',
    'DOM.scrollIntoViewIfNeeded','DOM.getNodeForLocation','DOM.setFileInputFiles',
    'Log.enable','Inspector.enable','Network.enable','Network.setCacheDisabled','Network.setBypassServiceWorker',
    'Emulation.setFocusEmulationEnabled','Emulation.setEmulatedMedia',
    'Target.setAutoAttach','Input.dispatchMouseEvent','Input.dispatchKeyEvent','Input.insertText',
  ]);
  // File input is never an admitted typed operation of this engine.
  methods.delete('DOM.setFileInputFiles');
  const fail = code => Object.assign(new Error('Local Playwright relay unavailable'), {code, dispatchState:'notDispatched'});
  const same = (a,b) => a && b && ['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'].every(k=>a[k]===b[k]);
  const keys=(p,allowed)=>p&&typeof p==='object'&&!Array.isArray(p)&&Object.keys(p).every(k=>allowed.includes(k));
  function inputAllowed(command,method,p){
    if(!method.startsWith('Input.'))return true;
    if(command?.action==='element.fill'){
      if(method==='Input.insertText')return keys(p,['text'])&&typeof p.text==='string'&&p.text===command.args?.value;
      if(method==='Input.dispatchKeyEvent')return command.args?.value===''&&keys(p,['type','key','code','windowsVirtualKeyCode','modifiers','autoRepeat','location','isKeypad','text','unmodifiedText','commands'])&&['rawKeyDown','keyDown','keyUp'].includes(p.type)&&p.key==='Delete'&&p.code==='Delete'&&p.windowsVirtualKeyCode===46&&p.modifiers===0&&(!p.text&&!p.unmodifiedText)&&p.autoRepeat!==true&&(!p.commands||Array.isArray(p.commands)&&(p.commands.length===0||p.commands.length===1&&p.commands[0]==='deleteForward'));
      return false;
    }
    if(command?.action!=='element.press'||method!=='Input.dispatchMouseEvent'||!keys(p,['type','x','y','button','buttons','clickCount','modifiers','pointerType','force'])||![p.x,p.y].every(v=>Number.isFinite(v)&&v>=0&&v<=100000)||p.modifiers!==0||p.clickCount!==undefined&&p.clickCount!==1||p.pointerType!==undefined&&p.pointerType!=='mouse'||p.force!==undefined&&(typeof p.force!=='number'||p.force<0||p.force>1))return false;
    if(p.type==='mouseMoved')return p.buttons===0&&['none',undefined].includes(p.button);
    return p.type==='mousePressed'&&p.button==='left'&&p.buttons===1||p.type==='mouseReleased'&&p.button==='left'&&p.buttons===0;
  }
  function create(api, authorize) {
    if(typeof authorize!=='function')throw fail('playwrightAuthorityRequired');
    const transport=globalThis.MechanizeCDP.create(api,method=>methods.has(method));
    return {
      async open(binding,deadline) {
        const i=binding?.identity;
        if(!i||i.frameId!==0||!Number.isSafeInteger(i.tabId)||i.tabId<=0||!i.documentId||!Number.isSafeInteger(deadline)||deadline<=Date.now()||deadline>Date.now()+30000)throw fail('playwrightBindingDenied');
        let closed=false,pinned,injectedObject;const objectContexts=new Map();
        const current=async()=>{
          if(closed||Date.now()>=deadline||await authorize(binding)!==true)throw fail('playwrightAuthorityChanged');
          const frames=await api.webNavigation.getAllFrames({tabId:i.tabId});
          const root=frames?.find(f=>f.frameId===0);
          if(!root||root.errorOccurred||root.frameType==='fenced_frame'||root.documentId!==i.documentId||new URL(root.url).origin!==binding.origin)throw fail('playwrightDocumentChanged');
          if(await authorize(binding)!==true)throw fail('playwrightAuthorityChanged');
        };
        await current();
        const session=await transport.attach(i.tabId,deadline);
        await current();
        // noDefaults keeps Playwright from changing the user's browser defaults,
        // including focus emulation. Enable only this independently admitted
        // root tab so background actionability can use animation frames.
        await session.send('Emulation.setFocusEmulationEnabled',{enabled:true},deadline);
        await current();
        const validate=async(method,params,requestDeadline)=>{
          if(!methods.has(method)||method==='Emulation.setFocusEmulationEnabled'&&(!keys(params,['enabled'])||params.enabled!==true)||!inputAllowed(binding.command,method,params)||!Number.isSafeInteger(requestDeadline)||requestDeadline>deadline||requestDeadline<=Date.now()||new TextEncoder().encode(JSON.stringify(params||{})).length>512*1024)throw fail('playwrightCDPDenied');
          await current();
          if(!same(i,binding.identity)||!session.current())throw fail('playwrightBindingChanged');
          const actual=method==='Input.insertText'||method==='Input.dispatchMouseEvent'&&params?.type==='mousePressed'||method==='Input.dispatchKeyEvent'&&['rawKeyDown','keyDown','char'].includes(params?.type);
          if(actual){
            const guard=globalThis.MechanizePlaywrightTarget;
            if(!guard||!pinned||!injectedObject||pinned.action!==binding.command?.action)throw fail('playwrightTargetUnpinned');
            const checked=await session.send('Runtime.callFunctionOn',{objectId:pinned.objectId,functionDeclaration:guard.boundarySource,arguments:[{value:pinned.action},{value:method==='Input.dispatchMouseEvent'?{type:params.type,x:params.x,y:params.y}:{}},{value:pinned.signature},{value:binding.command.locator},{objectId:injectedObject}],returnByValue:true,awaitPromise:true},requestDeadline);
            if(checked?.exceptionDetails||checked?.result?.value!==true)throw fail('playwrightTargetChanged');
            await current();
          }
        };
        return Object.freeze({
          identity:{...i},origin:binding.origin,
          async current(){try{await current();return session.current();}catch{return false;}},
          validate,
          onEvent(listener){return session.onEvent(event=>{if(!closed&&event.sessionId===undefined)listener(event);});},
          async send(method,params,requestDeadline,onDispatch){
            await validate(method,params,requestDeadline);
            // Child debugger sessions/frames cannot be selected by this relay.
            const result=await session.send(method,params,requestDeadline,undefined,onDispatch);
            if(method==='Runtime.evaluate'&&Number.isSafeInteger(params.contextId)&&typeof result?.result?.objectId==='string'&&objectContexts.size<32)objectContexts.set(result.result.objectId,params.contextId);
            const query=method==='Runtime.callFunctionOn'&&globalThis.MechanizePlaywrightTarget?.queryObject(params,result);if(query&&objectContexts.has(query))injectedObject??=query;
            const pin=globalThis.MechanizePlaywrightTarget?.pinnedObject(params,result);
            if(method==='Runtime.callFunctionOn'&&pin&&pin.action===binding.command?.action){
              if(!injectedObject)throw fail('playwrightTargetUnpinned');
              // Public ElementHandle.evaluate uses the main world; Playwright's
              // role engine lives in its utility world. Resolve only this exact
              // already-pinned DOM node into that known engine context.
              const described=await session.send('DOM.describeNode',{objectId:pin.objectId},requestDeadline);
              if(!Number.isSafeInteger(described?.node?.backendNodeId))throw fail('playwrightTargetDenied');
              const adopted=await session.send('DOM.resolveNode',{backendNodeId:described.node.backendNodeId,executionContextId:objectContexts.get(injectedObject)},requestDeadline);
              if(typeof adopted?.object?.objectId!=='string')throw fail('playwrightTargetDenied');
              const guardedPin={...pin,objectId:adopted.object.objectId};
              const snapshot=await session.send('Runtime.callFunctionOn',{objectId:guardedPin.objectId,functionDeclaration:globalThis.MechanizePlaywrightTarget.snapshotSource,arguments:[{value:binding.command.locator},{objectId:injectedObject}],returnByValue:true,awaitPromise:true},requestDeadline);
              const signature=snapshot?.result?.value;
              if(snapshot?.exceptionDetails||typeof signature!=='string'||signature.length>4096)throw fail('playwrightTargetDenied');
              // The semantic signature stays extension-local, never in model
              // output or the private sidecar IPC result.
              pinned={...guardedPin,signature};
            }
            return result;
          },
          close(){closed=true;},
        });
      }
    };
  }
  return {create,methods,inputAllowed};
})();
if(typeof module!=='undefined')module.exports=globalThis.MechanizePlaywrightRelay;
