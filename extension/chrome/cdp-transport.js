// Internal CDP transport, inspired by Playwriter's per-tab debugger sessions.
// Responses/events stay inside the extension; consumers supply their own policy.
// This is not an MCP endpoint and never logs commands, parameters or responses.
globalThis.MechanizeCDP = (() => {
  const fail = (code, dispatchState = 'notDispatched') => Object.assign(new Error('CDP transport unavailable'), {code, dispatchState});
  // One attachment owner per Chrome API, while each consumer keeps its own
  // method policy. Broader Playwright access never widens input-only handles.
  const hubs = new WeakMap();
  function hubFor(api) {
    let hub=hubs.get(api);
    if(hub)return hub;
    hub={sessions:new Map(),generation:0,epoch:0,stoppedByUser:false};
    hubs.set(api,hub);
    const {sessions}=hub;
    function retire(session) {
      session.retired = true;
      session.attached = false;
      session.contexts.clear();
      for (const reject of session.pending) reject();
      session.pending.clear();
    }
    api.debugger?.onDetach?.addListener((source, reason) => {
      if (sessions.get(source.tabId)?.selfDetach) return;
      if (reason === 'canceled_by_user') {
        hub.stoppedByUser = true;
        for (const session of sessions.values()) retire(session);
      } else {
        const session = sessions.get(source.tabId);
        if (session) retire(session);
      }
    });
    api.debugger?.onEvent?.addListener((source, method, params) => {
      const session = sessions.get(source.tabId);
      if (!session || session.retired || !session.attached) return;
      if(source.sessionId===undefined){
        if(method==='Runtime.executionContextsCleared'||method==='Page.frameNavigated'&&!params?.frame?.parentId)session.contexts.clear();
        if(method==='Runtime.executionContextDestroyed'){session.contexts.delete(params?.executionContextId);if(params?.executionContextUniqueId)for(const [id,cached] of session.contexts)if(cached.context?.uniqueId===params.executionContextUniqueId)session.contexts.delete(id);}
        if(method==='Runtime.executionContextCreated'&&Number.isInteger(params?.context?.id)&&typeof params.context?.auxData?.frameId==='string'){
          if(session.contexts.size>=256&&!session.contexts.has(params.context.id))session.contexts.clear();
          session.contexts.set(params.context.id,JSON.parse(JSON.stringify(params)));
        }
      }
      if (method === 'Target.attachedToTarget' && typeof params?.sessionId === 'string') session.children.add(params.sessionId);
      if (method === 'Target.detachedFromTarget') session.children.delete(params?.sessionId);
      for (const listener of session.listeners) { try { listener({method, params, sessionId: source.sessionId}); } catch {} }
    });
    api.webNavigation?.onCommitted?.addListener(event=>{
      if(event.frameId===0)sessions.get(event.tabId)?.contexts.clear();
    });
    hub.retire=retire;
    return hub;
  }
  function invalidate(api) {
    const hub=hubs.get(api);if(!hub)return;
    hub.epoch++;
    for(const session of hub.sessions.values()){
      // Retire authority handles and pending calls, retaining our own native
      // attachment for a freshly authorized consumer. No browser detach/takeover.
      session.generation=++hub.generation;
      if(session.runtimeEnabled)session.runtimeNeedsRefresh=true;
      for(const reject of [...session.pending])reject();
      session.pending.clear();session.listeners.clear();session.children.clear();session.contexts.clear();
    }
  }
  function create(api, permit) {
    if(typeof permit!=='function')throw fail('cdpDenied');
    const hub=hubFor(api),sessions=hub.sessions;
    function wait(promise, session, deadline, state) {
      if (!Number.isSafeInteger(deadline) || deadline <= Date.now()) {
        Promise.resolve(promise).catch(() => {});
        return Promise.reject(fail('cdpTimeout', state));
      }
      return new Promise((resolve, reject) => {
        let settled = false;
        const finish = (error, value) => {
          if (settled) return;
          settled = true; clearTimeout(timer); session.pending.delete(detached);
          error ? reject(error) : resolve(value);
        };
        const detached = () => finish(fail('cdpDetached', state));
        const timer = setTimeout(() => finish(fail('cdpTimeout', state)), deadline - Date.now());
        session.pending.add(detached);
        Promise.resolve(promise).then(value => finish(null, value), () => finish(fail('cdpUnavailable', state)));
        if (session.retired) detached();
      });
    }
    async function attach(tabId, deadline) {
      if (!Number.isSafeInteger(tabId) || tabId < 0 || hub.stoppedByUser) throw fail('cdpDenied');
      if (!api.debugger?.attach || !api.debugger?.sendCommand) throw fail('cdpUnavailable');
      if (!Number.isSafeInteger(deadline) || deadline <= Date.now()) throw fail('cdpTimeout');
      const admittedEpoch=hub.epoch;
      let session = sessions.get(tabId);
      if (session?.retired && session.attaching) throw fail('cdpAttachPending');
      if (!session || session.retired) {
        session = {tabId, generation: ++hub.generation, attached: false, retired: false, pending: new Set(), listeners: new Set(), children: new Set(), contexts:new Map()};
        sessions.set(tabId, session);
      }
      if (!session.attached && !session.attaching) {
        session.attaching = Promise.resolve().then(() => api.debugger.attach({tabId}, '1.3')).then(async () => {
          if (session.retired) {
            // A late attach cannot resurrect an expired or detached session.
            session.selfDetach = true;
            try { await api.debugger.detach({tabId}); } catch {}
            finally { session.selfDetach = false; }
            throw fail('cdpDetached');
          }
          session.attached = true;
        }).finally(() => { session.attaching = null; });
      }
      if (session.attaching) {
        try { await wait(session.attaching, session, deadline, 'notDispatched'); }
        catch (error) { if(admittedEpoch===hub.epoch)hub.retire(session); throw error; }
      }
      if(admittedEpoch!==hub.epoch)throw fail('cdpDetached');
      const generation=session.generation;
      const current = () => admittedEpoch===hub.epoch && generation===session.generation && !hub.stoppedByUser && sessions.get(tabId) === session && session.attached && !session.retired;
      const ownedListeners=new Map();
      return Object.freeze({
        tabId, generation, current,
        onEvent(listener) {
          if(typeof listener!=='function'||!current())throw fail('cdpDetached');
          const seen=new Set();
          const wrapped=event=>{
            if(!current())return;
            if(event.sessionId===undefined){
              if(event.method==='Runtime.executionContextsCleared'||event.method==='Page.frameNavigated'&&!event.params?.frame?.parentId)seen.clear();
              if(event.method==='Runtime.executionContextDestroyed')seen.delete(event.params?.executionContextId);
              if(event.method==='Runtime.executionContextCreated')seen.add(event.params?.context?.id);
            }
            listener(event);
          };
          ownedListeners.set(wrapped,seen);session.listeners.add(wrapped);
          return ()=>{ownedListeners.delete(wrapped);session.listeners.delete(wrapped);};
        },
        async send(method, params, deadline, childSessionId, onDispatch) {
          if (!current()) throw fail('cdpDetached');
          if (!Number.isSafeInteger(deadline) || deadline <= Date.now()) throw fail('cdpTimeout');
          let allowed = false;
          try { allowed = typeof method === 'string' && permit(method, params) === true; } catch {}
          if (!allowed || childSessionId !== undefined && !session.children.has(childSessionId)) throw fail('cdpDenied');
          if (!current()) throw fail('cdpDetached');
          const recipient = childSessionId === undefined ? {tabId} : {tabId, sessionId: childSessionId};
          if(method==='Runtime.enable'&&childSessionId===undefined&&session.runtimeNeedsRefresh){
            // An authority epoch discards all old context metadata. Reset only
            // our observer domain to obtain fresh Chrome events for the new
            // owner; keep the debugger attachment and never manufacture IDs.
            session.runtimeReset ||= Promise.resolve().then(()=>api.debugger.sendCommand({tabId},'Runtime.disable',{}));
            await wait(session.runtimeReset,session,deadline,'notDispatched');
            if(!current())throw fail('cdpDetached');
            session.contexts.clear();session.runtimeNeedsRefresh=false;session.runtimeReset=null;
          }
          // Once handed to Chrome, timeout/detach does not prove no execution.
          let response;
          try { if(onDispatch!==undefined){if(typeof onDispatch!=='function')throw fail('cdpDenied');onDispatch();} response = api.debugger.sendCommand(recipient, method, params); }
          catch { throw fail('cdpUnavailable', 'unknown'); }
          const result=await wait(response, session, deadline, 'unknown');
          if(method==='Runtime.enable'&&childSessionId===undefined&&current()){
            session.runtimeEnabled=true;
            // Chrome may already have Runtime enabled on our pooled attachment.
            // Replay only actual, still-live context metadata missed by this new
            // consumer; never replay calls, input, or another consumer's events.
            for(const [listener,seen] of ownedListeners)for(const [id,params] of session.contexts){
              if(!current())throw fail('cdpDetached');
              if(!seen.has(id))listener({method:'Runtime.executionContextCreated',params:JSON.parse(JSON.stringify(params))});
            }
          }
          return result;
        }
      });
    }
    return {attach};
  }
  return {create,invalidate};
})();
if (typeof module !== 'undefined') module.exports = globalThis.MechanizeCDP;
