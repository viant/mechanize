// Browser API mutation calls execute once. Navigation timers/promises only observe.
globalThis.MechanizeBrowser = (() => {
  const originAllowed = MechanizeProtocol.websiteAllowed;
  async function query(command, protectedOrigins = new Set()) {
    const saved = await chrome.storage.session.get(["browserReceipt:" + command.attemptId, "browserIntent:" + command.attemptId]);
    const receipt = saved["browserReceipt:" + command.attemptId], intent = saved["browserIntent:" + command.attemptId];
    if (!intent) return null;
    if (intent.action === "browser.openOrigin" || intent.action === "browser.activateTab") throw MechanizeProtocol.error("attemptConflict", "Browser-level attempt cannot be queried as a document command");
    if (["profileChannel", "browserInstance", "tabId", "frameId", "documentId"].some(key => intent.identity[key] !== command.identity[key]) || ["brokerEpoch", "channelEpoch", "scopeHash"].some(key => intent[key] !== command[key])) throw MechanizeProtocol.error("staleIdentity", "Browser receipt belongs to another document/channel");
    if (receipt?.newDocument?.origin && (protectedOrigins.isProtected?protectedOrigins.isProtected(receipt.newDocument.origin,receipt.newDocument):protectedOrigins.has(receipt.newDocument.origin))) {
      const doc=receipt.newDocument;
      const fields=['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration','origin','title','titleTruncated'];
      const receiptFields=['requestId','attemptId','identity','dispatchState','effectState','ready','inputSemantics','newDocument','retiredAuthorityQuiesced','controlLease','fingerprintVersion','fingerprintSHA256','privateTarget'];
      if(receipt.privateTarget!==true||doc.title!==''||doc.titleTruncated!==false||Object.keys(doc).some(k=>!fields.includes(k))||Object.keys(receipt).some(k=>!receiptFields.includes(k)))throw MechanizeProtocol.error('secureDocumentRequired','Protected origin receipt is withheld');
    }
    return receipt ? {...receipt, requestId: command.requestId} : {requestId: command.requestId, attemptId: command.attemptId, identity: command.identity, receiptAvailable: false, dispatchState: "unknown", effectState: "unknown"};
  }
  async function execute(command, enrollment, protectedOrigins = new Set(), authority = () => true, retired = () => {}, redact = value => value) {
    const originAllowed = (url, scope) => {
      try { return !(protectedOrigins.isProtected?protectedOrigins.isProtected(url,command.identity):protectedOrigins.has(new URL(url).origin)) && MechanizeProtocol.websiteAllowed(url, scope); }
      catch { return false; }
    };
    if (command.identity.frameId !== 0) throw MechanizeProtocol.error("unsupportedScope", "Browser mutations require a root frame");
    const fingerprintVersion=command.fingerprintVersion || 1;
    let fingerprint;
    if(fingerprintVersion===2) {
      const logical=await MechanizeFingerprint.mutationV2(command);
      if(logical.sha256!==command.fingerprintSHA256) throw MechanizeProtocol.error("fingerprintMismatch","Exact logical browser command fingerprint required");
      fingerprint=logical.sha256;
    } else {
      const digest=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(JSON.stringify([command.action,command.identity,command.args])));
      fingerprint=[...new Uint8Array(digest)].map(value=>value.toString(16).padStart(2,"0")).join("");
    }
    const previous = await query(command, protectedOrigins);
    if (previous) {
      const saved = await chrome.storage.session.get("browserIntent:" + command.attemptId);
      if ((saved["browserIntent:" + command.attemptId].fingerprintVersion || 1)!==fingerprintVersion || saved["browserIntent:" + command.attemptId].fingerprint !== fingerprint) throw MechanizeProtocol.error("attemptConflict", "Browser attempt was already bound to a different command");
      return previous;
    }
    if (Object.keys(command.args || {}).some(key => key !== "url")) throw MechanizeProtocol.error("invalidRequest", "Unknown browser argument");
    let destination, privateTarget=false;
    if (command.action === "browser.navigate") {
      if (typeof command.args?.url !== "string" || command.args.url.length > 8192) throw MechanizeProtocol.error("invalidRequest", "Bounded destination URL required");
      destination = new URL(command.args.url);
      privateTarget=protectedOrigins.isProtected?protectedOrigins.isProtected(destination.href,command.identity):protectedOrigins.has(destination.origin);
      if (destination.username || destination.password || !MechanizeProtocol.websiteAllowed(destination.href,enrollment) || [...destination.searchParams.keys()].some(key => /password|token|secret|credential/i.test(key)) || privateTarget&&(destination.protocol!=='https:'||destination.search||destination.hash||!['','/'].includes(destination.pathname)&&!protectedOrigins.allowsPrivateURL?.(destination.href,command.identity))) throw MechanizeProtocol.error("originDenied", "Destination must be enrolled with no embedded credentials");
    }
    const validated = await chrome.tabs.sendMessage(command.identity.tabId, {...command, action: "executor.validate", attemptId: undefined, args: undefined, fingerprintVersion:undefined, fingerprintSHA256:undefined}, {documentId: command.identity.documentId});
    if (validated.error || !validated.validated) return {...validated, requestId: command.requestId, attemptId: command.attemptId};
    const session = await chrome.storage.session.get(null);
    if (Object.keys(session).some(key => key.startsWith("browserIntent:") && (!session[key.replace("browserIntent:", "browserReceipt:")] || session[key.replace("browserIntent:", "browserReceipt:")].dispatchState === "unknown" || session[key.replace("browserIntent:", "browserReceipt:")].error?.dispatchState === "unknown"))) throw MechanizeProtocol.error("unknownEffect", "A prior browser intent has no confirmed receipt; reconcile before another mutation", "unknown");
    if (Object.keys(session).filter(key => key.startsWith("browserIntent:")).length >= 512) throw MechanizeProtocol.error("receiptCapacity", "Browser receipt capacity exhausted; explicit reconciliation required");
    const requireAuthority = () => {if(!authority() || command.deadlineUnixMs<=Date.now()) throw MechanizeProtocol.error("staleAuthority","Original native authority or deadline is no longer current");};
    let retiredProof=false;
    if(command.action==="browser.navigate" && fingerprintVersion===2) {
      requireAuthority();
      const proof=await chrome.tabs.sendMessage(command.identity.tabId,{requestId:crypto.randomUUID(),action:"executor.retire",identity:command.identity,brokerEpoch:command.brokerEpoch,channelEpoch:command.channelEpoch,scopeHash:command.scopeHash,deadlineUnixMs:command.deadlineUnixMs,controlLease:command.controlLease},{documentId:command.identity.documentId});
      if(!proof || proof.error || proof.retiredAuthorityQuiesced!==true || proof.controlLease?.id!==command.controlLease.id || proof.controlLease?.generation!==command.controlLease.generation || !proof.identity || Object.keys(command.identity).some(k=>proof.identity[k]!==command.identity[k])) throw MechanizeProtocol.error("staleAuthority","Exact source renderer retirement required before navigation");
      retiredProof=true;retired();requireAuthority();
    }
    // No URL/value/credential is persisted. Missing receipt after this marker is unknown.
    await chrome.storage.session.set({["browserIntent:" + command.attemptId]: {identity: command.identity, brokerEpoch: command.brokerEpoch, channelEpoch: command.channelEpoch, scopeHash: command.scopeHash, fingerprint, fingerprintVersion}});
    const frames = await chrome.webNavigation.getAllFrames({tabId: command.identity.tabId});
    const current = frames.find(frame => frame.frameId === 0 && frame.documentId === command.identity.documentId);
    if (!current || !originAllowed(current.url, enrollment)) throw MechanizeProtocol.error("staleIdentity", "Document changed before browser API dispatch");
    MechanizeProtocol.validate(command);
    requireAuthority();
    let receipt;
    if (command.action === "browser.activate") {
      await chrome.tabs.update(command.identity.tabId, {active: true});
      const tab = await chrome.tabs.get(command.identity.tabId);
      receipt = {requestId: command.requestId, attemptId: command.attemptId, identity: command.identity, dispatchState: "dispatched", effectState: "unverified", active: Boolean(tab.active), inputSemantics: "Chrome tabs API; physical window focus not verified"};
    } else {
      let finish;
      const completion = new Promise(resolve => { finish = resolve; });
      const completed = details => { if (details.tabId === command.identity.tabId && details.frameId === 0) finish(details); };
      const failed = details => { if (details.tabId === command.identity.tabId && details.frameId === 0) finish({failed: true}); };
      chrome.webNavigation.onCompleted.addListener(completed);
      chrome.webNavigation.onErrorOccurred.addListener(failed);
      const timer = setTimeout(() => finish({timeout: true}), Math.max(1, Math.min(1000, command.deadlineUnixMs - Date.now() - 250)));
      try {
        await chrome.tabs.update(command.identity.tabId, {url: destination.href});
        const event = await completion;
        const tab = await chrome.tabs.get(command.identity.tabId);
        const updatedFrames = await chrome.webNavigation.getAllFrames({tabId: tab.id});
        const root = updatedFrames.find(frame => frame.frameId === 0);
        const safe = root && (privateTarget ? MechanizeProtocol.websiteAllowed(root.url,enrollment)&&MechanizeProtocol.websiteAllowed(tab.url,enrollment)&&new URL(root.url).origin===destination.origin&&new URL(tab.url).origin===destination.origin : originAllowed(root.url,enrollment)&&originAllowed(tab.url,enrollment));
        // A successful tabs.update may still expose the old committed frame.
        // Report dispatch separately from readiness, without inventing a new
        // document or treating the original enrolled source as a redirect.
        const pendingDestination = !tab.pendingUrl || (MechanizeProtocol.websiteAllowed(tab.pendingUrl,enrollment) &&
          !new URL(tab.pendingUrl).username && !new URL(tab.pendingUrl).password &&
          (!privateTarget || new URL(tab.pendingUrl).origin===destination.origin));
        const pending = Boolean(event.timeout && !event.failed && pendingDestination &&
          (!root || root.documentId===command.identity.documentId && originAllowed(root.url,enrollment)) &&
          (originAllowed(tab.url,enrollment) || new URL(tab.url).origin===destination.origin));
        receipt = {requestId: command.requestId, attemptId: command.attemptId, identity: command.identity, dispatchState: "dispatched", effectState: "unverified", ready: Boolean(safe && !event.failed && !event.timeout), inputSemantics: "Chrome navigation API; readiness is not a business outcome"};
        if (!pendingDestination || !safe && !pending) receipt.error = MechanizeProtocol.error("redirectOriginDenied", "Navigation redirected outside enrolled origins; reconcile", "unknown");
        else if (safe && !pending) receipt.newDocument = {profileChannel: command.identity.profileChannel, browserInstance: command.identity.browserInstance, tabId: tab.id, frameId: 0, documentId: root.documentId, documentGeneration: 1, origin: new URL(root.url).origin, title: privateTarget?'':redact(tab.title || "").slice(0, 256), titleTruncated: privateTarget?false:redact(tab.title || "").length > 256};
        if(privateTarget)receipt.privateTarget=true;
      } finally { clearTimeout(timer); chrome.webNavigation.onCompleted.removeListener(completed); chrome.webNavigation.onErrorOccurred.removeListener(failed); }
    }
    if(retiredProof){receipt.retiredAuthorityQuiesced=true;receipt.controlLease={...command.controlLease};}
    if(fingerprintVersion===2) {receipt.fingerprintVersion=2;receipt.fingerprintSHA256=fingerprint;}
    receipt=redact(receipt);
    await chrome.storage.session.set({["browserReceipt:" + command.attemptId]: receipt});
    return receipt;
  }
  // A channel-scoped browser operation: never reads or injects the source page.
  // The shared browser intent/receipt keys retain the same restart and unknown gates.
  async function openOrigin(api, command, enrollment, fence, authority) {
    const keys=['type','requestId','attemptId','origin','brokerEpoch','channelEpoch','scopeHash','deadlineUnixMs',...(command?.controlBadge===true?['controlBadge']:[])];
    const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
    if(!command||Object.keys(command).sort().join()!==keys.sort().join()||command.type!=='browser.openOrigin'||!hex(command.requestId)||!hex(command.attemptId)||!Number.isSafeInteger(command.deadlineUnixMs)||command.deadlineUnixMs<=Date.now()||command.deadlineUnixMs>Date.now()+10000||!fence||['brokerEpoch','channelEpoch','scopeHash'].some(k=>command[k]!==fence[k]))return null;
    let origin;try{const u=new URL(command.origin);if(u.origin!==command.origin||u.username||u.password||!['https:','http:'].includes(u.protocol)||!MechanizeProtocol.websiteAllowed(u.origin,enrollment))return null;origin=u.origin;}catch{return null;}
    const reply=(dispatchState,tabId=0,errorCode='none')=>({type:'browser.openOriginResult',requestId:command.requestId,attemptId:command.attemptId,brokerEpoch:fence.brokerEpoch,channelEpoch:fence.channelEpoch,scopeHash:fence.scopeHash,dispatchState,tabId,errorCode});
    const check=()=>{if(!authority()||Date.now()>=command.deadlineUnixMs)throw 'authorityChanged';};
    let crossed=false,intended=false;
    try{
      check();
      const canonical=JSON.stringify(['mechanize-browser-open-origin-v1',enrollment.profileChannel,enrollment.browserInstance,command.attemptId,origin,command.brokerEpoch,command.channelEpoch,command.scopeHash]);
      const fingerprint=[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical)))].map(x=>x.toString(16).padStart(2,'0')).join('');
      const store=await api.storage.session.get(null);check();
      const ik='browserIntent:'+command.attemptId,rk='browserReceipt:'+command.attemptId,old=store[ik];
      if(old){
        if(old.action!=='browser.openOrigin'||old.fingerprint!==fingerprint)return reply('notDispatched',0,'attemptConflict');
        const prior=store[rk];
        if(!prior)return reply('unknown',0,'receiptUnavailable');
        const shape=reply(prior.dispatchState,prior.tabId,prior.errorCode);
        if(Object.keys(prior).sort().join()!==Object.keys(shape).sort().join()||['type','attemptId','brokerEpoch','channelEpoch','scopeHash'].some(k=>prior[k]!==shape[k])||!hex(prior.requestId)||!['dispatched','notDispatched','unknown'].includes(prior.dispatchState)||!Number.isSafeInteger(prior.tabId)||prior.dispatchState==='dispatched'&&(prior.tabId<=0||prior.errorCode!=='none')||prior.dispatchState!=='dispatched'&&(prior.tabId!==0||!['authorityChanged','permissionUnavailable','windowUnavailable','receiptCapacity','unknownEffect','lifecycleInhibited','creationUnavailable','receiptUnavailable','attemptConflict'].includes(prior.errorCode)))return reply('unknown',0,'receiptUnavailable');
        return shape;
      }
      if(Object.keys(store).some(k=>k.startsWith('browserIntent:')&&(!store[k.replace('browserIntent:','browserReceipt:')]||store[k.replace('browserIntent:','browserReceipt:')].dispatchState==='unknown'||store[k.replace('browserIntent:','browserReceipt:')].error?.dispatchState==='unknown')))throw 'unknownEffect';
      if(Object.keys(store).filter(k=>k.startsWith('browserIntent:')).length>=512)throw 'receiptCapacity';
      if(store.mechanizeLifecycleInhibited)throw 'lifecycleInhibited';
      if(!await api.permissions.contains({origins:[origin+'/*']}))throw 'permissionUnavailable';check();
      const window=await api.windows.getLastFocused({populate:false,windowTypes:['normal']});check();
      if(!window||!Number.isSafeInteger(window.id)||window.id<0||window.type!=='normal'||window.incognito===true)throw 'windowUnavailable';
      await api.storage.session.set({[ik]:{action:'browser.openOrigin',fingerprintVersion:1,fingerprint,brokerEpoch:fence.brokerEpoch,channelEpoch:fence.channelEpoch,scopeHash:fence.scopeHash}});intended=true;
      check();if(!await api.permissions.contains({origins:[origin+'/*']}))throw 'permissionUnavailable';check();
      crossed=true;
      const tab=await api.tabs.create({windowId:window.id,url:origin+'/',active:false});
      check();if(!tab||!Number.isSafeInteger(tab.id)||tab.id<=0||tab.windowId!==window.id||tab.incognito===true||tab.active!==false)throw 'creationUnavailable';
      const result=reply('dispatched',tab.id);await api.storage.session.set({[rk]:result});const confirmed=await api.storage.session.get(rk);if(!confirmed[rk]||Object.keys(confirmed[rk]).sort().join()!==Object.keys(result).sort().join()||Object.keys(result).some(k=>confirmed[rk][k]!==result[k]))throw 'creationUnavailable';check();if(command.controlBadge===true&&globalThis.MechanizeControlBadgeMetadata&&command.deadlineUnixMs-Date.now()>300){const controlBadgeWindow=await MechanizeControlBadgeMetadata.window(api,tab.id,Math.min(command.deadlineUnixMs,Date.now()+250),authority);check();if(controlBadgeWindow)return {...result,controlBadgeWindow};}return result;
    }catch(reason){
      const allowed=['authorityChanged','permissionUnavailable','windowUnavailable','receiptCapacity','unknownEffect','lifecycleInhibited'];
      const result=reply(crossed?'unknown':'notDispatched',0,allowed.includes(reason)?reason:'creationUnavailable');
      if(intended)try{await api.storage.session.set({['browserReceipt:'+command.attemptId]:result});}catch{return reply('unknown',0,'receiptUnavailable');}
      return result;
    }
  }
  return {execute, query, openOrigin};
})();
