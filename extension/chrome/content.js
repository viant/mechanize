// Injected only by the worker into an enrolled document's ISOLATED world.
if (!globalThis.__mechanizeExecutor) {
  globalThis.__mechanizeExecutor = true;
  let binding = null, generation = 1, quiesced = false;
  let reconnectIntent = null, pendingFingerprints = 0, pendingBrowserInputs = 0;
  const reconnectNonces = new Set();
  let controlLease = null;
  let publicReadScope=null;
  let privateProtected = false, privateContinuation = false,privateInputWritten=false,privateSubmitConfirmed=false;
  let privateRecipient=null;
  let privacyRedactions=null,privacyPermit=null,privacyOrigin=null,privacyActive=false,privacyCommitted=false,privacyCommittedEvidence=false;
  const secureInput = globalThis.MechanizeSecureInput?.create();
  const privateKeys = ["type","requestId","identity","brokerEpoch","channelEpoch","scopeHash","deadlineUnixMs","origin"];
  function privateBinding(message) {
    const i = message.identity;
    if (!binding?.leaseRequired || quiesced || recorder.active || !i ||
        Object.keys(i).sort().join() !== "browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId" ||
        i.frameId !== 0 || window.top !== window || location.origin !== message.origin ||
        typeof message.origin !== "string" || !message.origin.startsWith("https://") || new URL(message.origin).origin !== message.origin ||
        !/^[a-f0-9]{32}(?:[a-f0-9]{32})?$/.test(message.requestId) ||
        !Number.isSafeInteger(message.deadlineUnixMs) || message.deadlineUnixMs <= Date.now() || message.deadlineUnixMs > Date.now()+10000 ||
        ["profileChannel","browserInstance","tabId","frameId","documentId"].some(k => i[k] !== binding.identity[k]) ||
        ["brokerEpoch","channelEpoch","scopeHash"].some(k => message[k] !== binding[k])) throw Error();
  }
  function privateReceive(message,sender,reply) {
    const inspect = message.type === "credentialInspect", submit=message.type==="credentialSubmit",post=message.type==="credentialPostSubmit";
    // "unavailable" is a positive same-document privacy candidate on the
    // post-submit wire. Failed authority/lease checks prove no readiness.
    let status = "notDispatched", ready = false, stage=post?"pending":"unavailable", retired=false, retiredLease=null,inspectionReason="requestInvalid";
    const diagnostics=inspect&&message.diagnostics===true;
    try {
      if (sender.tab || sender.url && sender.url !== `chrome-extension://${chrome.runtime.id}/worker.js`) throw Error();
      const keys = post ? [...privateKeys,"attemptId","controlLease"] : inspect ? [...privateKeys,...(Object.hasOwn(message,"controlLease") ? ["controlLease"] : [])] : submit ? [...privateKeys,"attemptId","fillAttemptId","controlLease"] : [...privateKeys,"attemptId","controlLease","username","password"];

      if(diagnostics)keys.push('diagnostics');
      const pinned = Object.hasOwn(message,'recipientId');
      if(pinned) {
        if(post||submit||typeof message.recipientId!=='string'||!/^[a-f0-9]{64}$/.test(message.recipientId))throw Error();
        keys.push('recipientId');
      }
      if (Object.keys(message).sort().join() !== [...keys].sort().join()) throw Error();
      inspectionReason="documentBindingUnavailable";flush();privateBinding(message);
      inspectionReason=privateInputWritten?"privateInputRetained":"privateDocumentProtected";
      if (!secureInput || inspect&&privateProtected&&!privateContinuation || submit&&!privateProtected) throw Error();
      if(post) {
        if(!privateSubmitConfirmed||controlLease!==null||!message.controlLease||!retiredLeases.has(leaseKey(message.controlLease)))throw Error();
        const result=secureInput.postSubmitStatus(document,{attemptId:message.attemptId,origin:message.origin,deadlineUnixMs:message.deadlineUnixMs},()=>{privateBinding(message);return true;});
        stage=result.stage;
      } else if (inspect) {
        if(pinned && !Object.hasOwn(message,'controlLease')) {
          inspectionReason="privateInputRetained";if(privateInputWritten)throw Error();
          inspectionReason="recipientUnavailable";
          // A pre-input generation retry must retain the originally selected
          // recipient. Re-inspection cannot silently accept replacement fields.
          if(!privateRecipient||privateRecipient.id!==message.recipientId){
            privateRecipient?.pin.retire();
            privateRecipient={id:message.recipientId,documentId:message.identity.documentId,origin:message.origin,
              pin:globalThis.MechanizeSecureInput.pinRecipient(document,message.origin)};
          }
        }
        const recipientCurrent=()=>privateRecipient&&privateRecipient.id===message.recipientId&&
          privateRecipient.documentId===message.identity.documentId&&privateRecipient.origin===message.origin&&privateRecipient.pin.current();
        inspectionReason="recipientChanged";if(pinned&&!recipientCurrent())throw Error();
        inspectionReason="readinessUnavailable";const result = globalThis.MechanizeSecureInput.inspect(document,message.origin,() => {
          privateBinding(message);
          if (Object.hasOwn(message,"controlLease") && (!message.controlLease || Object.keys(message.controlLease).sort().join() !== "generation,id" ||
              !sameLease(controlLease,message.controlLease) || (pinned ? !recipientCurrent() || message.identity.documentGeneration > generation : message.identity.documentGeneration !== generation))) throw Error();
          return true;
        });
        ready = result && Object.keys(result).sort().join() === "ready,stage" && result.ready === true;stage=result?.stage||"unavailable";inspectionReason=ready?"none":stage==="challenge"?"challenge":"readinessUnavailable";
      } else if(submit) {
        const lease=message.controlLease;
        if(!lease||Object.keys(lease).sort().join()!=="generation,id"||!sameLease(controlLease,lease))throw Error();
        status="unknown";const result=secureInput.submit(document,{attemptId:message.attemptId,fillAttemptId:message.fillAttemptId,origin:message.origin,deadlineUnixMs:message.deadlineUnixMs},()=>{privateBinding(message);if(!sameLease(controlLease,lease))throw Error();return true;});
        status=result&&Object.keys(result).join()==="status"&&["dispatched","notDispatched","unknown"].includes(result.status)?result.status:"unknown";
        if(status==="dispatched"){retiredLeases.add(leaseKey(lease));controlLease=null;retired=true;retiredLease={...lease};privateSubmitConfirmed=true;}
      } else {
        const lease = message.controlLease;
        const recipientCurrent=(afterWrite=false)=>privateRecipient&&privateRecipient.id===message.recipientId&&privateRecipient.documentId===message.identity.documentId&&privateRecipient.origin===message.origin&&privateRecipient.pin.current(afterWrite);
        if (!lease || Object.keys(lease).sort().join() !== "generation,id" || !sameLease(controlLease,lease) || (pinned ? !recipientCurrent() || message.identity.documentGeneration > generation : message.identity.documentGeneration !== generation)) throw Error();
        privateProtected = true;privateInputWritten=true;
        status = "unknown";
        const result = secureInput.fill(document,{attemptId:message.attemptId,origin:message.origin,deadlineUnixMs:message.deadlineUnixMs,username:message.username,password:message.password},(hasWritten) => {
          privateBinding(message);if (!sameLease(controlLease,lease)||pinned&&!recipientCurrent(hasWritten===true)) throw Error();return true;
        });
        status = result && Object.keys(result).join() === "status" && ["dispatched","notDispatched","unknown"].includes(result.status) ? result.status : "unknown";
      }
    } catch(error) {if(globalThis.MechanizeSecureInput.isInspectionReason?.(error?.inspectionReason))inspectionReason=error.inspectionReason;if(inspectionReason==="challenge")stage="challenge"; /* No page text or thrown value crosses this lane. */ }
    if (inspect||post) reply({ready,stage,privateCredentialProtocolVersion:Object.hasOwn(message,'recipientId')?3:2,identity:binding ? {...binding.identity,documentGeneration:generation} : null,...(Object.hasOwn(message,'recipientId')?{recipientId:message.recipientId}:{}),...(diagnostics?{inspectionReason}:{})});
    else {if(submit)reply({status,retiredAuthorityQuiesced:retired,controlLease:retiredLease||message.controlLease});else{message.username="";message.password="";reply({status});}}
  }
  const retiredLeases = new Set();
  const sameLease = (a, b) => a && b && a.id === b.id && a.generation === b.generation;
  const leaseKey = value => `${value.id}:${value.generation}`;
  let receiptRevision = 0, executorStateRevision = 0;
  const receipts = new Map(); // Never evict receipt identities within a document.
  const recorder = new MechanizeRecorder(document, () => { flush(); return {...binding.identity, documentGeneration: generation}; }, location.origin);
  const observer = new MutationObserver(records => { if (records.length) generation++; });
  observer.observe(document, {subtree: true, childList: true, attributes: true, characterData: true});
  function flush() { if (observer.takeRecords().length) generation++; }
  const exportErrors = new Set(["invalidReceiptExport", "receiptRevisionMismatch", "receiptSnapshotChanged", "receiptExportUnavailable", "dispatchExpired", "frameTooLarge"]);
  const receiptErrors = new Set(["ambiguousTarget", "coverageIncomplete", "invalidLocator", "invalidRequest", "targetNotActionable", "targetNotFound", "unsupportedAction", "unsupportedAttribute", "unsupportedControl", "unsupportedSelector", "userActivationRequired", "secureDocumentRequired", "dispatchFailure"]);
  const pointerErrors = new Set(['targetNotActionable','targetNotFound','dispatchExpired','staleAuthority','secureDocumentRequired','browserInputDenied','browserInputUnavailable','browserInputTimeout','browserInputFrameTimeout','browserInputAttachTimeout','browserInputMouseMoveTimeout','browserInputMousePressTimeout','browserInputMouseReleaseTimeout','browserInputKeyDownTimeout','browserInputKeyUpTimeout','browserInputDocumentChanged','browserInputInhibited','browserInputPermitUnavailable','browserInputSenderMismatch','browserInputRequestMismatch','browserInputAuthorityChanged','browserInputTargetDenied','browserInputDeadlineDenied']);
  const dispatchStates = new Set(["dispatched", "notDispatched", "unknown"]);
  const effectStates = new Set(["none", "unverified", "unknown", "verified"]);
  const opaqueID = value => typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value);
  const exportFailure = error => MechanizeProtocol.error(exportErrors.has(error?.code) ? error.code : "receiptExportUnavailable", "Bounded receipt export could not be confirmed");
  function stableBinding() {
    return JSON.stringify({...binding, identity: {...binding.identity, documentGeneration: 0}});
  }
  function exportReadiness() {
    const state = {quiesced, controlLeaseHeld: Boolean(controlLease),
      recordingState: !recorder.id ? "none" : recorder.stopped ? "stopped" : recorder.active ? "recording" : "paused",
      recordingLastSequence: recorder.sequence, recordingDroppedThrough: recorder.droppedThrough,
      recordingLeaseExpiresUnixMs: recorder.active ? recorder.expiresAt : 0};
    if (controlLease) state.controlLease = {id: controlLease.id, generation: controlLease.generation};
    return state;
  }
  async function exportReceipts(command) {
    const {offset, limit, expectedRevision} = command.args;
    if (offset > receipts.size) throw MechanizeProtocol.error("invalidReceiptExport", "Receipt cursor exceeds retained history");
    if (expectedRevision !== undefined && expectedRevision !== receiptRevision) throw MechanizeProtocol.error("receiptRevisionMismatch", "Receipt revision changed; restart export");
    const revision = receiptRevision, stateRevision = executorStateRevision, total = receipts.size, fence = stableBinding(), readiness = exportReadiness();
    // A recording identity is checked privately, never included in the export.
    const readySnapshot = JSON.stringify([readiness, recorder.id]);
    const i = binding.identity;
    if (![i.profileChannel, i.browserInstance, i.documentId].every(opaqueID) || controlLease && !opaqueID(controlLease.id)) throw MechanizeProtocol.error("receiptExportUnavailable", "Bounded opaque identities required");
    const entries = [...receipts.entries()].slice(offset, offset + limit);
    let timer;
    try {
      const exported = await Promise.race([
        Promise.all(entries.map(async ([attemptId, receipt]) => {
          if (!opaqueID(attemptId)) throw MechanizeProtocol.error("receiptExportUnavailable", "Bounded opaque attempt identity required");
          const version = receipt.fingerprintVersion || 1;
          if (version !== (binding.mutationFingerprintVersion || 1)) throw MechanizeProtocol.error("receiptExportUnavailable", "Receipt version differs from immutable executor");
          let digest;
          if (version === 2) { if (!/^[0-9a-f]{64}$/.test(receipt.fingerprint)) throw MechanizeProtocol.error("receiptExportUnavailable", "Exact stored v2 digest required"); digest=receipt.fingerprint; }
          else { const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(receipt.fingerprint)); if (hash.byteLength !== 32) throw MechanizeProtocol.error("receiptExportUnavailable", "SHA256 digest unavailable"); digest=[...new Uint8Array(hash)].map(byte => byte.toString(16).padStart(2,"0")).join(""); }
          const result = receipt.result;
          const dispatchState = dispatchStates.has(result.dispatchState) ? result.dispatchState : dispatchStates.has(result.error?.dispatchState) ? result.error.dispatchState : "unknown";
          const effectState = effectStates.has(result.effectState) ? result.effectState : effectStates.has(result.error?.effectState) ? result.error.effectState : dispatchState === "dispatched" ? "unverified" : dispatchState === "notDispatched" ? "none" : "unknown";
          const row = {attemptId, fingerprintSHA256: digest, dispatchState, effectState};
          if (version === 2) row.fingerprintVersion = 2;
          if (result.error) {
            row.errorCode = receiptErrors.has(result.error.code) ? result.error.code : "unclassified";
            row.errorDispatchState = dispatchStates.has(result.error.dispatchState) ? result.error.dispatchState : "unknown";
          }
          return row;
        })),
        new Promise((_, reject) => { timer = setTimeout(() => reject(MechanizeProtocol.error("dispatchExpired", "Receipt export deadline expired")), Math.max(0, command.deadlineUnixMs - Date.now())); })
      ]);
      if (Date.now() >= command.deadlineUnixMs) throw MechanizeProtocol.error("dispatchExpired", "Receipt export deadline expired");
      if (privateProtected || receiptRevision !== revision || executorStateRevision !== stateRevision || stableBinding() !== fence || JSON.stringify([exportReadiness(), recorder.id]) !== readySnapshot) throw MechanizeProtocol.error("receiptSnapshotChanged", "Receipt or executor readiness changed during export");
      // Page animation does not change immutable receipt history. Report the
      // current DOM generation without invalidating an otherwise exact page.
      flush();
      const response = {version: binding.mutationFingerprintVersion === 2 ? 2 : 1, requestId: command.requestId,
        identity: {profileChannel: i.profileChannel, browserInstance: i.browserInstance, tabId: i.tabId, frameId: i.frameId, documentId: i.documentId, documentGeneration: generation},
        total, revision, offset, nextOffset: offset + exported.length, truncated: offset + exported.length < total, receipts: exported, readiness};
      if (new TextEncoder().encode(JSON.stringify(response)).length > MechanizeProtocol.MAX_BYTES) throw MechanizeProtocol.error("frameTooLarge", "Receipt export exceeds frame budget");
      return response;
    } finally { clearTimeout(timer); }
  }
  const reconnectKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join() === [...keys].sort().join();
  const reconnectIdentityKeys = ["profileChannel","browserInstance","tabId","frameId","documentId","documentGeneration"];
  function reconnectIdle() {
    if (privateProtected || privateContinuation || privateInputWritten || privacyRedactions !== null || privacyPermit !== null || privacyOrigin !== null || privacyActive || privacyCommitted || pendingFingerprints || pendingBrowserInputs || recorder.id !== null || recorder.active || recorder.stopped || recorder.sequence || recorder.droppedThrough || recorder.events.length || recorder.expiryTimer !== null) return false;
    for (const receipt of receipts.values()) {
      const r = receipt.result, d = dispatchStates.has(r?.dispatchState) ? r.dispatchState : dispatchStates.has(r?.error?.dispatchState) ? r.error.dispatchState : "unknown";
      const e = effectStates.has(r?.effectState) ? r.effectState : effectStates.has(r?.error?.effectState) ? r.error.effectState : d === "dispatched" ? "unverified" : d === "notDispatched" ? "none" : "unknown";
      if (d === "unknown" || e === "unknown" || r?.error?.dispatchState === "unknown" || r?.error?.effectState === "unknown") return false;
    }
    return true;
  }
  function brokerReconnect(message, sender, reply) {
    try {
      if (Object.hasOwn(sender,"tab") || Object.hasOwn(sender,"url") && sender.url !== `chrome-extension://${chrome.runtime.id}/worker.js` || !["inspect","prepare","adopt"].includes(message.phase) ||
          !reconnectKeys(message,["type","phase","nonce","deadlineUnixMs","oldFence","newBinding",...(message.phase === "adopt" ? ["receiptRevision"] : [])]) ||
          !/^[a-f0-9]{64}$/.test(message.nonce) || !Number.isSafeInteger(message.deadlineUnixMs) || message.deadlineUnixMs <= Date.now() || message.deadlineUnixMs > Date.now()+10000) throw Error();
      const next = message.newBinding, old = message.oldFence, i = next?.identity;
      if (!reconnectKeys(old,["brokerEpoch","channelEpoch","scopeHash"]) || !opaqueID(old.brokerEpoch) || !opaqueID(old.channelEpoch) || !/^[a-f0-9]{64}$/.test(old.scopeHash) ||
          !reconnectKeys(next,["identity","brokerEpoch","channelEpoch","scopeHash","leaseRequired","mutationFingerprintVersion"]) || !reconnectKeys(i,reconnectIdentityKeys) ||
          ![i.profileChannel,i.browserInstance,i.documentId,next.brokerEpoch,next.channelEpoch].every(opaqueID) || !Number.isSafeInteger(i.tabId) || i.tabId < 0 || !Number.isSafeInteger(i.frameId) || i.frameId < 0 || !Number.isSafeInteger(i.documentGeneration) || i.documentGeneration < 1 ||
          next.scopeHash !== old.scopeHash || next.leaseRequired !== true || next.mutationFingerprintVersion !== 2 || !globalThis.MechanizeFingerprint?.mutationV2 ||
          next.brokerEpoch === old.brokerEpoch && next.channelEpoch === old.channelEpoch) throw Error();
      flush();
      const frozen = JSON.stringify([message.nonce,message.deadlineUnixMs,old.brokerEpoch,old.channelEpoch,old.scopeHash,...reconnectIdentityKeys.map(k=>i[k]),next.brokerEpoch,next.channelEpoch,next.scopeHash,next.leaseRequired,next.mutationFingerprintVersion]);
      if (message.phase !== "adopt") {
        if (reconnectIntent || reconnectNonces.has(message.nonce) || reconnectNonces.size >= 256 || quiesced || !reconnectIdle()) throw Error();
        if (binding) {
          const legacyTrust = reconnectKeys(binding,[...Object.keys(next),"trustScope","scopeQualified","profileQualified"]) &&
            ["desktop","profile"].includes(binding.trustScope) && binding.scopeQualified === true && binding.profileQualified === (binding.trustScope === "profile");
          if (!(reconnectKeys(binding,Object.keys(next)) || legacyTrust) || binding.leaseRequired !== true || binding.mutationFingerprintVersion !== 2 ||
              ["profileChannel","browserInstance","tabId","frameId","documentId"].some(k => binding.identity[k] !== i[k]) || Object.keys(old).some(k => binding[k] !== old[k])) throw Error();
        } else if (controlLease || receipts.size || receiptRevision || retiredLeases.size || executorStateRevision) throw Error();
        if (message.phase === "inspect") {reply({nonce:message.nonce,phase:"inspected",version:1,identity:{...i,documentGeneration:generation}});return;}
        if (controlLease) { if (retiredLeases.size >= 512) throw Error(); retiredLeases.add(leaseKey(controlLease)); controlLease = null; }
        reconnectNonces.add(message.nonce);
        const trust = binding && Object.hasOwn(binding,"trustScope") ? Object.freeze({trustScope:binding.trustScope,scopeQualified:binding.scopeQualified,profileQualified:binding.profileQualified}) : Object.freeze({});
        reconnectIntent = Object.freeze({frozen,revision:receiptRevision,generation,trust});
        quiesced = true; executorStateRevision++;
      } else {
        if (!reconnectIntent || !quiesced || reconnectIntent.frozen !== frozen || reconnectIntent.revision !== message.receiptRevision || receiptRevision !== message.receiptRevision || generation < reconnectIntent.generation || !reconnectIdle() || controlLease) throw Error();
        binding = {identity:{...i,documentGeneration:generation},brokerEpoch:next.brokerEpoch,channelEpoch:next.channelEpoch,scopeHash:next.scopeHash,leaseRequired:true,mutationFingerprintVersion:2,...reconnectIntent.trust};
        reconnectIntent = null;quiesced = false;executorStateRevision++;
      }
      reply({nonce:message.nonce,phase:message.phase === "prepare" ? "prepared" : "adopted",identity:{...i,documentGeneration:generation},receiptRevision,receiptCount:receipts.size,quiescent:true});
    } catch { reply({error:MechanizeProtocol.error("executorReconnectUnavailable","Exact idle renderer reconnect proof unavailable")}); }
  }
  function scopedPublicRead(message) {
    flush();const scope=publicReadScope;
    if(!scope||generation!==scope.identity.documentGeneration||message.identity?.documentGeneration!==scope.identity.documentGeneration||!['observe','read','resolve','executor.validate'].includes(message?.action)||!binding||quiesced||reconnectIntent||Date.now()>=scope.deadline)return false;
    if(['profileChannel','browserInstance','tabId','frameId','documentId'].some(k=>message.identity?.[k]!==scope.identity[k]||binding.identity[k]!==scope.identity[k])||['brokerEpoch','channelEpoch','scopeHash'].some(k=>message[k]!==scope[k]||binding[k]!==scope[k]))return false;
    try{const u=new URL(document.URL);return u.origin+u.pathname===scope.route&&globalThis.MechanizeDOM.credentialLayout(document).state==='public';}catch{return false;}
  }
  async function qualifyPublicRead(message,sender,reply) {
    publicReadScope=null;
    const refused=()=>reply({requestId:message?.requestId,publicDocument:null});
    try {
      const keys=[...privateKeys,'redactions'],i=message.identity;
      if(sender.tab||sender.url&&sender.url!==`chrome-extension://${chrome.runtime.id}/worker.js`||Object.keys(message).sort().join()!==keys.sort().join()||!i||Object.keys(i).sort().join()!=='browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId'||i.frameId!==0||window.top!==window||!Number.isSafeInteger(i.documentGeneration)||i.documentGeneration<0||!Number.isSafeInteger(i.tabId)||i.tabId<1||!['profileChannel','browserInstance','documentId'].every(k=>typeof i[k]==='string'&&i[k].length>0&&i[k].length<=128)||!/^[a-f0-9]{64}$/.test(message.requestId)||!['brokerEpoch','channelEpoch','scopeHash'].every(k=>typeof message[k]==='string'&&message[k].length>0&&message[k].length<=128)||!Number.isSafeInteger(message.deadlineUnixMs)||message.deadlineUnixMs<=Date.now()||message.deadlineUnixMs>Date.now()+5000||location.origin!==message.origin||quiesced||reconnectIntent||pendingFingerprints||pendingBrowserInputs||recorder.active)throw Error();
      if(binding&&(['profileChannel','browserInstance','tabId','frameId','documentId'].some(k=>binding.identity[k]!==i[k])||['brokerEpoch','channelEpoch','scopeHash'].some(k=>binding[k]!==message[k])))throw Error();
      if(!Array.isArray(message.redactions)||message.redactions.length&&!globalThis.MechanizeSecureInput.validRedactions(message.redactions)||privateInputWritten&&!globalThis.MechanizeSecureInput.validRedactions(message.redactions))throw Error();
      const redactions=[...message.redactions];
      flush();const heldBinding=binding,heldGeneration=generation;
      const current=()=>binding===heldBinding&&generation===heldGeneration&&!quiesced&&!reconnectIntent&&!pendingFingerprints&&!pendingBrowserInputs&&!recorder.active&&Date.now()<message.deadlineUnixMs;
      const proof=await globalThis.MechanizeDOM.credentialScopeEvidence(document,current);flush();
      if(!proof.public||!current())throw Error();
      if(!binding)binding={identity:{...i,documentGeneration:generation},brokerEpoch:message.brokerEpoch,channelEpoch:message.channelEpoch,scopeHash:message.scopeHash,leaseRequired:true,mutationFingerprintVersion:2};
      const u=new URL(document.URL);
      publicReadScope={identity:{...binding.identity,documentGeneration:generation},brokerEpoch:binding.brokerEpoch,channelEpoch:binding.channelEpoch,scopeHash:binding.scopeHash,deadline:message.deadlineUnixMs,route:u.origin+u.pathname,redactions};
      reply({requestId:message.requestId,publicDocument:{version:1,identity:{...binding.identity,documentGeneration:generation},routeSHA256:proof.routeSHA256,public:true}});
    }catch{refused();}
  }
  chrome.runtime.onMessage.addListener((message, sender, reply) => {
    if (sender.id !== chrome.runtime.id) return;
    if(message?.type==='credentialPublicScope'){void qualifyPublicRead(message,sender,reply);return true;}
    if (message?.type === "brokerReconnect") {brokerReconnect(message,sender,reply);return;}
    if (reconnectIntent) {reply({error:MechanizeProtocol.error("executorQuiesced","Renderer reconnect is pending")});return;}
    if (["credentialDelivery","credentialInspect","credentialSubmit","credentialPostSubmit"].includes(message?.type)) {privateReceive(message,sender,reply);return;}
    if(message?.type==="credentialBind") {
      let ready=false,stage="unavailable";
      try {
        const i=message.identity,lease=message.controlLease;
        if(binding&&(!privateContinuation||privateInputWritten||["profileChannel","browserInstance","tabId","frameId","documentId"].some(k=>binding.identity[k]!==i?.[k])||["brokerEpoch","channelEpoch","scopeHash"].some(k=>binding[k]!==message[k]))||sender.tab||sender.url&&sender.url!==`chrome-extension://${chrome.runtime.id}/worker.js`||
           Object.keys(message).sort().join()!==[...privateKeys,"controlLease"].sort().join()||!i||Object.keys(i).sort().join()!=="browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId"||
           !lease||Object.keys(lease).sort().join()!=="generation,id"||!opaqueID(lease.id)||!Number.isSafeInteger(lease.generation)||lease.generation<1)throw Error();
        if(controlLease){if(retiredLeases.size>=512)throw Error();retiredLeases.add(leaseKey(controlLease));controlLease=null;}
        binding={identity:{...i},brokerEpoch:message.brokerEpoch,channelEpoch:message.channelEpoch,scopeHash:message.scopeHash,leaseRequired:true,mutationFingerprintVersion:2};
        controlLease={...lease};privateProtected=true;privateContinuation=true;privateBinding(message);
        const result=globalThis.MechanizeSecureInput.inspect(document,message.origin,()=>{privateBinding(message);return true;});ready=result.ready===true;stage=result.stage;
      }catch{ready=false;}
      reply({ready,stage,identity:binding?{...binding.identity,documentGeneration:generation}:null});return;
    }
    if(['credentialManualPrivacyBind','credentialManualPrivacyCommit'].includes(message?.type)){
      let ready=false,redactionReady=false,privateInputRetired=false;
      try{
        const bind=message.type==='credentialManualPrivacyBind',keys=[...privateKeys,'permitId',...(bind?['redactions']:[])];
        if(sender.tab||sender.url&&sender.url!==`chrome-extension://${chrome.runtime.id}/worker.js`||Object.keys(message).sort().join()!==keys.sort().join()||!/^[a-f0-9]{32}(?:[a-f0-9]{32})?$/.test(message.permitId))throw Error();
        // Independent manual-session qualification never borrows or silently
        // retires a prior dispatch lease, recording, receipt, or private input.
        if(controlLease||privateInputWritten||privateSubmitConfirmed||privateContinuation||quiesced||recorder.id||recorder.active||recorder.events.length||pendingFingerprints||pendingBrowserInputs||receipts.size)throw Error();
        if(bind){
          if(!globalThis.MechanizeSecureInput.validRedactions(message.redactions))throw Error();
          if(binding&&['profileChannel','browserInstance','tabId','frameId','documentId'].some(key=>binding.identity[key]!==message.identity?.[key]))throw Error();
          if(privacyRedactions&&(privacyRedactions.length!==message.redactions.length||privacyRedactions.some((value,index)=>value!==message.redactions[index])))throw Error();
          binding={identity:{...message.identity},brokerEpoch:message.brokerEpoch,channelEpoch:message.channelEpoch,scopeHash:message.scopeHash,leaseRequired:true,mutationFingerprintVersion:2};
          privateProtected=true;privacyActive=false;privacyCommitted=false;privacyRedactions=[...message.redactions];privacyPermit=message.permitId;privacyOrigin=message.origin;
          if(!globalThis.MechanizeDOM.installPrivateDocumentRedactor(document,value=>globalThis.MechanizeSecureInput.redact(value,privacyRedactions)))throw Error();
        }
        privateBinding(message);flush();
        if(message.permitId!==privacyPermit||message.origin!==privacyOrigin||!privacyRedactions||!bind&&privacyCommitted)throw Error();
        redactionReady=globalThis.MechanizeSecureInput.validRedactions(privacyRedactions);
        privateInputRetired=controlLease===null&&!privateInputWritten;
        ready=redactionReady&&privateInputRetired&&globalThis.MechanizeSecureInput.privacyReady(document,privacyOrigin);
        if(!bind&&ready){privacyActive=true;privacyCommitted=true;privateProtected=false;}
        if(!ready){privateProtected=true;privacyActive=false;}
      }catch{ready=false;}
      reply({identity:binding?{...binding.identity,documentGeneration:generation}:null,ready,redactionReady,privateInputRetired,permitId:privacyPermit});return;
    }
    if(["credentialPrivacyBind","credentialPrivacyCommit","credentialPrivacyInspect"].includes(message?.type)) {
      let ready=false,redactionReady=false;
      try {
        const bind=message.type==="credentialPrivacyBind",keys=[...privateKeys,"permitId",...(bind?["redactions"]:[])];
        if(sender.tab||sender.url&&sender.url!==`chrome-extension://${chrome.runtime.id}/worker.js`||Object.keys(message).sort().join()!==keys.sort().join()||!/^[a-f0-9]{32}(?:[a-f0-9]{32})?$/.test(message.permitId))throw Error();
        if(bind){
          if(!globalThis.MechanizeSecureInput.validRedactions(message.redactions))throw Error();
          const retainedRedactor=privacyOrigin===message.origin&&privacyPermit!==null&&
            globalThis.MechanizeSecureInput.validRedactions(privacyRedactions)&&privacyRedactions.length===message.redactions.length&&privacyRedactions.every((value,index)=>value===message.redactions[index]);
          // Readiness may be revoked without erasing the authenticated private bind.
          // The exact document/fences and unchanged variants below remain mandatory.
          const committedRefresh=privacyCommittedEvidence&&retainedRedactor;
          if(privacyCommittedEvidence&&!committedRefresh)throw Error();
          if(binding&&((!privateContinuation||privateInputWritten)&&!(privateSubmitConfirmed&&controlLease===null)&&!retainedRedactor||["profileChannel","browserInstance","tabId","frameId","documentId"].some(k=>binding.identity[k]!==message.identity?.[k])||["brokerEpoch","channelEpoch","scopeHash"].some(k=>binding[k]!==message[k])))throw Error();
          if(controlLease){if(retiredLeases.size>=512)throw Error();retiredLeases.add(leaseKey(controlLease));controlLease=null;}
          privateProtected=true;privacyActive=false;
          const nextRedactions=[...message.redactions];
          if(!globalThis.MechanizeDOM.installPrivateDocumentRedactor(document,value=>globalThis.MechanizeSecureInput.redact(value,nextRedactions)))throw Error();
          // A failed layout probe cannot leave a fresh document half-bound.
          binding={identity:{...message.identity},brokerEpoch:message.brokerEpoch,channelEpoch:message.channelEpoch,scopeHash:message.scopeHash,leaseRequired:true,mutationFingerprintVersion:2};
          privacyRedactions=nextRedactions;privacyPermit=message.permitId;privacyOrigin=message.origin;controlLease=null;privacyCommitted=false;
        }
        privateBinding(message);flush();
        if(message.permitId!==privacyPermit||message.origin!==privacyOrigin||!privacyRedactions)throw Error();
        redactionReady=globalThis.MechanizeSecureInput.validRedactions(privacyRedactions);
        ready=redactionReady&&globalThis.MechanizeSecureInput.privacyReady(document,privacyOrigin)&&(bind||message.type==="credentialPrivacyCommit"&&!privacyCommitted||message.type==="credentialPrivacyInspect"&&privacyActive&&privacyCommitted);
        if(message.type==="credentialPrivacyCommit"&&ready){privacyActive=true;privacyCommitted=true;privacyCommittedEvidence=true;privateProtected=false;}
        if(!ready){privateProtected=true;privacyActive=false;}
      }catch{ready=false;}
      reply({identity:binding?{...binding.identity,documentGeneration:generation}:null,ready,redactionReady,privateInputRetired:privacyRedactions!==null,permitId:privacyPermit});return;
    }
    // A committed public document can become a login/challenge again without
    // navigating. Revoke its DOM permit before any ordinary read or input.
    if(privacyActive&&privacyCommitted&&privacyOrigin){const returning=globalThis.MechanizeSecureInput.inspect(document,privacyOrigin,()=>true);if(returning.ready||returning.stage==='challenge'){privateProtected=true;privacyActive=false;}}
    if (privateProtected&&!scopedPublicRead(message)) {reply({error:MechanizeProtocol.error("secureDocumentRequired","Protected document requires private control")});return;}
    const rawReply=reply;
    reply=value=>{try{const combined=[...(privacyRedactions||[]),...(scopedPublicRead(message)?publicReadScope.redactions:[])];const variants=combined.length?[...new Set(combined)]:null;rawReply(variants?globalThis.MechanizeSecureInput.redact(value,variants):value);}catch{rawReply({error:MechanizeProtocol.error("secureDocumentRequired","Private redaction unavailable")});}};
    try {
      if(privacyRedactions&&(!privacyActive||message.action?.startsWith("record."))&&!scopedPublicRead(message)){privateProtected=true;privacyActive=false;throw MechanizeProtocol.error("secureDocumentRequired","Private output redaction unavailable");}
      flush();
      if (message.type === "bind") {
        if (quiesced) throw MechanizeProtocol.error("executorQuiesced", "Quiesced document cannot accept a new binding");
        const sorted = value => Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b)));
        // Inventory display metadata and the document's changing generation are
        // not binding authority. Preserve comparison of every other field.
        const stable = value => {
          const identity = {...value.identity, documentGeneration: 0};
          for (const key of ["origin","title","titleTruncated","mutationFingerprintVersion"]) delete identity[key];
          return sorted({...value, identity: sorted(identity)});
        };
        if (binding && JSON.stringify(stable(binding)) !== JSON.stringify(stable(message.binding))) {
          // Older on-demand executors omitted these informational trust fields.
          // An authenticated worker may add them on the SAME immutable core
          // binding; this is not a fence handoff or receipt/lease retirement.
          const trustKeys=['trustScope','scopeQualified','profileQualified'],next=message.binding;
          const legacyKeys=['identity','brokerEpoch','channelEpoch','scopeHash','leaseRequired','mutationFingerprintVersion'];
          const core=next&&Object.fromEntries(Object.entries(next).filter(([key])=>!trustKeys.includes(key)));
          const additive=!sender.tab&&(!sender.url||sender.url===`chrome-extension://${chrome.runtime.id}/worker.js`) &&
            !pendingFingerprints&&!pendingBrowserInputs &&
            Object.keys(binding).sort().join()===legacyKeys.sort().join() && binding.leaseRequired===true&&binding.mutationFingerprintVersion===2 &&
            next&&Object.keys(next).sort().join()===[...legacyKeys,...trustKeys].sort().join() &&
            ['desktop','profile'].includes(next.trustScope)&&next.scopeQualified===true&&next.profileQualified===(next.trustScope==='profile') &&
            JSON.stringify(stable(binding))===JSON.stringify(stable(core));
          if(!additive)throw MechanizeProtocol.error("executorNotQuiescent", "Existing document binding cannot be replaced; reconcile receipts first");
        }
        const version = message.binding?.mutationFingerprintVersion || 1;
        if (![1,2].includes(version) || version === 2 && !globalThis.MechanizeFingerprint?.mutationV2) throw MechanizeProtocol.error("fingerprintMismatch", "Packaged v2 executor required");
        // Inventory entries may include title/origin and capability metadata.
        // Executor identity has exactly six fields, including in private replies.
        const sourceIdentity=message.binding.identity;
        const identity=Object.fromEntries(['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'].map(key=>[key,sourceIdentity[key]]));
        binding = {...message.binding,identity};
        reply({identity: {...binding.identity, documentGeneration: generation}, mutationFingerprintVersion: binding.mutationFingerprintVersion || 1});
        return;
      }
      const command = MechanizeProtocol.validate(message, true);
      if (!binding) throw MechanizeProtocol.error("notEnrolled", "Document is not bound to an enrolled channel");
      const i = command.identity;
      if (["profileChannel", "browserInstance", "tabId", "frameId", "documentId"].some(k => i[k] !== binding.identity[k]) || command.brokerEpoch !== binding.brokerEpoch || command.channelEpoch !== binding.channelEpoch || command.scopeHash !== binding.scopeHash) throw MechanizeProtocol.error("staleIdentity", "Document/channel/scope identity changed");
      if (command.action === "executor.receipts") {
        exportReceipts(command).then(reply, error => reply({requestId: command.requestId, error: exportFailure(error)}));
        return true; // Keep only this readonly response channel alive for hashing.
      }
      if (command.action === "receipt.query") {
        const receipt = receipts.get(command.attemptId);
        reply(receipt ? {...receipt.result, requestId: command.requestId} : {requestId: command.requestId, dispatchState: "unknown", effectState: "unknown", receiptAvailable: false});
        return;
      }
      if (command.action === "executor.quiesce") {
        quiesced = true;
        recorder.active = false;
        reply({requestId: command.requestId, quiescent: true, identity: {...binding.identity, documentGeneration: generation}});
        return;
      }
      if (command.action === "executor.retire") {
        const lease = command.controlLease;
        if (!lease || (!sameLease(controlLease, lease) && !retiredLeases.has(leaseKey(lease)))) throw MechanizeProtocol.error("staleAuthority", "Exact live or already retired renderer lease required");
        if (!retiredLeases.has(leaseKey(lease)) || sameLease(controlLease, lease)) executorStateRevision++;
        retiredLeases.add(leaseKey(lease));
        if (sameLease(controlLease, lease)) controlLease = null;
        reply({requestId: command.requestId, identity: {...binding.identity, documentGeneration: generation}, retiredAuthorityQuiesced: true, controlLease: lease});
        return;
      }
      if (command.action.startsWith("record.")) {
        if (quiesced && command.action === "record.start") throw MechanizeProtocol.error("executorQuiesced", "Quiesced document cannot start recording");
        reply({requestId: command.requestId, identity: {...binding.identity, documentGeneration: generation}, ...recorder.control(command.action, command.args)});
        return;
      }
      const mutation = MechanizeProtocol.mutations.has(command.action);
      if (mutation && (binding.leaseRequired || command.controlLease) && !sameLease(controlLease, command.controlLease)) throw MechanizeProtocol.error("staleAuthority", "Mutation renderer lease is absent or retired");
      const fingerprintVersion = command.fingerprintVersion || 1;
      if (mutation && fingerprintVersion !== (binding.mutationFingerprintVersion || 1)) throw MechanizeProtocol.error("fingerprintMismatch", "Mutation differs from immutable executor fingerprint version");
      const perform = fingerprint => {
        if (privateProtected&&!scopedPublicRead(command)) throw MechanizeProtocol.error("secureDocumentRequired","Protected document requires private control");
        flush();
        MechanizeProtocol.validate(command, true);
        if (["profileChannel", "browserInstance", "tabId", "frameId", "documentId"].some(k => i[k] !== binding.identity[k]) || command.brokerEpoch !== binding.brokerEpoch || command.channelEpoch !== binding.channelEpoch || command.scopeHash !== binding.scopeHash) throw MechanizeProtocol.error("staleIdentity", "Pinned mutation binding changed");
        if (mutation && (binding.leaseRequired || command.controlLease) && !sameLease(controlLease, command.controlLease)) throw MechanizeProtocol.error("staleAuthority", "Pinned renderer lease changed before mutation");

      if (mutation && receipts.has(command.attemptId)) {
        const existing = receipts.get(command.attemptId);
        if ((existing.fingerprintVersion || 1) !== fingerprintVersion || existing.fingerprint !== fingerprint) throw MechanizeProtocol.error("attemptConflict", "Attempt identity was already used with a different command");
        reply({...existing.result, requestId: command.requestId});
        return;
      }
      if (quiesced) throw MechanizeProtocol.error("executorQuiesced", "Executor has stopped accepting actions");
      if (command.action !== "observe" && command.action !== "executor.validate" && i.documentGeneration !== generation) throw MechanizeProtocol.error("staleGeneration", "DOM changed; observe the current generation before dispatch");
      if (command.action === "executor.acquire") {
        const lease = command.controlLease;
        if (!lease || retiredLeases.has(leaseKey(lease)) || retiredLeases.size >= 512 || controlLease && !sameLease(controlLease, lease)) throw MechanizeProtocol.error("staleAuthority", "Fresh exclusive renderer lease required");
        if (!sameLease(controlLease, lease)) executorStateRevision++;
        controlLease = {...lease};
        reply({requestId: command.requestId, identity: {...binding.identity, documentGeneration: generation}, validated: true, controlLease});
        return;
      }
      if (command.controlLease && !sameLease(controlLease, command.controlLease)) throw MechanizeProtocol.error("staleAuthority", "Renderer lease does not match live authority");
      if (command.action === "executor.validate") { reply({requestId: command.requestId, identity: {...binding.identity, documentGeneration: generation}, validated: true}); return; }
      if (mutation && receipts.size >= 512) throw MechanizeProtocol.error("receiptCapacity", "Receipt cache full; reconcile or explicitly attach a fresh owned document");
      const complete = result => {
        flush();
        result.identity = {...binding.identity, documentGeneration: generation};
        if (mutation && fingerprintVersion === 2) { result.fingerprintVersion = 2; result.fingerprintSHA256 = fingerprint; }
        if (mutation) { receipts.set(command.attemptId, {fingerprintVersion, fingerprint, result:privacyRedactions?globalThis.MechanizeSecureInput.redact(result,privacyRedactions):result}); receiptRevision++; }
        reply(result);
      };
      const protocolInput=mutation&&fingerprintVersion===2&&command.action==='element.press'&&i.frameId===0&&chrome.runtime.getManifest?.().permissions?.includes('debugger');
      if(protocolInput) {
        pendingBrowserInputs++;
        receipts.set(command.attemptId,{fingerprintVersion,fingerprint,result:{requestId:command.requestId,attemptId:command.attemptId,dispatchState:'unknown',effectState:'unknown'}});
        return (async()=>{
          let forwarded=false;
          try {
            const point=await MechanizeDOM.protocolClickPoint(document,command.locator,command.deadlineUnixMs);
            if(privateProtected||quiesced||!sameLease(controlLease,command.controlLease)||Date.now()>=command.deadlineUnixMs)throw MechanizeProtocol.error('staleAuthority','Browser input authority changed');
            forwarded=true;
            const delivered=await chrome.runtime.sendMessage({type:'browserInputLocal',requestId:command.requestId,attemptId:command.attemptId,deadlineUnixMs:command.deadlineUnixMs,action:'click',point});
            if(!delivered||!['notDispatched','dispatched','unknown'].includes(delivered.dispatchState))throw Error();
            const result={requestId:command.requestId,attemptId:command.attemptId,dispatchState:delivered.dispatchState,effectState:delivered.effectState,inputSemantics:delivered.inputSemantics};
            if(delivered.errorCode)result.error=MechanizeProtocol.error(pointerErrors.has(delivered.errorCode)?delivered.errorCode:'dispatchFailure','Browser protocol input did not complete',delivered.dispatchState);
            return result;
          } catch(error) {
            return {requestId:command.requestId,attemptId:command.attemptId,error:MechanizeProtocol.error(pointerErrors.has(error?.code)?error.code:'dispatchFailure','Browser protocol input did not complete',forwarded?'unknown':'notDispatched')};
          } finally {pendingBrowserInputs--;}
        })().then(complete);
      }
      // Legacy DOM delivery stays synchronous and retains its original receipts.
      let result;
      try {const run=()=>MechanizeDOM.act(document,command.action,command.locator,command.args);result={requestId:command.requestId,attemptId:command.attemptId,...(scopedPublicRead(command)?MechanizeDOM.withCredentialScope(document,()=>scopedPublicRead(command),run):run())};}
      catch(error){result={requestId:command.requestId,attemptId:command.attemptId,error:error.code?error:MechanizeProtocol.error('dispatchFailure','DOM action failed; reconcile before retry',mutation?'unknown':'notDispatched')};}
      complete(result);
      };
      if (mutation && fingerprintVersion === 2) {
        const fail = error => reply({requestId:command.requestId,attemptId:command.attemptId,identity:{...binding.identity,documentGeneration:generation},fingerprintVersion:2,fingerprintSHA256:command.fingerprintSHA256,error:error.code ? error : MechanizeProtocol.error("fingerprintMismatch", "Logical mutation fingerprint could not be confirmed")});
        pendingFingerprints++;
        let hashing=true;const finishedHash=()=>{if(hashing){hashing=false;pendingFingerprints--;}};
        Promise.resolve().then(()=>MechanizeFingerprint.mutationV2(command)).then(fingerprint => {
          finishedHash();
          if (fingerprint.sha256 !== command.fingerprintSHA256) throw MechanizeProtocol.error("fingerprintMismatch", "Logical mutation fingerprint differs");
          return perform(fingerprint.sha256);
        }).catch(error=>{finishedHash();fail(error);});
        return true;
      }
      void perform(JSON.stringify({...command, requestId:null, deadlineUnixMs:null}));
      return true;
    } catch (error) { reply({requestId: message?.requestId, attemptId: message?.attemptId, identity: binding ? {...binding.identity, documentGeneration: generation} : undefined, error: error.code ? error : MechanizeProtocol.error("invalidRequest", "Invalid content command")}); }
  });
  addEventListener("pageshow", event => { if (event.persisted) { generation++; quiesced = true; recorder.active = false; if (recorder.id) recorder.push({kind: "gap", reason: "bfcacheRestore", trusted: false}); } });
  addEventListener("pagehide", () => { if (recorder.id) { recorder.push({kind: "gap", reason: "documentLeaving", trusted: false}); recorder.active = false; } });
  for (const event of ["popstate", "hashchange"]) addEventListener(event, () => { generation++; if (recorder.active) recorder.push({kind: "gap", reason: "sameDocumentNavigation", trusted: false}); });
}
