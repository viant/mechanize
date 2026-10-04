// Injected only by the worker into an enrolled document's ISOLATED world.
if (!globalThis.__mechanizeExecutor) {
  globalThis.__mechanizeExecutor = true;
  let binding = null, generation = 1, quiesced = false;
  let controlLease = null;
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
  const receiptErrors = new Set(["ambiguousTarget", "coverageIncomplete", "invalidLocator", "invalidRequest", "targetNotActionable", "targetNotFound", "unsupportedAction", "unsupportedAttribute", "unsupportedControl", "unsupportedSelector", "userActivationRequired", "dispatchFailure"]);
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
      if (receiptRevision !== revision || executorStateRevision !== stateRevision || stableBinding() !== fence || JSON.stringify([exportReadiness(), recorder.id]) !== readySnapshot) throw MechanizeProtocol.error("receiptSnapshotChanged", "Receipt or executor readiness changed during export");
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
  chrome.runtime.onMessage.addListener((message, sender, reply) => {
    if (sender.id !== chrome.runtime.id) return;
    try {
      flush();
      if (message.type === "bind") {
        if (quiesced) throw MechanizeProtocol.error("executorQuiesced", "Quiesced document cannot accept a new binding");
        const stable = value => ({...value, identity: {...value.identity, documentGeneration: 0}});
        if (binding && JSON.stringify(stable(binding)) !== JSON.stringify(stable(message.binding))) throw MechanizeProtocol.error("executorNotQuiescent", "Existing document binding cannot be replaced; reconcile receipts first");
        const version = message.binding?.mutationFingerprintVersion || 1;
        if (![1,2].includes(version) || version === 2 && !globalThis.MechanizeFingerprint?.mutationV2) throw MechanizeProtocol.error("fingerprintMismatch", "Packaged v2 executor required");
        binding = message.binding;
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
      if (command.action !== "observe" && i.documentGeneration !== generation) throw MechanizeProtocol.error("staleGeneration", "DOM changed; observe the current generation before dispatch");
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
      // A mutation is synchronous. No timer or detached continuation can mutate later.
      let result;
      try { result = {requestId: command.requestId, attemptId: command.attemptId, ...MechanizeDOM.act(document, command.action, command.locator, command.args)}; }
      catch (error) { result = {requestId: command.requestId, attemptId: command.attemptId, error: error.code ? error : MechanizeProtocol.error("dispatchFailure", "DOM action failed; reconcile before retry", mutation ? "unknown" : "notDispatched")}; }
      flush();
      result.identity = {...binding.identity, documentGeneration: generation};
      if (mutation && fingerprintVersion === 2) { result.fingerprintVersion = 2; result.fingerprintSHA256 = fingerprint; }
      if (mutation) { receipts.set(command.attemptId, {fingerprintVersion, fingerprint, result}); receiptRevision++; }
      reply(result);
      };
      if (mutation && fingerprintVersion === 2) {
        const fail = error => reply({requestId:command.requestId,attemptId:command.attemptId,identity:{...binding.identity,documentGeneration:generation},fingerprintVersion:2,fingerprintSHA256:command.fingerprintSHA256,error:error.code ? error : MechanizeProtocol.error("fingerprintMismatch", "Logical mutation fingerprint could not be confirmed")});
        MechanizeFingerprint.mutationV2(command).then(fingerprint => {
          if (fingerprint.sha256 !== command.fingerprintSHA256) throw MechanizeProtocol.error("fingerprintMismatch", "Logical mutation fingerprint differs");
          perform(fingerprint.sha256);
        }).catch(fail);
        return true;
      }
      perform(JSON.stringify({...command, requestId:null, deadlineUnixMs:null}));
    } catch (error) { reply({requestId: message?.requestId, attemptId: message?.attemptId, identity: binding ? {...binding.identity, documentGeneration: generation} : undefined, error: error.code ? error : MechanizeProtocol.error("invalidRequest", "Invalid content command")}); }
  });
  addEventListener("pageshow", event => { if (event.persisted) { generation++; quiesced = true; recorder.active = false; if (recorder.id) recorder.push({kind: "gap", reason: "bfcacheRestore", trusted: false}); } });
  addEventListener("pagehide", () => { if (recorder.id) { recorder.push({kind: "gap", reason: "documentLeaving", trusted: false}); recorder.active = false; } });
  for (const event of ["popstate", "hashchange"]) addEventListener(event, () => { generation++; if (recorder.active) recorder.push({kind: "gap", reason: "sameDocumentNavigation", trusted: false}); });
}
