// Metadata only: no page access, values/keys in output, storage writes, lifecycle
// reset, reconnect, or input authority. Usable before a website executor exists.
globalThis.MechanizeSetupMetadata = (() => {
  const INVENTORY_REASONS=Object.freeze(["none","tabQueryUnavailable","tabListInvalid","tabLimitExceeded","tabMetadataInvalid","tabIDInvalid","tabIDDuplicate","tabURLUnavailable","tabURLInvalid","pendingNavigation","incognitoTab","discardedTab","nonSetupTab","frameQueryUnavailable","frameListUnavailable","frameLimitExceeded","frameMetadataInvalid","frameIDInvalid","frameIDDuplicate","frameParentInvalid","frameDocumentUnavailable","frameError","frameLifecycleInactive","rootLifecycleMissing","rootLifecyclePrerender","rootLifecycleCached","rootLifecyclePendingDeletion","rootLifecycleInvalid","rootFrameTypeMissing","rootFrameTypeDenied","childLifecycleMissing","childLifecyclePrerender","childLifecycleCached","childLifecyclePendingDeletion","childLifecycleInvalid","childFrameTypeMissing","childFrameTypeDenied","rootFrameTypeOuterMost","rootFrameTypeSubFrame","rootFrameTypeFenced","rootFrameTypeInvalid","childFrameTypeOuterMost","childFrameTypeSubFrame","childFrameTypeFenced","childFrameTypeInvalid","frameTypeDenied","frameRootURLDenied","builtInRootURLDenied","tabSchemeDenied","rootFrameURLInvalid","childFrameURLInvalid","rootFrameUserinfoDenied","childFrameUserinfoDenied","rootFrameSchemeDenied", "rootFrameError", "builtInRootFrameError", "childSourceIdentityUnavailable","rootFrameOriginNotGranted","childFrameOriginNotGranted","rootTabOriginMismatch","frameChildURLDenied","frameRootMissing","inactiveRootParentDenied","frameParentDocumentMismatch","frameParentMissing","frameCycle","inventoryDrift"]);
  const INVENTORY_BOUNDS=Object.freeze(['setupFrames','perTabFrames','censusTotal','eligibleDocuments','orphanEvidence','inventoryBytes']);
  const validInventoryLimit=value=>Boolean(value&&Object.keys(value).sort().join()==='bound,count,limit'&&INVENTORY_BOUNDS.includes(value.bound)&&Number.isSafeInteger(value.count)&&value.count>=0&&value.count<=4294967295&&Number.isSafeInteger(value.limit)&&value.limit>0&&value.limit<=(value.bound==='inventoryBytes'?262144:4096)&&value.count>value.limit);
  const LIMIT = 1024 * 1024, MAX_NODES = 50000;
  let revision = 0;
  chrome.storage?.onChanged?.addListener(() => { revision++; });
  const fail = code => { const error = new Error("Setup metadata is unavailable"); error.code = code; throw error; };
  function canonical(value) {
    let nodes = 0;
    function visit(node, depth) {
      if (++nodes > MAX_NODES || depth > 20) fail("storageBoundExceeded");
      if (node === null || typeof node === "boolean" || typeof node === "string") return JSON.stringify(node);
      if (typeof node === "number" && Number.isFinite(node)) return JSON.stringify(node);
      if (Array.isArray(node)) return "[" + node.map(v => visit(v, depth + 1)).join(",") + "]";
      if (!node || typeof node !== "object") fail("storageUnavailable");
      return "{" + Object.keys(node).sort().map(k => JSON.stringify(k) + ":" + visit(node[k], depth + 1)).join(",") + "}";
    }
    const bytes = new TextEncoder().encode(visit(value, 0));
    if (bytes.length > LIMIT) fail("storageBoundExceeded");
    return bytes;
  }
  async function digest(value) {
    const bytes = canonical(value);
    const result = await crypto.subtle.digest("SHA-256", bytes);
    bytes.fill(0);
    return [...new Uint8Array(result)].map(v => v.toString(16).padStart(2, "0")).join("");
  }
  async function snapshot(state) {
    if (!/^[a-p]{32}$/.test(chrome.runtime.id) || !chrome.storage?.onChanged ||
        typeof chrome.storage.local.getBytesInUse !== "function") fail("storageUnavailable");
    const before = revision;
    const size = await chrome.storage.local.getBytesInUse(null);
    if (!Number.isSafeInteger(size) || size < 0 || size > LIMIT) fail("storageBoundExceeded");
    const first = await chrome.storage.local.get(null);
    const firstHash = await digest(first);
    const session = await chrome.storage.session.get(null);
    const second = await chrome.storage.local.get(null);
    const secondHash = await digest(second);
    if (before !== revision || firstHash !== secondHash) fail("storageChanged");
    let retainedUnknown = 0;
    for (const key of Object.keys(session)) if (key.startsWith("browserIntent:")) {
      const receipt = session[key.replace("browserIntent:", "browserReceipt:")];
      const disposition = receipt?.dispatchState ?? receipt?.error?.dispatchState;
      if (!receipt || !["notDispatched", "dispatched"].includes(disposition) || receipt.error?.dispatchState === "unknown") retainedUnknown++;
    }
    const current = state();
    if (![current.activeCommands, current.unknownAttempts, retainedUnknown].every(v => Number.isSafeInteger(v) && v >= 0 && v <= 4096)) fail("stateUnavailable");
    const version = chrome.runtime.getManifest().version;
    if (typeof version !== "string" || !/^\d+(?:\.\d+){0,3}$/.test(version)) fail("stateUnavailable");
    return {version: 1, extensionId: chrome.runtime.id, extensionVersion: version,
      storageSHA256: secondHash, storageScope: "extension-local-v1", storageStable: true,
      activeCommands: current.activeCommands, unknownAttempts: Math.max(current.unknownAttempts, retainedUnknown),
      mutationBusy: current.mutationBusy === true,
      lifecycleInhibited: current.lifecycleInhibited === true || session.mechanizeLifecycleInhibited === true || second.mechanizeRetirementV1 !== undefined,
      nativeConnected: current.nativeConnected === true, executorQualified: current.executorQualified === true,
      loadedDirectoryAvailable: false};
  }
  const validMissingReceiptSources=value=>Boolean(value&&Object.keys(value).sort().join()==='count,hashes,truncated,version'&&value.version===1&&Number.isInteger(value.count)&&value.count>0&&value.count<=200&&Array.isArray(value.hashes)&&value.hashes.length===Math.min(value.count,16)&&value.hashes.every(h=>typeof h==='string'&&/^[a-f0-9]{64}$/.test(h))&&new Set(value.hashes).size===value.hashes.length&&value.hashes.every((h,i)=>i===0||value.hashes[i-1]<h)&&value.truncated===(value.count>16));
  async function connectionDiagnostics(state) {
    const current = state();
    const phases = ["idle", "scope", "barriers", "journal", "inventory", "inspect", "prepare", "adopt", "commit"];
    const reasons = ["none", "portChanged", "deadline", "busy", "unknownReceipts", "privateProtection", "lifecycle", "scopeChanged", "journalChanged", "inventoryChanged", "storageFailure", "rendererUnavailable", "executorRefused", "injectionUnavailable", "restrictedBrowserPage", "packagedExecutorUnavailable", "documentChanged", "websitePermissionMissing", "extensionContextInvalidated", "restrictedFrame", "injectionArgumentsRejected", "executorEvaluationFailed"];
    if (!current || !phases.includes(current.phase) || !reasons.includes(current.reason) ||
        ![current.privatePending, current.lifecyclePending].every(v => typeof v === "boolean")) fail("stateUnavailable");
    let missingReceiptSources;
    if(current.missingReceiptSources!==null&&current.missingReceiptSources!==undefined){if(current.phase!=='inspect'||current.reason!=='unknownReceipts'||!validMissingReceiptSources(current.missingReceiptSources))fail('stateUnavailable');missingReceiptSources={...current.missingReceiptSources,hashes:[...current.missingReceiptSources.hashes]};}
    const local = await chrome.storage.local.get(["mechanizeProtectedOrigins", "mechanizeRetirementV1", "mechanizeReconnect", "lastGrant"]);
    const session = await chrome.storage.session.get(["mechanizeProtectedOrigins", "mechanizeLifecycleInhibited"]);
    // Only presence and a closed phase vocabulary leave this process. No origin,
    // record, document, receipt, fence, key, digest or arbitrary error text.
    const protectedState = value => value !== undefined && (!Array.isArray(value) || value.length !== 0);
    const journal = local.mechanizeReconnect;
    const sameFence = (a,b) => a && b && ["brokerEpoch", "channelEpoch", "scopeHash"].every(key => typeof a[key] === "string" && a[key] !== "" && a[key] === b[key]);
    const old = sameFence(journal?.oldFence, local.lastGrant), next = sameFence(journal?.newFence, local.lastGrant);
    return {version: 3, phase: current.phase, reason: current.reason,...(missingReceiptSources?{missingReceiptSources}:{}),...(current.reason==='inventoryChanged'&&INVENTORY_REASONS.includes(current.inventoryReason)?{inventoryReason:current.inventoryReason}:{}),
      ...(current.reason==='inventoryChanged'&&validInventoryLimit(current.inventoryLimit)?{inventoryLimit:{...current.inventoryLimit}}:{}),
      credentialProtection: current.privatePending || protectedState(local.mechanizeProtectedOrigins) || protectedState(session.mechanizeProtectedOrigins),
      lifecyclePending: current.lifecyclePending || session.mechanizeLifecycleInhibited !== undefined && session.mechanizeLifecycleInhibited !== false,
      retirementPending: local.mechanizeRetirementV1 !== undefined,
      reconnectJournal: journal === undefined ? "absent" : journal?.phase === "adopted" ? "adopted" : journal?.phase === "pending" ? "pending" : "unrecognized",
      journalVersion: journal === undefined ? 0 : [1,2,3,4,5,6].includes(journal?.version) ? journal.version : -1,
      grantRelation: journal === undefined ? "none" : !local.lastGrant ? "unavailable" : old && next ? "both" : old ? "old" : next ? "new" : "neither"};
  }
  function installLocal(state, diagnostics) {
    chrome.runtime.onMessage.addListener((message, sender, reply) => {
      if (!["setupMetadataLocal", "connectionDiagnosticsLocal"].includes(message?.type) || Object.keys(message).length !== 1 || sender?.id !== chrome.runtime.id ||
          sender.url !== chrome.runtime.getURL("options.html") || sender.origin !== chrome.runtime.getURL("").replace(/\/$/, "") ||
          sender.frameId !== 0 || !Number.isInteger(sender.tab?.id) || sender.tab.id < 0) return;
      if (message.type === "connectionDiagnosticsLocal") {
        if (typeof diagnostics !== "function") return;
        connectionDiagnostics(diagnostics).then(value => reply({diagnostics: value})).catch(() => reply({error: "connectionDiagnosticsUnavailable"}));
        return true;
      }
      snapshot(state).then(value => reply({metadata: value})).catch(() => reply({error: "setupMetadataUnavailable"}));
      return true;
    });
  }
  async function respond(command, fence, state) {
    const keys = ["type", "requestId", "nonce", "brokerEpoch", "channelEpoch", "scopeHash", "deadlineUnixMs"];
    if (!command || Object.keys(command).sort().join(",") !== keys.sort().join(",") || command.type !== "setupMetadata" ||
        ![command.requestId, command.nonce].every(v => typeof v === "string" && /^[a-f0-9]{64}$/.test(v)) ||
        !fence || ["brokerEpoch", "channelEpoch", "scopeHash"].some(k => command[k] !== fence[k]) ||
        !Number.isSafeInteger(command.deadlineUnixMs) || command.deadlineUnixMs <= Date.now() || command.deadlineUnixMs > Date.now() + 10000) fail("setupMetadataDenied");
    const metadata = await snapshot(state);
    if (command.deadlineUnixMs <= Date.now()) fail("setupMetadataDenied");
    return {type: "setupMetadata", requestId: command.requestId, nonce: command.nonce,
      brokerEpoch: command.brokerEpoch, channelEpoch: command.channelEpoch, scopeHash: command.scopeHash, metadata};
  }
  return Object.freeze({snapshot, installLocal, respond, INVENTORY_REASONS, validInventoryLimit});
})();
