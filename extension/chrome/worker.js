import "./protocol.js";
import "./browser.js";
import "./retirement.js";
const retirementJournal = MechanizeRetirement.create(chrome.storage.local);
let port = null, grant = null, mutationBusy = false, lifecycleGuardId = null;
const requests = new Set();
const documents = new Map();
const documentFingerprintVersions = new Map();
const unknownAttempts = new Set();
async function inventory(enrollment) {
  const result = [];
  for (const tab of await chrome.tabs.query({})) {
    if (!allowedOrigin(tab.url, enrollment)) continue;
    for (const frame of await chrome.webNavigation.getAllFrames({tabId: tab.id}) || []) {
      if (!allowedOrigin(frame.url, enrollment) || !frame.documentId) continue;
      result.push({profileChannel: enrollment.profileChannel, browserInstance: enrollment.browserInstance, tabId: tab.id, frameId: frame.frameId, documentId: frame.documentId, documentGeneration: documents.get(`${tab.id}:${frame.documentId}`)?.documentGeneration || 1, mutationFingerprintVersion: documentFingerprintVersions.get(`${tab.id}:${frame.documentId}`) || 1, origin: new URL(frame.url).origin, title: (tab.title || "").slice(0, 256), titleTruncated: (tab.title || "").length > 256});
      if (result.length >= 200) return {documents: result, truncated: true};
    }
  }
  return {documents: result, truncated: false};
}
const allowedOrigin = (url, config) => { try { return config.origins.includes(new URL(url).origin); } catch { return false; } };
async function config() {
  const {enrollment} = await chrome.storage.local.get("enrollment");
  if (!enrollment?.profileChannel || !enrollment?.browserInstance || !Array.isArray(enrollment.origins)) throw MechanizeProtocol.error("notEnrolled", "Enroll this browser profile in extension options");
  return enrollment;
}
function send(value) {
  if (!port) return;
  if (new TextEncoder().encode(JSON.stringify(value)).length > MechanizeProtocol.MAX_BYTES) value = {requestId: value.requestId, error: MechanizeProtocol.error("frameTooLarge", "Result exceeds 256 KiB; request a smaller snapshot")};
  port.postMessage(value);
}
async function attach(command, enrollment) {
  const tab = await chrome.tabs.get(command.identity.tabId);
  if (!allowedOrigin(tab.url, enrollment)) throw MechanizeProtocol.error("originDenied", "Top-level tab origin is not enrolled");
  const frames = await chrome.webNavigation.getAllFrames({tabId: tab.id});
  const frame = frames.find(f => f.frameId === command.identity.frameId && f.documentId === command.identity.documentId);
  if (!frame || !allowedOrigin(frame.url, enrollment)) throw MechanizeProtocol.error("documentDenied", "Frame document/origin unavailable or not enrolled");
  const key = `${tab.id}:${frame.documentId}`;
  if (!documents.has(key)) {
    await chrome.scripting.executeScript({target: {tabId: tab.id, documentIds: [frame.documentId]}, world: "ISOLATED", files: ["protocol.js", "fingerprint.js", "dom.js", "recorder.js", "content.js"]});
    const bound = await chrome.tabs.sendMessage(tab.id, {type: "bind", binding: {identity: command.identity, brokerEpoch: grant.brokerEpoch, channelEpoch: grant.channelEpoch, scopeHash: grant.scopeHash, leaseRequired: grant.leaseRequired === true, mutationFingerprintVersion: grant.mutationFingerprintVersion || 1}}, {documentId: frame.documentId});
    if (bound?.error || !bound?.identity || bound.identity.documentId !== frame.documentId || (grant.mutationFingerprintVersion === 2 && bound.mutationFingerprintVersion !== 2)) throw MechanizeProtocol.error("executorBindingFailed", "Exact negotiated document executor required");
    documents.set(key, bound.identity);
    documentFingerprintVersions.set(key, bound.mutationFingerprintVersion || 1);
  }
  return frame;
}
function validateRetirementCommand(command) {
  const keys = ["requestId", "action", "identity", "brokerEpoch", "channelEpoch", "scopeHash", "deadlineUnixMs", "args"];
  const id = command.identity;
  if (!command || Object.keys(command).some(k => !keys.includes(k)) || keys.some(k => !Object.hasOwn(command, k)) ||
      typeof command.requestId !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(command.requestId) ||
      !Number.isSafeInteger(command.deadlineUnixMs) || command.deadlineUnixMs <= Date.now() ||
      new TextEncoder().encode(JSON.stringify(command)).length > MechanizeProtocol.MAX_BYTES ||
      !id || Object.keys(id).sort().join(",") !== "browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId" ||
      id.tabId !== 0 || id.frameId !== 0 || id.documentId !== "" || id.documentGeneration !== 0)
    throw MechanizeProtocol.error("lifecycleDenied", "Closed channel journal command required");
}
let lifecycleLane = Promise.resolve();
async function receive(command) {
  if (command?.type !== "lifecycle") return receiveCommand(command);
  const operation = lifecycleLane.then(() => receiveCommand(command));
  lifecycleLane = operation.catch(() => {});
  return operation;
}
async function receiveCommand(command) {
  if (command?.type === "enrolled" || command?.type === "processQualified") {
    grant = null;
    if (lifecycleGuardId) { send({type: "attention", error: MechanizeProtocol.error("lifecycleInhibited", "Retained lifecycle cannot be replaced by enrollment")}); return; }
    if (!["brokerEpoch", "channelEpoch", "scopeHash"].every(k => typeof command[k] === "string" && command[k])) return;
    try {
      // A reconnection may only reuse the acknowledged channel fence. A new
      // epoch requires broker-driven quiescence/reconciliation.
      const {lastGrant} = await chrome.storage.local.get("lastGrant");
      if (lastGrant && ["brokerEpoch", "channelEpoch", "scopeHash"].some(k => lastGrant[k] !== command[k])) {
        send({type: "attention", error: MechanizeProtocol.error("storedFenceMismatch", "Stored channel fence requires quiescence and receipt reconciliation")});
        return;
      }
      const mutationFingerprintVersion = command.mutationFingerprintVersion === undefined ? 1 : command.mutationFingerprintVersion;
      if (![1,2].includes(mutationFingerprintVersion)) { send({type:"attention", error:MechanizeProtocol.error("executorBindingFailed", "Supported mutation fingerprint negotiation required")}); return; }
      const candidate = {mutationFingerprintVersion, brokerEpoch: command.brokerEpoch, channelEpoch: command.channelEpoch, scopeHash: command.scopeHash};
      if (command.type === "processQualified") {
        const trustScope = command.trustScope === undefined || command.trustScope === "" ? "profile" : command.trustScope;
        const scopeQualified = trustScope === "desktop" ? command.scopeQualified === true && command.profileQualified === false :
          trustScope === "profile" && command.profileQualified === true && (command.scopeQualified === undefined || command.scopeQualified === true);
        if (!scopeQualified || command.executorQualified || typeof command.executorChallenge !== "string" || !command.executorChallenge || mutationBusy || unknownAttempts.size) {
          send({type: "attention", error: MechanizeProtocol.error("executorNotQuiescent", "Qualified browser scope and idle reconciled executor required")}); return;
        }
        candidate.trustScope = trustScope;
        candidate.scopeQualified = true;
        candidate.profileQualified = trustScope === "profile";
        const snapshot = await inventory(await config());
        if (snapshot.truncated) { send({type: "attention", error: MechanizeProtocol.error("inventoryIncomplete", "Complete root inventory required")}); return; }
        for (const identity of snapshot.documents.filter(d => d.frameId === 0)) {
          try {
            await chrome.scripting.executeScript({target: {tabId: identity.tabId, documentIds: [identity.documentId]}, world: "ISOLATED", files: ["protocol.js", "fingerprint.js", "dom.js", "recorder.js", "content.js"]});
          } catch { send({type: "attention", error: MechanizeProtocol.error("executorInjectionFailed", "Packaged executor injection could not be confirmed")}); return; }
          let bound;
          try {
            bound = await chrome.tabs.sendMessage(identity.tabId, {type: "bind", binding: {identity, ...candidate, leaseRequired: true}}, {documentId: identity.documentId});
          } catch { send({type: "attention", error: MechanizeProtocol.error("executorBindingFailed", "Exact document executor binding could not be confirmed")}); return; }
          if (bound?.error || !bound?.identity || bound.identity.documentId !== identity.documentId || (mutationFingerprintVersion === 2 && bound.mutationFingerprintVersion !== 2)) {
            send({type: "attention", error: MechanizeProtocol.error("executorBindingFailed", "Exact document executor binding could not be confirmed")}); return;
          }
          documents.set(`${identity.tabId}:${identity.documentId}`, bound.identity);
          documentFingerprintVersions.set(`${identity.tabId}:${identity.documentId}`, bound.mutationFingerprintVersion || 1);
        }
      }
      candidate.leaseRequired = command.type === "processQualified";
      const snapshot = await inventory(await config());
      if (snapshot.truncated) { send({type: "attention", error: MechanizeProtocol.error("inventoryIncomplete", "Complete root inventory required")}); return; }
      await chrome.storage.local.set({lastGrant: candidate});
      grant = candidate;
      // Complete awaited setup before acknowledging renderer qualification. An
      // empty inventory remains explicitly empty; it proves no available tab.
      if (command.type === "processQualified") send({type: "executorPrepared", executorChallenge: command.executorChallenge, mutationFingerprintVersion});
      send({type: "documents", ...snapshot, capabilities: [...MechanizeProtocol.actions], inputSemantics: "DOM activation; isTrusted=false", unsupported: ["trusted input", "file selection", "custom editors", "closed shadow roots", "network response bodies", "capture", "tab open/close", "production signed-parent enrollment"]});
    } catch {
      grant = null;
      send({type: "attention", error: MechanizeProtocol.error("inventoryUnavailable", "Enrollment storage or document inventory unavailable")});
    }
    return;
  }
  try {
    const lifecycle = command?.type === "lifecycle";
    let guardId;
    if (lifecycle) {
      guardId = command.lifecycleGuardId;
      if (typeof guardId !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(guardId) ||
          !["executor.retire", "executor.quiesce", "record.stop", "executor.receipts", "retirement.intend", "retirement.prepare", "retirement.status"].includes(command.action))
        throw MechanizeProtocol.error("lifecycleDenied", "Closed lifecycle receipt operation required");
      const {type, lifecycleGuardId: omittedGuard, ...payload} = command;
      command = payload;
    }
    const journal = lifecycle && command.action.startsWith("retirement.");
    if (journal) validateRetirementCommand(command); else MechanizeProtocol.validate(command, lifecycle);
    const enrollment = await config();
    if (!grant || command.identity.profileChannel !== enrollment.profileChannel || command.identity.browserInstance !== enrollment.browserInstance || ["brokerEpoch", "channelEpoch", "scopeHash"].some(k => command[k] !== grant[k])) throw MechanizeProtocol.error("notEnrolled", "Authenticated broker channel/scope does not match");
    const admittedPort = port, admittedGrant = grant;
    const requireCurrentLifecycle = () => {
      if (!lifecycle) return;
      if (!admittedPort || port !== admittedPort || grant !== admittedGrant ||
          command.deadlineUnixMs <= Date.now())
        throw MechanizeProtocol.error("lifecycleDenied", "Original lifecycle connection or deadline no longer valid");
    };
    const handoff = journal && command.action === "retirement.status" && lifecycleGuardId && lifecycleGuardId !== guardId;
    if (lifecycle) {
      if (mutationBusy || unknownAttempts.size || (lifecycleGuardId && lifecycleGuardId !== guardId && !handoff))
        throw MechanizeProtocol.error("lifecycleDenied", "Idle exact lifecycle guard required");
      if (!journal && !documents.has(`${command.identity.tabId}:${command.identity.documentId}`))
        throw MechanizeProtocol.error("lifecycleDenied", "Existing bound document required");
      // Persist inhibition before forwarding any lifecycle command. Restart
      // recovery must explicitly reconcile it; ordinary enrollment cannot clear it.
      if (!handoff) lifecycleGuardId = guardId;
      await chrome.storage.session.set({mechanizeLifecycleInhibited: true});
      requireCurrentLifecycle();
    } else if (lifecycleGuardId) {
      throw MechanizeProtocol.error("lifecycleInhibited", "Channel is retained for lifecycle reconciliation");
    }
    if (requests.has(command.requestId)) throw MechanizeProtocol.error("requestReplay", "Request IDs are single-use; query the original attempt receipt");
    if (requests.size >= 4096) throw MechanizeProtocol.error("requestCapacity", "Channel request quota exhausted; explicitly reconcile before replacing channel");
    requests.add(command.requestId);
    if (journal) {
      const input = command.args;
      const channel = {profileChannel: enrollment.profileChannel, browserInstance: enrollment.browserInstance};
      let result;
      if (command.action === "retirement.status") {
        if (!input || Object.keys(input).sort().join(",") !== "browserInstance,profileChannel" || input.profileChannel !== channel.profileChannel || input.browserInstance !== channel.browserInstance) throw MechanizeProtocol.error("lifecycleDenied", "Exact retirement channel required");
        result = await retirementJournal.status(channel);
        requireCurrentLifecycle();
        // The private lane has drained all predecessor lifecycle operations.
        // Transfer only inspection authority; input stays inhibited.
        if (handoff && (result.confirmed || result.reason === "retirementNotFound")) lifecycleGuardId = guardId;
      } else {
        if (!input || input.channel?.profileChannel !== channel.profileChannel || input.channel?.browserInstance !== channel.browserInstance ||
            ["brokerEpoch", "channelEpoch", "scopeHash"].some(k => input.oldFence?.[k] !== grant[k]))
          throw MechanizeProtocol.error("lifecycleDenied", "Exact predecessor journal fence required");
        result = command.action === "retirement.intend" ? await retirementJournal.intend(input) : await retirementJournal.prepare(input);
      }
      requireCurrentLifecycle();
      send({requestId: command.requestId, identity: command.identity, retirement: result});
      return;
    }
    const mutation = MechanizeProtocol.mutations.has(command.action);
    if (mutation && (command.fingerprintVersion || 1) !== (grant.mutationFingerprintVersion || 1)) throw MechanizeProtocol.error("fingerprintMismatch", "Mutation version differs from negotiated worker");
    if (grant.leaseRequired && mutation && !command.controlLease) throw MechanizeProtocol.error("rendererAuthorityRequired", "Production mutation requires an admitted renderer lease");
    if (["executor.acquire", "executor.retire"].includes(command.action) && unknownAttempts.size) throw MechanizeProtocol.error("unknownEffect", "Unresolved mutation prevents renderer lease transitions", "unknown");
    if (mutation && unknownAttempts.size) throw MechanizeProtocol.error("unknownEffect", "A previous receipt was lost; query and reconcile its attempt before another mutation", "unknown");
    if (mutationBusy) throw MechanizeProtocol.error("mutationBusy", "One browser mutation at a time; wait for its receipt");
    if (mutation) mutationBusy = true;
    try {
      if (command.action === "receipt.query") {
        const receipt = await MechanizeBrowser.query(command);
        if (receipt) { if (receipt.dispatchState !== "unknown" && receipt.error?.dispatchState !== "unknown") unknownAttempts.delete(command.attemptId); send(receipt); return; }
      }
      if (!lifecycle) await attach(command, enrollment);
      if (command.action === "record.start") {
        if (!chrome.action) throw MechanizeProtocol.error("recordingIndicatorUnavailable", "Visible recording badge is required before capture starts");
        await chrome.action.setBadgeText({tabId: command.identity.tabId, text: "REC"});
        await chrome.action.setBadgeBackgroundColor({tabId: command.identity.tabId, color: "#B42318"});
      }
      const result = command.action.startsWith("browser.") ? await MechanizeBrowser.execute(command, enrollment) : await chrome.tabs.sendMessage(command.identity.tabId, command, {documentId: command.identity.documentId});
      if (result.recordingState && chrome.action) { await chrome.action.setBadgeText({tabId: command.identity.tabId, text: result.recordingState === "recording" ? "REC" : result.recordingState === "paused" ? "PAUSE" : ""}); await chrome.action.setBadgeBackgroundColor({tabId: command.identity.tabId, color: "#B42318"}); }
      if (result.identity) documents.set(`${command.identity.tabId}:${command.identity.documentId}`, result.identity);
      if (command.action === "receipt.query" && result.receiptAvailable !== false && result.dispatchState !== "unknown" && result.error?.dispatchState !== "unknown") unknownAttempts.delete(command.attemptId);
      if (mutation && result.error?.dispatchState === "unknown") unknownAttempts.add(command.attemptId);
      send(result);
    } catch (error) {
      if (error.code) throw error;
      if (mutation) unknownAttempts.add(command.attemptId);
      send({requestId: command.requestId, attemptId: command.attemptId, error: MechanizeProtocol.error("receiptLost", "Renderer receipt unavailable; query original document receipt, then reconcile; never replay", "unknown")});
    } finally { if (mutation) mutationBusy = false; }
  } catch (error) { send({requestId: command?.requestId, attemptId: command?.attemptId, identity: command?.identity, error: error.code ? error : MechanizeProtocol.error("transportFailure", "Browser command unavailable")}); }
}
async function connect() {
  if (port) return;
  try {
    const enrollment = await config();
    const retained = await chrome.storage.local.get(MechanizeRetirement.KEY);
    if (retained[MechanizeRetirement.KEY] !== undefined) {
      lifecycleGuardId = "restart-reconciliation-required";
      throw MechanizeProtocol.error("lifecycleInhibited", "Durable retirement requires explicit restart reconciliation");
    }
    const session = await chrome.storage.session.get(null);
    if (session.mechanizeLifecycleInhibited) {
      lifecycleGuardId = "restart-reconciliation-required";
      throw MechanizeProtocol.error("lifecycleInhibited", "Retained lifecycle requires explicit restart reconciliation");
    }
    for (const key of Object.keys(session)) if (key.startsWith("browserIntent:") && (!session[key.replace("browserIntent:", "browserReceipt:")] || session[key.replace("browserIntent:", "browserReceipt:")].error?.dispatchState === "unknown")) unknownAttempts.add(key.slice("browserIntent:".length));
    port = chrome.runtime.connectNative("com.viant.mechanize");
    const connectedPort = port;
    port.onMessage.addListener(command => { if (port === connectedPort) receive(command); });
    port.onDisconnect.addListener(() => {
      // Reading lastError consumes Chrome's transport diagnostic; only a public
      // disconnected flag is sent to extension UI, never native-host output.
      void chrome.runtime.lastError;
      if (port !== connectedPort) return;
      port = null; grant = null;
      chrome.runtime.sendMessage({type: "nativeConnectionStatus", connected: false}).catch(() => {});
    });
    const {lastGrant} = await chrome.storage.local.get("lastGrant");
    send({type: "hello", protocolVersion: 1, extensionVersion: chrome.runtime.getManifest().version, profileChannel: enrollment.profileChannel, browserInstance: enrollment.browserInstance, lastGrant, documents: [...documents.values()]});
  } catch {
    const failedPort = port;
    port = null; grant = null;
    try { failedPort?.disconnect(); } catch {}
    // Remain disconnected until explicit enrollment/connect.
  }
}
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  // Only the extension options page can request connection. No page bridge.
  // Chrome includes sender.tab for an options_page opened in a normal tab.
  // The authenticated top-level frame and exact extension URL/origin matter.
  if (sender?.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL("options.html") ||
      sender.origin !== chrome.runtime.getURL("").replace(/\/$/, "") || sender.frameId !== 0 ||
      !Number.isInteger(sender.tab?.id) || sender.tab.id < 0 || message?.type !== "connect") return;
  connect().then(() => reply({connected: Boolean(port)}));
  return true;
});
chrome.webNavigation.onCommitted.addListener(event => {
  for (const [key, identity] of documents) if (identity.tabId === event.tabId && identity.frameId === event.frameId && identity.documentId !== event.documentId) { documents.delete(key); documentFingerprintVersions.delete(key); }
  if (grant) config().then(inventory).then(result => send({type: "documents", ...result})).catch(() => {});
});
const refreshInventory = () => { if (grant) config().then(inventory).then(result => send({type: "documents", ...result})).catch(() => {}); };
for (const event of [chrome.webNavigation.onHistoryStateUpdated, chrome.webNavigation.onReferenceFragmentUpdated, chrome.webNavigation.onCompleted, chrome.tabs.onUpdated, chrome.tabs.onActivated]) event?.addListener(refreshInventory);
chrome.tabs.onRemoved.addListener(tabId => { for (const [key, identity] of documents) if (identity.tabId === tabId) { documents.delete(key); documentFingerprintVersions.delete(key); } refreshInventory(); });
connect();
