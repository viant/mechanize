// Browser API mutation calls execute once. Navigation timers/promises only observe.
globalThis.MechanizeBrowser = (() => {
  const originAllowed = (url, enrollment) => { try { return enrollment.origins.includes(new URL(url).origin); } catch { return false; } };
  async function query(command) {
    const saved = await chrome.storage.session.get(["browserReceipt:" + command.attemptId, "browserIntent:" + command.attemptId]);
    const receipt = saved["browserReceipt:" + command.attemptId], intent = saved["browserIntent:" + command.attemptId];
    if (!intent) return null;
    if (["profileChannel", "browserInstance", "tabId", "frameId", "documentId"].some(key => intent.identity[key] !== command.identity[key]) || ["brokerEpoch", "channelEpoch", "scopeHash"].some(key => intent[key] !== command[key])) throw MechanizeProtocol.error("staleIdentity", "Browser receipt belongs to another document/channel");
    return receipt ? {...receipt, requestId: command.requestId} : {requestId: command.requestId, attemptId: command.attemptId, identity: command.identity, receiptAvailable: false, dispatchState: "unknown", effectState: "unknown"};
  }
  async function execute(command, enrollment) {
    if (command.identity.frameId !== 0) throw MechanizeProtocol.error("unsupportedScope", "Browser mutations require a root frame");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify([command.action, command.identity, command.args])));
    const fingerprint = [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, "0")).join("");
    const previous = await query(command);
    if (previous) {
      const saved = await chrome.storage.session.get("browserIntent:" + command.attemptId);
      if (saved["browserIntent:" + command.attemptId].fingerprint !== fingerprint) throw MechanizeProtocol.error("attemptConflict", "Browser attempt was already bound to a different command");
      return previous;
    }
    if (Object.keys(command.args || {}).some(key => key !== "url")) throw MechanizeProtocol.error("invalidRequest", "Unknown browser argument");
    let destination;
    if (command.action === "browser.navigate") {
      if (typeof command.args?.url !== "string" || command.args.url.length > 8192) throw MechanizeProtocol.error("invalidRequest", "Bounded destination URL required");
      destination = new URL(command.args.url);
      if (destination.username || destination.password || !originAllowed(destination.href, enrollment) || [...destination.searchParams.keys()].some(key => /password|token|secret|credential/i.test(key))) throw MechanizeProtocol.error("originDenied", "Destination must be enrolled with no embedded credentials");
    }
    const validated = await chrome.tabs.sendMessage(command.identity.tabId, {...command, action: "executor.validate", attemptId: undefined, args: undefined}, {documentId: command.identity.documentId});
    if (validated.error || !validated.validated) return {...validated, requestId: command.requestId, attemptId: command.attemptId};
    const session = await chrome.storage.session.get(null);
    if (Object.keys(session).some(key => key.startsWith("browserIntent:") && (!session[key.replace("browserIntent:", "browserReceipt:")] || session[key.replace("browserIntent:", "browserReceipt:")].error?.dispatchState === "unknown"))) throw MechanizeProtocol.error("unknownEffect", "A prior browser intent has no confirmed receipt; reconcile before another mutation", "unknown");
    if (Object.keys(session).filter(key => key.startsWith("browserIntent:")).length >= 512) throw MechanizeProtocol.error("receiptCapacity", "Browser receipt capacity exhausted; explicit reconciliation required");
    // No URL/value/credential is persisted. Missing receipt after this marker is unknown.
    await chrome.storage.session.set({["browserIntent:" + command.attemptId]: {identity: command.identity, brokerEpoch: command.brokerEpoch, channelEpoch: command.channelEpoch, scopeHash: command.scopeHash, fingerprint}});
    const frames = await chrome.webNavigation.getAllFrames({tabId: command.identity.tabId});
    const current = frames.find(frame => frame.frameId === 0 && frame.documentId === command.identity.documentId);
    if (!current || !originAllowed(current.url, enrollment)) throw MechanizeProtocol.error("staleIdentity", "Document changed before browser API dispatch");
    MechanizeProtocol.validate(command);
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
      const timer = setTimeout(() => finish({timeout: true}), Math.max(1, command.deadlineUnixMs - Date.now()));
      try {
        await chrome.tabs.update(command.identity.tabId, {url: destination.href});
        const event = await completion;
        const tab = await chrome.tabs.get(command.identity.tabId);
        const updatedFrames = await chrome.webNavigation.getAllFrames({tabId: tab.id});
        const root = updatedFrames.find(frame => frame.frameId === 0);
        const safe = root && originAllowed(root.url, enrollment) && originAllowed(tab.url, enrollment);
        receipt = {requestId: command.requestId, attemptId: command.attemptId, identity: command.identity, dispatchState: "dispatched", effectState: "unverified", ready: Boolean(safe && !event.failed && !event.timeout), inputSemantics: "Chrome navigation API; readiness is not a business outcome"};
        if (!safe) receipt.error = MechanizeProtocol.error("redirectOriginDenied", "Navigation redirected outside enrolled origins; reconcile", "unknown");
        else receipt.newDocument = {profileChannel: command.identity.profileChannel, browserInstance: command.identity.browserInstance, tabId: tab.id, frameId: 0, documentId: root.documentId, documentGeneration: 1, origin: new URL(root.url).origin, title: (tab.title || "").slice(0, 256), titleTruncated: (tab.title || "").length > 256};
      } finally { clearTimeout(timer); chrome.webNavigation.onCompleted.removeListener(completed); chrome.webNavigation.onErrorOccurred.removeListener(failed); }
    }
    await chrome.storage.session.set({["browserReceipt:" + command.attemptId]: receipt});
    return receipt;
  }
  return {execute, query};
})();
