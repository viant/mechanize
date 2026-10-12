// Packaged code only. Neither page code nor caller-provided JavaScript is evaluated.
globalThis.MechanizeProtocol = (() => {
  const MAX_BYTES = 256 * 1024;
  const mutations = new Set(["element.press", "element.fill", "element.select", "element.check", "element.uncheck", "browser.navigate", "browser.activate"]);
  const actions = new Set(["observe", "resolve", "read", "receipt.query", "executor.quiesce", "executor.validate", "executor.acquire", "executor.retire", "record.start", "record.pause", "record.stop", "record.events", ...mutations]);
  function error(code, message, state = "notDispatched") {
    return {code, message, stage: "browser", dispatchState: state, effectState: state === "unknown" ? "unknown" : "none"};
  }
  // Website scope never includes browser internals, files or embedded credentials.
  // This local preference does not replace the broker's independently bound scope.
  function websiteScopeValid(enrollment) {
    if (!enrollment || !Array.isArray(enrollment.origins) ||
        enrollment.allWebsites !== undefined && typeof enrollment.allWebsites !== "boolean") return false;
    if (enrollment.allWebsites === true) return enrollment.origins.length === 0;
    if (!enrollment.origins.length || enrollment.origins.length > 20 || new Set(enrollment.origins).size !== enrollment.origins.length) return false;
    try { return enrollment.origins.every(origin => {
      if (typeof origin !== "string" || origin.length > 512) return false;
      const url = new URL(origin);
      return url.origin === origin && !url.username && !url.password &&
        (url.protocol === "https:" || url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname));
    }); } catch { return false; }
  }
  function websiteAllowed(rawURL, enrollment) {
    if (!websiteScopeValid(enrollment)) return false;
    try {
      const url = new URL(rawURL);
      if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return false;
      return enrollment.allWebsites === true || enrollment.origins.includes(url.origin);
    } catch { return false; }
  }
  function validate(command, executorInternal = false) {
    if (!command || typeof command !== "object" || Array.isArray(command)) throw error("invalidRequest", "Expected a typed command");
    if (new TextEncoder().encode(JSON.stringify(command)).length > MAX_BYTES) throw error("frameTooLarge", "Application frame exceeds 256 KiB");
    const keys = new Set(["type", "requestId", "action", "identity", "brokerEpoch", "channelEpoch", "attemptId", "scopeHash", "deadlineUnixMs", "locator", "args", "controlLease", "fingerprintVersion", "fingerprintSHA256", "publicRead"]);
    if (Object.keys(command).some(k => !keys.has(k))) throw error("invalidRequest", "Unknown command field");
    if (!actions.has(command.action) && !(executorInternal === true && command.action === "executor.receipts")) throw error("unsupportedAction", "Action is not supported by the DOM transport");
    if(Object.hasOwn(command,'publicRead')&&(command.publicRead!==true||!['observe','read','resolve','executor.validate'].includes(command.action)||command.controlLease!==undefined||command.attemptId!==undefined||command.fingerprintVersion!==undefined||command.fingerprintSHA256!==undefined))throw error('invalidRequest','Explicit public read accepts only unleased read commands');
    if (typeof command.requestId !== "string" || !command.requestId || command.requestId.length > 128) throw error("invalidRequest", "Bounded requestId required");
    if (command.controlLease !== undefined && (!command.controlLease || Object.keys(command.controlLease).some(k => !["id", "generation"].includes(k)) || typeof command.controlLease.id !== "string" || !command.controlLease.id || command.controlLease.id.length > 128 || !Number.isSafeInteger(command.controlLease.generation) || command.controlLease.generation < 1)) throw error("invalidLease", "Exact bounded renderer authority required");
    if(command.locator && (Object.hasOwn(command.locator,'index')||Object.hasOwn(command.locator,'order')) && (!Number.isInteger(command.locator.index)||command.locator.index<0||command.locator.index>999||command.locator.order!=='document'||command.locator.exact!==true))throw error('invalidLocator','Indexed locator requires bounded document order and exact matching');
    const i = command.identity;
    if (!i || ["profileChannel", "browserInstance", "documentId"].some(k => typeof i[k] !== "string" || !i[k]) || !Number.isInteger(i.tabId) || !Number.isInteger(i.frameId) || !Number.isSafeInteger(i.documentGeneration) || i.documentGeneration < 1) throw error("invalidIdentity", "Full tab/frame/document/generation identity required");
    if (["brokerEpoch", "channelEpoch", "scopeHash"].some(k => typeof command[k] !== "string" || !command[k])) throw error("invalidFence", "Broker, channel and scope fences required");
    if (mutations.has(command.action) && (typeof command.attemptId !== "string" || !command.attemptId)) throw error("invalidRequest", "Mutation attemptId required");
    if (!Number.isSafeInteger(command.deadlineUnixMs) || command.deadlineUnixMs <= Date.now() || command.deadlineUnixMs > Date.now() + 30000) throw error("dispatchExpired", "Dispatch deadline expired or exceeds 30 seconds");
    if (command.fingerprintVersion !== undefined || command.fingerprintSHA256 !== undefined) {
      if (!mutations.has(command.action) || command.fingerprintVersion !== 2 || typeof command.fingerprintSHA256 !== "string" || !/^[0-9a-f]{64}$/.test(command.fingerprintSHA256)) throw error("fingerprintMismatch", "Explicit v2 mutation fingerprint required");
    }
    if (command.action === "executor.receipts") {
      const args = command.args;
      if (!args || typeof args !== "object" || Array.isArray(args) || Object.keys(args).some(k => !["offset", "limit", "expectedRevision"].includes(k)) ||
          !Number.isSafeInteger(args.offset) || args.offset < 0 || args.offset > 512 || !Number.isInteger(args.limit) || args.limit < 1 || args.limit > 64 ||
          args.expectedRevision !== undefined && (!Number.isSafeInteger(args.expectedRevision) || args.expectedRevision < 0) || args.offset > 0 && args.expectedRevision === undefined ||
          command.locator !== undefined || command.attemptId !== undefined || command.controlLease !== undefined) throw error("invalidReceiptExport", "Closed receipt cursor, limit 1–64 and exact revision for later pages required");
    }
    return command;
  }
  return {MAX_BYTES, mutations, actions, error, validate, websiteScopeValid, websiteAllowed};
})();
if (typeof module !== "undefined") module.exports = globalThis.MechanizeProtocol;
