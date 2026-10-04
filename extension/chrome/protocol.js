// Packaged code only. Neither page code nor caller-provided JavaScript is evaluated.
globalThis.MechanizeProtocol = (() => {
  const MAX_BYTES = 256 * 1024;
  const mutations = new Set(["element.press", "element.fill", "element.select", "element.check", "element.uncheck", "browser.navigate", "browser.activate"]);
  const actions = new Set(["observe", "resolve", "read", "receipt.query", "executor.quiesce", "executor.validate", "executor.acquire", "executor.retire", "record.start", "record.pause", "record.stop", "record.events", ...mutations]);
  function error(code, message, state = "notDispatched") {
    return {code, message, stage: "browser", dispatchState: state, effectState: state === "unknown" ? "unknown" : "none"};
  }
  function validate(command, executorInternal = false) {
    if (!command || typeof command !== "object" || Array.isArray(command)) throw error("invalidRequest", "Expected a typed command");
    if (new TextEncoder().encode(JSON.stringify(command)).length > MAX_BYTES) throw error("frameTooLarge", "Application frame exceeds 256 KiB");
    const keys = new Set(["type", "requestId", "action", "identity", "brokerEpoch", "channelEpoch", "attemptId", "scopeHash", "deadlineUnixMs", "locator", "args", "controlLease", "fingerprintVersion", "fingerprintSHA256"]);
    if (Object.keys(command).some(k => !keys.has(k))) throw error("invalidRequest", "Unknown command field");
    if (!actions.has(command.action) && !(executorInternal === true && command.action === "executor.receipts")) throw error("unsupportedAction", "Action is not supported by the DOM transport");
    if (typeof command.requestId !== "string" || !command.requestId || command.requestId.length > 128) throw error("invalidRequest", "Bounded requestId required");
    if (command.controlLease !== undefined && (!command.controlLease || Object.keys(command.controlLease).some(k => !["id", "generation"].includes(k)) || typeof command.controlLease.id !== "string" || !command.controlLease.id || command.controlLease.id.length > 128 || !Number.isSafeInteger(command.controlLease.generation) || command.controlLease.generation < 1)) throw error("invalidLease", "Exact bounded renderer authority required");
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
  return {MAX_BYTES, mutations, actions, error, validate};
})();
if (typeof module !== "undefined") module.exports = globalThis.MechanizeProtocol;
