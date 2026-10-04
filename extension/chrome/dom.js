globalThis.MechanizeDOM = (() => {
  const fail = (code, message) => { throw MechanizeProtocol.error(code, message); };
  const text = value => String(value || "").replace(/\s+/g, " ").trim().slice(0, 256);
  function secret(el) {
    return el.type === "password" || /password|secret|token|credit.?card|cc-number|cc-csc|one-time-code|api.?key|security.?code/i.test([el.id, el.name, el.autocomplete, el.getAttribute("aria-label"), el.getAttribute("placeholder"), el.getAttribute("title"), ...(el.labels ? [...el.labels].map(label => label.textContent) : [])].join(" ")) || Boolean(el.closest("[data-mechanize-secret]"));
  }
  function role(el) {
    const explicit = el.getAttribute("role");
    if (explicit) return explicit.split(" ")[0];
    const tag = el.tagName.toLowerCase();
    if (tag === "input") return {checkbox: "checkbox", radio: "radio", button: "button", submit: "button", range: "slider"}[el.type] || "textbox";
    return {button: "button", a: el.hasAttribute("href") ? "link" : "generic", textarea: "textbox", select: "combobox", img: "img", h1: "heading", h2: "heading"}[tag] || "generic";
  }
  function name(el, doc) {
    if (secret(el)) return "[redacted]";
    const ids = el.getAttribute("aria-labelledby");
    if (ids) return text(ids.split(/\s+/).map(id => { const label = doc.getElementById(id); return label && !secret(label) ? label.textContent : ""; }).join(" "));
    if (el.getAttribute("aria-label")) return text(el.getAttribute("aria-label"));
    if (el.labels?.length) return text([...el.labels].map(l => l.textContent).join(" "));
    if (["button", "link", "heading"].includes(role(el))) return text(el.textContent);
    return text(el.getAttribute("alt") || el.getAttribute("title"));
  }
  function visible(el) {
    const style = el.ownerDocument.defaultView.getComputedStyle(el);
    return !el.hidden && style.display !== "none" && style.visibility !== "hidden" && el.getClientRects().length > 0;
  }
  function walk(doc, max = 2000) {
    const nodes = [], queue = [], enqueue = children => {
      for (const child of children) {
        if (queue.length + nodes.length >= max + 1) { truncated = true; break; }
        queue.push(child);
      }
    };
    let truncated = false;
    enqueue(doc.children);
    while (queue.length && nodes.length < max) {
      const el = queue.shift();
      if (["SCRIPT", "STYLE", "NOSCRIPT"].includes(el.tagName)) continue;
      nodes.push(el);
      enqueue(el.children);
      if (el.shadowRoot) enqueue(el.shadowRoot.children);
    }
    return {nodes, complete: !truncated && queue.length === 0};
  }
  function resolve(doc, locator) {
    if (!locator || Object.keys(locator).some(k => !["strategy", "value", "name", "exact"].includes(k)) || typeof locator.value !== "string") fail("invalidLocator", "Closed locator with string value required");
    const allowed = ["id", "testId", "role", "label", "css"];
    if (!allowed.includes(locator.strategy)) fail("unsupportedSelector", "Supported: id, testId, role, label, css; frame scope is mandatory");
    const all = walk(doc);
    if (!all.complete) fail("coverageIncomplete", "Document traversal exceeded 2000 nodes; narrow the document scope");
    let matches;
    try { matches = all.nodes.filter(el => {
      const expected = locator.value;
      if (locator.strategy === "id") return el.id === expected;
      if (locator.strategy === "testId") return el.getAttribute("data-testid") === expected;
      if (locator.strategy === "css") return el.matches(expected);
      const n = name(el, doc), expectedName = locator.strategy === "role" ? locator.name : expected;
      return (locator.strategy !== "role" || role(el) === expected) && (expectedName === undefined || (locator.exact === false ? n.includes(expectedName) : n === expectedName));
    }); } catch { fail("invalidLocator", "CSS selector could not be parsed"); }
    if (!matches.length) fail("targetNotFound", "No matching element in the bound document");
    if (matches.length !== 1) fail("ambiguousTarget", `${matches.length} elements match; refine the locator`);
    return matches[0];
  }
  function snapshot(doc, args = {}) {
    const limit = Number.isInteger(args.limit) ? Math.max(1, Math.min(args.limit, 200)) : 100;
    const result = walk(doc), nodes = [];
    for (const el of result.nodes) {
      const r = role(el);
      if (r === "generic") continue;
      if (nodes.length >= limit) return {nodes, truncated: true, coverage: coverage()};
      nodes.push({role: r, name: name(el, doc), id: text(el.id), testId: text(el.getAttribute("data-testid")), visible: visible(el), enabled: !el.disabled && el.getAttribute("aria-disabled") !== "true", value: secret(el) ? "[redacted]" : ("value" in el ? text(el.value) : undefined)});
    }
    return {nodes, truncated: !result.complete, coverage: coverage()};
  }
  const coverage = () => ["DOM-derived roles/names, not Chrome AX", "Open shadow roots only; closed roots/canvas unavailable", "Only the explicitly bound frame", "DOM events are untrusted; business outcome requires broker verification"];
  function act(doc, action, locator, args = {}) {
    if (Object.keys(args).some(k => !["value", "limit", "attribute"].includes(k))) fail("invalidRequest", "Unknown action argument");
    if (action === "observe") return snapshot(doc, args);
    const el = resolve(doc, locator);
    if (action === "resolve") return {role: role(el), name: name(el, doc), visible: visible(el), enabled: !el.disabled};
    if (action === "read") {
      const attribute = args.attribute || "value";
      if (!["value", "text", "name"].includes(attribute)) fail("unsupportedAttribute", "Read supports value, text and name");
      return {value: secret(el) ? "[redacted]" : (attribute === "name" ? name(el, doc) : text(attribute === "text" ? el.textContent : el.value))};
    }
    if (!el.isConnected || !visible(el) || el.disabled || el.getAttribute("aria-disabled") === "true" || el.closest("[inert]")) fail("targetNotActionable", "Element must be connected, visible and enabled");
    if (el.type === "file" || el.hasAttribute("data-mechanize-user-activation")) fail("userActivationRequired", "Use a separately qualified native/protocol route; DOM events do not grant user activation");
    if (action === "element.press") el.click();
    else if (action === "element.check" || action === "element.uncheck") {
      if (el.type !== "checkbox") fail("unsupportedControl", "Checked-state operations require a native checkbox");
      if (el.checked !== (action === "element.check")) el.click();
    } else if (action === "element.fill" || action === "element.select") {
      if (typeof args.value !== "string" || args.value.length > 16384) fail("invalidRequest", "A string value of at most 16384 characters is required");
      const win = doc.defaultView;
      let proto;
      if (action === "element.select") {
        if (el.tagName !== "SELECT" || ![...el.options].some(o => o.value === args.value && !o.disabled)) fail("unsupportedControl", "Select requires an enabled existing option");
        proto = win.HTMLSelectElement.prototype;
      } else {
        if (!["INPUT", "TEXTAREA"].includes(el.tagName) || el.readOnly || ["checkbox", "radio", "button", "submit", "range", "color", "hidden"].includes(el.type)) fail("unsupportedControl", "Fill supports native text inputs/textarea; custom editors require qualification");
        proto = el.tagName === "INPUT" ? win.HTMLInputElement.prototype : win.HTMLTextAreaElement.prototype;
      }
      Object.getOwnPropertyDescriptor(proto, "value").set.call(el, args.value);
      el.dispatchEvent(new win.Event("input", {bubbles: true, composed: true}));
      el.dispatchEvent(new win.Event("change", {bubbles: true}));
    } else fail("unsupportedAction", "Unsupported DOM action");
    return {dispatchState: "dispatched", effectState: "unverified", inputSemantics: "DOM activation; isTrusted=false", value: secret(el) ? "[redacted]" : ("value" in el ? text(el.value) : undefined)};
  }
  return {snapshot, resolve, act, role, name, secret};
})();
if (typeof module !== "undefined") module.exports = globalThis.MechanizeDOM;
