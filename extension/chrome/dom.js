globalThis.MechanizeDOM = globalThis.MechanizeDOM || (() => {
  const fail = (code, message) => { throw MechanizeProtocol.error(code, message); };
  let privateText=null;
  const text = value => {const raw=String(value||"");return (privateText?privateText(raw):raw).replace(/\s+/g," ").trim().slice(0,256);};
  // Explicit values are data, not snapshot labels. Never normalize or truncate
  // them: equality postconditions need the entire redacted native value.
  function exactValue(value) {
    const raw=String(value ?? "");
    const safe=privateText?privateText(raw):raw;
    if(typeof safe!=="string")fail("attributeUnavailable","Public value redaction unavailable");
    if(safe.length>32768)fail("readTooLarge","Public value exceeds 32768 UTF-8 bytes");
    const bytes=new TextEncoder().encode(safe).length;
    if(bytes>32768)fail("readTooLarge","Public value exceeds 32768 UTF-8 bytes");
    return {value:safe,valueReadVersion:1,valueReadBytes:bytes};
  }
  function installPrivateRedactor(redactor){if(privateText||typeof redactor!=="function")throw Error();privateText=redactor;return true;}
  function identifierCredential(el){
    const cues=[el.id,el.name,el.getAttribute('aria-label'),el.getAttribute('placeholder'),...(el.labels?[...el.labels].map(x=>x.textContent):[])].join(' ');
    if(!/identifier|identyfikator/i.test(cues))return false;
    const strong=/login|sign.?in|logowanie|zalog/i;
    function loginContext(scope){
      if(scope.querySelector('input[type="password"]'))return true;
      if(strong.test([scope.id,scope.getAttribute('class'),scope.getAttribute('aria-label')].join(' ')))return true;
      // Only local form headings, with a bounded text length; ordinary business
      // labels and arbitrary page prose do not establish credential context.
      const headings=scope.querySelectorAll('h1,h2,h3,[role="heading"]');
      for(let i=0;i<Math.min(headings.length,8);i++)if(strong.test((headings[i].textContent||'').slice(0,256)))return true;
      return false;
    }
    const form=el.closest('form,[role="form"]');
    if(form)return loginContext(form);
    let scope=el.parentElement;
    for(let i=0;scope&&i<4;i++,scope=scope.parentElement){if(scope.tagName==='BODY'||scope.tagName==='HTML')break;if(loginContext(scope))return true;}
    return false;
  }
  function secret(el) {
    if(el.closest("[data-mechanize-secret]"))return true;
    // Credential cues classify value-bearing controls, not navigation labels
    // or conversation titles which happen to discuss login, tokens or secrets.
    const editable=el.isContentEditable||el.closest('[contenteditable="true"],[contenteditable=""],[contenteditable="plaintext-only"]');
    const control=["INPUT","TEXTAREA","SELECT"].includes(el.tagName)&&!(el.tagName==="INPUT"&&["button","submit","reset","image"].includes(el.type))||editable||["textbox","searchbox","combobox"].includes(el.getAttribute("role"));
    // Keep the existing conservative label masking after a private handoff.
    // Its installed redactor may know credentials reflected outside inputs.
    if(!control&&!privateText)return false;
    return identifierCredential(el) || el.type === "password" || /password|username|user.?name|login|secret|token|credit.?card|cc-number|cc-csc|one-time-code|api.?key|security.?code|authorization|autoryzac|otp|captcha/i.test([el.id, el.name, el.autocomplete, el.getAttribute("aria-label"), el.getAttribute("placeholder"), el.getAttribute("title"), ...(el.labels ? [...el.labels].map(label => label.textContent) : [])].join(" "));
  }
  // Metadata-only, fresh on each admitted public projection. Hidden credential
  // nodes remain secret() and never become a value-read permission.
  function credentialLayout(doc) {
    try {
      const url=new URL(doc.URL);
      if(!['http:','https:'].includes(url.protocol)||url.username||url.password)return {state:'unavailable',reason:'location'};
      const result=walk(doc);
      if(!result.complete)return {state:'unavailable',reason:'coverage'};
      const valueControl=el=>['INPUT','TEXTAREA','SELECT'].includes(el.tagName)||el.isContentEditable||['textbox','searchbox','combobox'].includes(el.getAttribute('role'));
      for(const el of result.nodes) {
        if(!visible(el)||el.closest('[hidden],[inert]'))continue;
        if(valueControl(el)&&(el.type==='password'||identifierCredential(el)||/password|username|user.?name|login|one-time-code|otp|captcha|security.?code|authorization|autoryzac/i.test([el.id,el.name,el.autocomplete,el.getAttribute('aria-label'),el.getAttribute('placeholder'),...(el.labels?[...el.labels].map(x=>x.textContent):[])].join(' '))))return {state:'login',reason:'credentialField'};
        if(['H1','H2','H3'].includes(el.tagName)||el.getAttribute('role')==='alert') {
          const heading=(el.textContent||'').slice(0,256);
          if(/(?:nie.możemy.ci[eę].zalogować|(?:login|sign.?in).*(?:failed|error)|(?:failed|unable).*(?:login|sign.?in)|(?:you.have.been|you.are).*(?:logged|signed).out)/i.test(heading))return {state:'login',reason:'loginError'};
        }
      }
      return {state:'public',reason:'none'};
    } catch { return {state:'unavailable',reason:'coverage'}; }
  }
  async function credentialScopeEvidence(doc, current) {
    if(typeof current!=='function'||current()!==true)return {version:1,public:false,reason:'authority'};
    try {
      const before=credentialLayout(doc);if(before.state!=='public')return {version:1,public:false,reason:before.reason};
      const url=new URL(doc.URL),route=url.origin+url.pathname;
      const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(route));
      if(current()!==true)return {version:1,public:false,reason:'authority'};
      const after=new URL(doc.URL);
      if(after.origin+after.pathname!==route)return {version:1,public:false,reason:'authority'};
      const fresh=credentialLayout(doc);if(fresh.state!=='public')return {version:1,public:false,reason:fresh.reason};
      return {version:1,public:true,routeSHA256:Array.from(new Uint8Array(digest),v=>v.toString(16).padStart(2,'0')).join('')};
    }catch{return {version:1,public:false,reason:'coverage'};}
  }
  let credentialScopeGuard=null;
  function withCredentialScope(doc, guard, run) {
    if(credentialScopeGuard||typeof guard!=='function'||typeof run!=='function'||guard()!==true||credentialLayout(doc).state!=='public')fail('secureDocumentRequired','Current credential scope is not public');
    credentialScopeGuard=()=>guard()===true&&credentialLayout(doc).state==='public';
    try { return run(); } finally { credentialScopeGuard=null; }
  }
  const quarantined = new WeakSet();
  function protectedDocument(doc) {
    if(credentialScopeGuard)return !credentialScopeGuard();
    // A committed login handoff ends document-wide blocking. Sensitive fields
    // are still withheld by secret(), and known values pass through privateText.
    if (privateText) return false;
    if (quarantined.has(doc)) return true;
    const result = walk(doc);
    // Incomplete coverage cannot establish that a document is credential-free.
    if (!result.complete || result.nodes.some(privateText ? unsafePrivateInput : secret)) { quarantined.add(doc); return true; }
    return false;
  }
  function unsafePrivateInput(el) {
    if(!["INPUT","TEXTAREA","SELECT"].includes(el.tagName)&&!el.isContentEditable)return false;
    if(el.type==="password"||el.closest("[data-mechanize-secret]"))return true;
    const cues=[el.id,el.name,el.autocomplete,el.getAttribute("aria-label"),el.getAttribute("placeholder"),...(el.labels?[...el.labels].map(x=>x.textContent):[])].join(" ");
    return visible(el)&&(identifierCredential(el)||/username|user.?name|login|one-time-code|otp|captcha|security.?code|authorization|autoryzac/i.test(cues));
  }
  // Layout evidence alone grants no public observation authority.
  function privateLayoutReady(doc) {const result=walk(doc);return result.complete&&!result.nodes.some(unsafePrivateInput);}
  function privateDocumentReady(doc) {return !quarantined.has(doc)&&privateLayoutReady(doc);}
  function installPrivateDocumentRedactor(doc,redactor) {
    if(typeof redactor!=='function'||!privateLayoutReady(doc))throw Error();
    if(privateText)return privateDocumentReady(doc);
    installPrivateRedactor(redactor);quarantined.delete(doc);return privateDocumentReady(doc);
  }
  function requirePublicDocument(doc) {
    if (protectedDocument(doc)) fail("secureDocumentRequired", "Credential document requires a separately qualified local secure route");
  }
  function role(el){return globalThis.MechanizeAccessibility?.role(el)||'generic';}
  let projection,projectionOperation=false;
  function withProjection(doc,run){
    requirePublicDocument(doc);
    if(projectionOperation)return run();
    projectionOperation=true;
    try{return run();}finally{projection=undefined;projectionOperation=false;}
  }
  function name(el,doc){
    if(secret(el))return '[redacted]';
    return withProjection(doc,()=>{
      if(!globalThis.MechanizeAccessibility)fail('coverageIncomplete','Accessible-name provider unavailable');
      try{
        if(!projection)projection=MechanizeAccessibility.createProjection(doc,{secret,redact:v=>privateText?privateText(v):v});
        const n=projection.name(el);
        if(!n.supported)return undefined;
        if(n.value!=='' || !(el.tagName==='TEXTAREA'||el.tagName==='INPUT'&&['text','search','tel','email','url'].includes(el.type)))return n.value;
        // Playwright adds the browser placeholder fallback to the public
        // AccName algorithm. Apply it only to supported, non-secret controls.
        const raw=el.getAttribute('placeholder')||'',safe=privateText?privateText(raw):raw;
        if(safe!==raw)return undefined;
        const fallback=safe.replace(/\s+/g,' ').trim();
        return fallback.length<=256?fallback:undefined;
      }catch(error){
        if(error?.code)throw error;
        if(error?.message==='projectionLimit')fail('coverageIncomplete','Accessible-name projection exceeded its bound');
        fail('coverageIncomplete','Accessible-name projection unavailable');
      }
    });
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
  function resolve(doc,locator){return withProjection(doc,()=>resolveProjected(doc,locator));}
  function resolveProjected(doc, locator) {
    requirePublicDocument(doc);
    if (!locator || Object.keys(locator).some(k => !["strategy", "value", "name", "exact"].includes(k)) || typeof locator.value !== "string") fail("invalidLocator", "Closed locator with string value required");
    const allowed = ["id", "testId", "role", "label", "css"];
    if (!allowed.includes(locator.strategy)) fail("unsupportedSelector", "Supported: id, testId, role, label, css; frame scope is mandatory");
    // Query candidate elements without consuming the semantic snapshot budget
    // on unrelated layout nodes. Discover open shadow roots with a separate
    // bounded pass so duplicate matches remain ambiguous across all roots.
    const roots = [doc], candidates = [], seen = new Set();
    let inspected = 0;
    const selectors = {id: "[id]", testId: "[data-testid]", role: "*", label: "*"};
    try {
      for (let i = 0; i < roots.length; i++) {
        const root = roots[i];
        for (const el of root.querySelectorAll("*")) {
          if (++inspected > 20000) fail("coverageIncomplete", "Bounded open-shadow discovery exceeded its limit");
          if (el.shadowRoot) roots.push(el.shadowRoot);
        }
        for (const el of root.querySelectorAll(locator.strategy === "css" ? locator.value : selectors[locator.strategy])) {
          if (!seen.has(el)) { seen.add(el); candidates.push(el); }
        }
      }
    } catch (error) {
      if (error?.code) throw error;
      fail("invalidLocator", "CSS selector could not be parsed");
    }
    let matches;
    try { matches = candidates.filter(el => {
      const expected = locator.value;
      if (locator.strategy === "id") return el.id === expected;
      if (locator.strategy === "testId") return el.getAttribute("data-testid") === expected;
      if (locator.strategy === "css") return el.matches(expected);
      if(locator.strategy === "role" && role(el) !== expected)return false;
      const expectedName = locator.strategy === "role" ? locator.name : expected;
      if(expectedName === undefined)return true;
      const n=name(el,doc);
      return locator.exact === false ? typeof n === "string" && n.includes(expectedName) : n === expectedName;
    }); } catch(error) {if(error?.code)throw error;fail("invalidLocator", "CSS selector could not be parsed");}
    if (!matches.length) fail("targetNotFound", "No matching element in the bound document");
    if (matches.length !== 1) fail("ambiguousTarget", `${matches.length} elements match; refine the locator`);
    return matches[0];
  }
  function snapshot(doc,args={}){return withProjection(doc,()=>snapshotProjected(doc,args));}
  function snapshotProjected(doc, args = {}) {
    requirePublicDocument(doc);
    const limit = Number.isInteger(args.limit) ? Math.max(1, Math.min(args.limit, 200)) : 100;
    const result = walk(doc), nodes = [];
    // Reorder only the already bounded discovery set into DOM preorder. Open
    // shadow children follow the host's light children; no extra nodes or values
    // are inspected to establish ordering.
    const children = new Map();
    for (const el of result.nodes) {
      const parent = el.parentElement || el.getRootNode().host || doc;
      if (!children.has(parent)) children.set(parent, []);
      children.get(parent).push(el);
    }
    const ordered = [], stack = [...(children.get(doc) || [])].reverse();
    while (stack.length) { const el = stack.pop(); ordered.push(el); stack.push(...(children.get(el) || []).slice().reverse()); }
    // Visible controls get the bounded output budget before structural rows.
    // Stable partitions retain DOM order within groups; hidden nodes stay last.
    const interactive = new Set(['button','checkbox','combobox','gridcell','link','listbox','menuitem','menuitemcheckbox','menuitemradio','option','radio','scrollbar','searchbox','slider','spinbutton','switch','tab','textbox','treeitem']);
    const candidates = ordered.map(el => ({el, role: role(el), visible: visible(el)}));
    const groups = [[], [], []];
    for (const candidate of candidates) {
      if (candidate.role !== 'generic') groups[candidate.visible ? interactive.has(candidate.role) ? 0 : 1 : 2].push(candidate);
    }
    for (const {el, role: r, visible: isVisible} of groups.flat()) {
      if (nodes.length >= limit) return {nodes, truncated: true, coverage: coverage()};
      const sensitive=secret(el);
      nodes.push({role: r, name: sensitive ? "[redacted]" : name(el, doc), id: sensitive ? undefined : text(el.id), testId: sensitive ? undefined : text(el.getAttribute("data-testid")), visible: isVisible, enabled: !el.disabled && el.getAttribute("aria-disabled") !== "true", value: sensitive ? "[redacted]" : ("value" in el ? text(el.value) : undefined)});
    }
    return {nodes, truncated: !result.complete, coverage: coverage()};
  }
  const coverage = () => ["DOM-derived roles/names, not Chrome AX", "Open shadow roots only; closed roots/canvas unavailable", "Only the explicitly bound frame", "DOM events are untrusted; business outcome requires broker verification"];
  async function protocolClickPoint(doc,locator,deadline) {
    requirePublicDocument(doc);
    const el=resolve(doc,locator);
    const ready=()=>el.isConnected&&visible(el)&&!el.disabled&&el.getAttribute('aria-disabled')!=='true'&&!el.closest('[inert]')&&Date.now()<deadline;
    if(!ready()||el.type==='file')fail('targetNotActionable','Browser click target is unavailable');
    el.scrollIntoView?.({block:'center',inline:'center'});
    const before=el.getBoundingClientRect();
    // Background tabs suspend animation frames. Observe geometry after a short
    // bounded interval as well; neither path grants input without the fresh
    // geometry, visibility, hit-target and deadline checks below.
    await new Promise(resolve => {
      let frame, settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (frame !== undefined) doc.defaultView.cancelAnimationFrame?.(frame);
        resolve();
      };
      const timer = setTimeout(finish, Math.max(0, Math.min(50, deadline - Date.now())));
      frame = doc.defaultView.requestAnimationFrame?.(finish);
    });
    if (Date.now() >= deadline) fail('dispatchExpired', 'Target stability observation expired');
    const after=el.getBoundingClientRect();
    if(!ready()||['x','y','width','height'].some(k=>!Number.isFinite(after[k])||Math.abs(after[k]-before[k])>1)||after.width<=0||after.height<=0)fail('targetNotActionable','Browser click target did not settle');
    const x=after.x+after.width/2,y=after.y+after.height/2;
    const hit=doc.elementFromPoint(x,y);
    if(x<0||y<0||x>=doc.defaultView.innerWidth||y>=doc.defaultView.innerHeight||!hit||!(hit===el||el.contains(hit)))fail('targetNotActionable','Browser click target is obscured');
    requirePublicDocument(doc);
    return {x,y};
  }
  function scopedElementText(el) {
    if(!credentialScopeGuard)return el.textContent;
    const queue=[el],pieces=[];let count=0;
    while(queue.length){const node=queue.pop();if(++count>2000)fail('coverageIncomplete','Bounded text projection unavailable');
      if(node.nodeType===3){pieces.push(node.textContent||'');continue;}
      if(node.nodeType!==1||secret(node)||['SCRIPT','STYLE','NOSCRIPT'].includes(node.tagName))continue;
      queue.push(...[...node.childNodes].reverse());
    }
    return pieces.join('');
  }
  function act(doc, action, locator, args = {}) {
    requirePublicDocument(doc);
    if (Object.keys(args).some(k => !["value", "limit", "attribute"].includes(k))) fail("invalidRequest", "Unknown action argument");
    if (action === "observe") return snapshot(doc, args);
    const el = resolve(doc, locator);
    if (action === "resolve") return {role: role(el), name: secret(el) ? "[redacted]" : name(el, doc), visible: visible(el), enabled: !el.disabled};
    if (action === "read") {
      const attribute = args.attribute || "value";
      if (!["value", "text", "name"].includes(attribute)) fail("unsupportedAttribute", "Read supports value, text and name");
      if(secret(el))return {value:"[redacted]"};
      if(attribute==="value")return exactValue(el.value);
      return {value:attribute==="name"?name(el,doc):text(scopedElementText(el))};
    }
    if (secret(el)) fail("secureDocumentRequired", "Sensitive input requires local credential delivery");
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
    if (protectedDocument(doc)) throw MechanizeProtocol.error("secureDocumentRequired", "Credential document appeared after dispatch; reconcile the effect locally", "unknown");
    return {dispatchState: "dispatched", effectState: "unverified", inputSemantics: "DOM activation; isTrusted=false", value: secret(el) ? "[redacted]" : ("value" in el ? text(el.value) : undefined)};
  }
  return {credentialScopeEvidence,credentialLayout,withCredentialScope,protocolClickPoint, snapshot, resolve, act, role, name, secret, protectedDocument,installPrivateRedactor,installPrivateDocumentRedactor,privateLayoutReady,privateDocumentReady};
})();
if (typeof module !== "undefined") module.exports = globalThis.MechanizeDOM;
