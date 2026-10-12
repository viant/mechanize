// Private receiver component only. No ordinary DOM command calls this module.
// The worker must independently authenticate the channel, document and lease.
globalThis.MechanizeSecureInput = (() => {
  const keys = ['attemptId', 'origin', 'deadlineUnixMs', 'username', 'password'];
  const cue = /username|user.?name|login|identyfikator/i;
  const challenge = /one-time-code|otp|captcha|security.?code|authorization|autoryzac/i;
  function metadata(el) {
    return [el.id, el.name, el.autocomplete, el.getAttribute('aria-label'),
      el.getAttribute('placeholder'), ...(el.labels ? [...el.labels].map(x => x.textContent) : [])].join(' ');
  }
  function usernameCue(el) {
    const value=metadata(el);
    if(/username|user.?name|login/i.test(value))return true;
    if(!/identyfikator/i.test(value))return false;
    return typeof globalThis.MechanizeDOM?.secret!=='function'||globalThis.MechanizeDOM.secret(el);
  }
  function visible(el) {
    const style = el.ownerDocument.defaultView.getComputedStyle(el);
    return el.isConnected &&
      !el.closest('[hidden],[inert]') && style.display !== 'none' && style.visibility !== 'hidden' && el.getClientRects().length > 0;
  }
  function textChallenge(doc) {
    return [...doc.querySelectorAll('h1,h2,h3,p,label,button,[role="alert"],[aria-live="assertive"]')].filter(visible).slice(0,128).some(x=>/potwierdź\s+logowanie|kod\s+(?:sms|jednorazowy|weryfikacyjny)|(?:approve|confirm)\s+(?:this\s+)?(?:login|sign.?in)|verification\s+code/i.test((x.textContent||'').slice(0,4096)));
  }
  function actionable(el) {
    return visible(el) && !el.disabled && !el.readOnly && el.getAttribute('aria-disabled') !== 'true';
  }
  const inspectionReasons=new Set(['none','originUnavailable','fieldLimit','visibleChallengeControl','inactiveChallengeControl','hiddenChallengeControl','ambiguousPasswordFields','newPasswordField','ambiguousUsernameFields','noCredentialFields','missingForm','differentForms','unsafeFormAction','unsafeFormTarget','formControlLimit','unsupportedFormControl','formDetached','unsupportedFormMethod','submitUnavailable','missingSubmitter','ambiguousSubmitter','submitterDisabled','unsafeSubmitter','fieldsUnavailable','submitterUnavailable','challenge']);
  const inspectionFailure=reason=>{throw Object.assign(Error(),{inspectionReason:reason});};
  function pair(doc, origin) {
    const inputs=[...doc.querySelectorAll('input')];
    if(inputs.length>64)inspectionFailure('fieldLimit');if(inputs.some(x=>actionable(x)&&challenge.test(metadata(x))))inspectionFailure('visibleChallengeControl');
    const passwords=inputs.filter(x=>x.type==='password'&&actionable(x));
    if(passwords.length>1)inspectionFailure('ambiguousPasswordFields');if(passwords.some(x=>x.autocomplete.split(/\s+/).includes('new-password')))inspectionFailure('newPasswordField');
    const users=inputs.filter(x=>['text','email','tel'].includes(x.type)&&usernameCue(x)&&actionable(x));
    if(users.length>1)inspectionFailure('ambiguousUsernameFields');if(!users.length&&!passwords.length)inspectionFailure('noCredentialFields');
    const password=passwords[0]||null,username=users[0]||null,form=(password||username).form;
    if(!form)inspectionFailure('missingForm');if(form.ownerDocument!==doc||username&&username.form!==form)inspectionFailure('differentForms');
    if(new URL(form.action||doc.URL,doc.URL).origin!==origin)inspectionFailure('unsafeFormAction');if(form.target&&form.target!=='_self')inspectionFailure('unsafeFormTarget');
    const controls=[...form.elements];
    if(controls.length>64)inspectionFailure('formControlLimit');if(controls.some(x=>x.tagName.includes('-')||x.shadowRoot))inspectionFailure('unsupportedFormControl');const challengeControl=controls.find(x=>challenge.test(metadata(x)));if(challengeControl)inspectionFailure(visible(challengeControl)?'inactiveChallengeControl':'hiddenChallengeControl');
    return {username,password,form,stage:username&&password?'pair':username?'username':'password'};
  }
  // Qualify the same submission contract before secrets reach the page, then
  // recheck it at dispatch. This probe reads metadata only, never input values.
  function submitter(doc, origin, form, requireEnabled = false) {
    if(!form.isConnected)inspectionFailure('formDetached');if(!['post','get'].includes(form.method.toLowerCase()))inspectionFailure('unsupportedFormMethod');
    if(new URL(form.action||doc.URL,doc.URL).origin!==origin)inspectionFailure('unsafeFormAction');if(form.target&&form.target!=='_self')inspectionFailure('unsafeFormTarget');if(typeof doc.defaultView.HTMLElement.prototype.click!=='function')inspectionFailure('submitUnavailable');
    const candidates = [...form.elements].filter(x => ['BUTTON','INPUT'].includes(x.tagName) && ['submit','button'].includes(x.type) && visible(x));
    const submits = candidates.filter(x => x.type === 'submit');
    const buttons = submits.length ? submits : candidates;
    if(buttons.length!==1)inspectionFailure(buttons.length?'ambiguousSubmitter':'missingSubmitter');
    const button = buttons[0];
    if(requireEnabled&&!actionable(button))inspectionFailure('submitterDisabled');
    // Check explicit overrides as attributes too: some DOM implementations do
    // not expose formMethod/formAction properties.
    const action = button.getAttribute('formaction');
    const method = button.getAttribute('formmethod');
    const target = button.getAttribute('formtarget');
    if (action !== null && new URL(action || doc.URL, doc.URL).origin !== origin ||
        method !== null && !['post','get'].includes(method.toLowerCase()) ||
        target !== null && target !== '' && target !== '_self') inspectionFailure('unsafeSubmitter');
    return button;
  }
  // JavaScript login buttons often live in forms whose default method is GET.
  // Click handlers may run, but credentials must never leave by native GET
  // submission. Keep this guard for delayed requestSubmit calls as well.
  function guardNativeSubmission(doc, origin, form) {
    form.addEventListener('submit', event => {
      try {
        const button = event.submitter;
        const action = button?.getAttribute('formaction') ?? form.action;
        const method = button?.getAttribute('formmethod') ?? form.method;
        const target = button?.getAttribute('formtarget') ?? form.target;
        if (new URL(action || doc.URL, doc.URL).origin !== origin || method.toLowerCase() !== 'post' || target && target !== '_self') event.preventDefault();
      } catch { event.preventDefault(); }
    }, true);
  }
  // Presentation only, with fixed markup. No page text or credential is read,
  // retained in the marker, or returned to the broker. Mount after dispatch so
  // the cue cannot invalidate the final document/lease guard before the click.
  function clickCue(doc, rect) {
    try {
      if (!rect || ![rect.left,rect.top,rect.width,rect.height].every(Number.isFinite) || rect.width<=0 || rect.height<=0) return;
      const marker=doc.createElement('div');marker.setAttribute('data-mechanize-pointer','');marker.setAttribute('aria-hidden','true');
      marker.style.cssText=`all:initial!important;position:fixed!important;left:${rect.left+rect.width/2-25}px!important;top:${rect.top+rect.height/2-25}px!important;width:84px!important;height:84px!important;pointer-events:none!important;z-index:2147483647!important;`;
      const shadow=marker.attachShadow({mode:'closed'});
      shadow.innerHTML='<style>:host{pointer-events:none}svg{overflow:visible}.pulse{transform-origin:25px 25px;animation:pulse .6s ease-out forwards}@keyframes pulse{from{transform:scale(.7);opacity:1}to{transform:scale(1.5);opacity:0}}</style><svg width="84" height="84" viewBox="0 0 84 84" aria-hidden="true"><circle class="pulse" cx="25" cy="25" r="18" fill="none" stroke="#db1929" stroke-width="3"/><path d="M25 25V65L36 54L45 72L54 67L45 49H62Z" fill="#db1929" stroke="white" stroke-width="3" stroke-linejoin="round"/></svg>';
      doc.documentElement.append(marker);
      doc.defaultView.setTimeout(()=>marker.remove(),900);
    } catch { /* A visual cue cannot change a dispatched action's outcome. */ }
  }
  function create() {
    const attempts = new Set();
    let blocked = false, retained = null;
    function fill(doc, payload, revalidate) {
      let wrote = false;
      try {
        if (blocked || retained || !payload || Object.keys(payload).sort().join() !== [...keys].sort().join() ||
            !/^[a-f0-9]{64}$/.test(payload.attemptId) || attempts.has(payload.attemptId) || attempts.size >= 256 ||
            typeof revalidate !== 'function' || typeof payload.username !== 'string' || typeof payload.password !== 'string' ||
            !payload.username || !payload.password || new TextEncoder().encode(payload.username).length > 1024 ||
            new TextEncoder().encode(payload.password).length > 4096 || typeof payload.origin !== 'string' ||
            new URL(payload.origin).origin !== payload.origin || !payload.origin.startsWith('https://')) return {status: 'notDispatched'};
        attempts.add(payload.attemptId);
        const check = () => {
          if (!Number.isSafeInteger(payload.deadlineUnixMs) || payload.deadlineUnixMs <= Date.now() ||
              payload.deadlineUnixMs > Date.now() + 15000 || doc.location.origin !== payload.origin ||
              doc.defaultView.top !== doc.defaultView) throw Error();
          const checked = revalidate(wrote);
          if (checked !== undefined && checked !== true) throw Error();
        };
        check();
        const fields = pair(doc, payload.origin);
        const button = submitter(doc, payload.origin, fields.form);
        guardNativeSubmission(doc, payload.origin, fields.form);
        // Preserve the ordinary document quarantine, including after SPA login.
        for(const el of [fields.username,fields.password])if(el)el.setAttribute('data-mechanize-secret','');
        if (!globalThis.MechanizeDOM?.protectedDocument(doc)) throw Error();
        const setter = Object.getOwnPropertyDescriptor(doc.defaultView.HTMLInputElement.prototype, 'value')?.set;
        if (!setter) throw Error();
        for (const key of ['username', 'password'].filter(key=>fields[key])) {
          check();
          const current = pair(doc, payload.origin);
          if (current.username !== fields.username || current.password !== fields.password || current.form !== fields.form) throw Error();
          wrote = true;
          setter.call(fields[key], payload[key]);
          fields[key].dispatchEvent(new doc.defaultView.Event('input', {bubbles: true, composed: true}));
          fields[key].dispatchEvent(new doc.defaultView.Event('change', {bubbles: true}));
          check();
          if (!fields[key].isConnected || fields[key].value !== payload[key]) throw Error();
        }
        check();
        if (submitter(doc,payload.origin,fields.form) !== button) throw Error();
        retained={...fields,button,buttonType:button.type,buttonAction:button.getAttribute('formaction'),buttonMethod:button.getAttribute('formmethod'),buttonTarget:button.getAttribute('formtarget'),attemptId:payload.attemptId,origin:payload.origin,action:fields.form.action,method:fields.form.method,submitted:false};
        return {status: 'dispatched'};
      } catch {
        if (wrote) blocked = true;
        return {status: wrote ? 'unknown' : 'notDispatched'};
      }
    }
    function submit(doc,payload,revalidate) {
      let dispatched=false;
      try {
        if(blocked||!retained||retained.submitted||!payload||Object.keys(payload).sort().join()!=="attemptId,deadlineUnixMs,fillAttemptId,origin"||
           !/^[a-f0-9]{64}$/.test(payload.attemptId)||attempts.has(payload.attemptId)||payload.fillAttemptId!==retained.attemptId||payload.origin!==retained.origin||typeof revalidate!=="function")return {status:"notDispatched"};
        attempts.add(payload.attemptId);retained.submitted=true;retained.submitAttempt=payload.attemptId;
        const check=()=>{if(!Number.isSafeInteger(payload.deadlineUnixMs)||payload.deadlineUnixMs<=Date.now()||payload.deadlineUnixMs>Date.now()+10000||doc.location.origin!==retained.origin||doc.defaultView.top!==doc.defaultView)throw Error();const r=revalidate();if(r!==undefined&&r!==true)throw Error();};
        check();const current=pair(doc,payload.origin),form=retained.form;
        if(current.form!==form||current.username!==retained.username||current.password!==retained.password||!form.isConnected||form.action!==retained.action||form.method!==retained.method)throw Error();
        const button=submitter(doc,payload.origin,form,true);
        if(button!==retained.button||button.type!==retained.buttonType||button.getAttribute('formaction')!==retained.buttonAction||button.getAttribute('formmethod')!==retained.buttonMethod||button.getAttribute('formtarget')!==retained.buttonTarget)throw Error();
        const click=doc.defaultView.HTMLElement.prototype.click;
        const rect=button.getBoundingClientRect();
        check();dispatched=true;click.call(button);clickCue(doc,rect);return {status:"dispatched"};
      }catch{if(dispatched)blocked=true;return {status:dispatched?"unknown":"notDispatched"};}
    }
    function postSubmitStatus(doc,payload,revalidate) {
      try {
        if(blocked||!retained?.submitted||retained.submitAttempt!==payload?.attemptId||!payload||Object.keys(payload).sort().join()!=='attemptId,deadlineUnixMs,origin'||typeof revalidate!=='function'||payload.origin!==retained.origin||doc.location.origin!==retained.origin||doc.defaultView.top!==doc.defaultView||!Number.isSafeInteger(payload.deadlineUnixMs)||payload.deadlineUnixMs<=Date.now()||payload.deadlineUnixMs>Date.now()+10000)throw Error();
        const check=()=>{const r=revalidate();if(r!==undefined&&r!==true||Date.now()>=payload.deadlineUnixMs)throw Error();};check();
        // Classification reads only local metadata and fixed error cues. No
        // input values, selectors, labels or text leave this private receiver.
        const inputs=[...doc.querySelectorAll('input')];if(inputs.length>512)throw Error();
        let stage;
        if(inputs.some(x=>actionable(x)&&challenge.test(metadata(x)))||textChallenge(doc))stage='challenge';
        else if([...doc.querySelectorAll('[role="alert"],[aria-live="assertive"],[data-error],.error,.validation-error,[class*="error"],[id*="error"]')].filter(visible).slice(0,64).some(x=>/(?:invalid|incorrect|wrong)\s+(?:credentials|password|login)|(?:sign.?in|log.?in|authentication)\s+(?:failed|error|rejected)|nie\s+możemy\s+cię\s+zalogować|nieprawidłow[ey]\s+(?:hasło|login|dane)/i.test((x.textContent||'').slice(0,4096))))stage='rejected';
        else stage=privacyReady(doc,payload.origin)?'unavailable':'pending';
        check();return {ready:false,stage};
      }catch{return {ready:false,stage:'pending'};}
    }
    return Object.freeze({fill,submit,postSubmitStatus});
  }
  // Private recipient identity is independent of unrelated page mutation.
  // This closure is ISOLATED-world custody only: it exposes no node, selector,
  // field metadata, credential value, or serializable authority token. Transport
  // integration must bind its lifetime to the original document/channel/lease.
  function pinRecipient(doc, origin) {
    if (typeof origin !== 'string' || !origin.startsWith('https://') ||
        new URL(origin).origin !== origin || doc.location.origin !== origin ||
        doc.defaultView.top !== doc.defaultView) throw Error();
    let fields,button;try{fields=pair(doc,origin);}catch(error){throw Object.assign(Error(),{inspectionReason:inspectionReasons.has(error?.inspectionReason)?error.inspectionReason:inspect(doc,origin,()=>true).stage==='challenge'?'challenge':'fieldsUnavailable'});}try{button=submitter(doc,origin,fields.form);}catch(error){throw Object.assign(Error(),{inspectionReason:inspectionReasons.has(error?.inspectionReason)?error.inspectionReason:'submitterUnavailable'});}
    const attrs = ['type','id','name','autocomplete','form','action','method','target',
      'formaction','formmethod','formtarget','readonly','disabled','hidden','inert',
      'aria-disabled','aria-label','aria-labelledby','placeholder'];
    const signature = el => el === null ? null : JSON.stringify([
      el.tagName, ...attrs.map(key => el.getAttribute(key)), metadata(el)
    ]);
    const nodes = [fields.username, fields.password, fields.form, button];
    const original = nodes.map(signature);
    const originalDisabled=button.getAttribute('disabled'),originalAriaDisabled=button.getAttribute('aria-disabled');
    const originallyBlocked=button.disabled||originalAriaDisabled==='true';
    let retired = false;
    const current = (afterWrite=false) => {
      if (retired) return false;
      try {
        if (doc.location.origin !== origin || doc.defaultView.top !== doc.defaultView ||
            textChallenge(doc)) return false;
        const next = pair(doc, origin), nextButton = submitter(doc, origin, next.form);
        const actual = [next.username, next.password, next.form, nextButton];
        // A page may enable its original submitter in response to our input.
        // Only the fill receiver's local wrote flag permits this transition;
        // inspection and admission remain exact. No recipient or route changes.
        const currentSignature=el=>{
          if(el!==button||afterWrite!==true||!originallyBlocked||!actionable(button))return signature(el);
          return JSON.stringify([el.tagName,...attrs.map(key=>key==='disabled'?originalDisabled:key==='aria-disabled'?originalAriaDisabled:el.getAttribute(key)),metadata(el)]);
        };
        return next.stage === fields.stage && actual.every((el,index) =>
          el === nodes[index] && currentSignature(el) === original[index]);
      } catch { return false; }
    };
    return Object.freeze({stage:fields.stage,current,retire:()=>{retired=true;}});
  }

  // Metadata-only admission probe. Never returns labels, selectors or values.
  function inspect(doc, origin, revalidate) {
    try {
      if (typeof revalidate !== 'function' || typeof origin !== 'string' || !origin.startsWith('https://') ||
          new URL(origin).origin !== origin || doc.location.origin !== origin || doc.defaultView.top !== doc.defaultView) return {ready:false,stage:"unavailable"};
      const before = revalidate();
      if (before !== undefined && before !== true) return {ready:false,stage:"unavailable"};
      const fields=pair(doc, origin);
      submitter(doc, origin, fields.form);
      const after = revalidate();
      return {ready:after === undefined || after === true,stage:fields.stage};
    } catch { let stage="unavailable";try {if([...doc.querySelectorAll("input")].some(x=>actionable(x)&&challenge.test(metadata(x)))||textChallenge(doc))stage="challenge";}catch{}return {ready:false,stage}; }
  }
  function inspectionReason(doc,origin){
    try{if(typeof origin!=='string'||!origin.startsWith('https://')||new URL(origin).origin!==origin||doc.location.origin!==origin||doc.defaultView.top!==doc.defaultView)return 'originUnavailable';const fields=pair(doc,origin);submitter(doc,origin,fields.form);return 'none';}
    catch(error){if(inspectionReasons.has(error?.inspectionReason))return error.inspectionReason;return 'fieldsUnavailable';}
  }
  function redactionVariants(values) {
    const result=new Set(),alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const base64=value=>{const bytes=new TextEncoder().encode(value);let out="";for(let i=0;i<bytes.length;i+=3){const n=(bytes[i]<<16)|((bytes[i+1]||0)<<8)|(bytes[i+2]||0);out+=alphabet[(n>>>18)&63]+alphabet[(n>>>12)&63]+(i+1<bytes.length?alphabet[(n>>>6)&63]:"=")+(i+2<bytes.length?alphabet[n&63]:"=");}return out;};
    for(const value of values){if(typeof value!=="string"||!value||value.length>4096)throw Error();
      const html=value.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"),encoded=base64(value);
      for(const item of [value,value.toLowerCase(),value.toUpperCase(),encodeURI(value),encodeURIComponent(value),JSON.stringify(value).slice(1,-1),encodeURIComponent(value).replace(/%20/g,"+"),html,html.replace(/&#39;/g,"&apos;"),html.replace(/&#39;/g,"&#x27;"),value.split("").map(x=>"\\u"+x.charCodeAt(0).toString(16).padStart(4,"0")).join(""),[...value].map(x=>"&#x"+x.codePointAt(0).toString(16)+";").join(""),encoded,encoded.replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,""),[...value].map(x=>"&#"+x.codePointAt(0)+";").join('')]){result.add(item);if(item.includes('%'))result.add(item.replace(/%[0-9A-F]{2}/g,x=>x.toLowerCase()));}
    }
    const variants=[...result].filter(Boolean);if(variants.length>64||variants.reduce((n,x)=>n+x.length,0)>262144)throw Error();return variants;
  }
  function validRedactions(values){return Array.isArray(values)&&values.length>0&&values.length<=64&&values.every(x=>typeof x==="string"&&x.length>0&&x.length<=32768)&&values.reduce((n,x)=>n+x.length,0)<=262144;}
  function redact(value,variants) {
    if(!validRedactions(variants))throw Error();let nodes=0;
    const visit=(item,depth)=>{if(++nodes>65536||depth>32)throw Error();if(typeof item==="string")return variants.some(secret=>item.includes(secret))?"[redacted]":item;
      if(Array.isArray(item))return item.map(x=>visit(x,depth+1));if(item&&typeof item==="object"){const result={};for(const [key,value]of Object.entries(item))result[visit(key,depth+1)]=visit(value,depth+1);return result;}return item;};return visit(value,0);
  }
  function privacyReady(doc,origin){try{return globalThis.MechanizeDOM?.privateLayoutReady(doc)===true&&doc.location.origin===origin&&origin.startsWith("https://")&&doc.defaultView.top===doc.defaultView&&!textChallenge(doc)&&[...doc.querySelectorAll('input')].length<=512&&![...doc.querySelectorAll('input')].some(x=>x.type==='password'||challenge.test(metadata(x))||usernameCue(x)&&actionable(x));}catch{return false;}}
  return Object.freeze({create, inspect,inspectionReason,isInspectionReason:reason=>inspectionReasons.has(reason),pinRecipient,redactionVariants,validRedactions,redact,privacyReady});
})();
