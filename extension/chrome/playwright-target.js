// Canonical packaged target guard shared by the reviewed sidecar and relay.
// No caller expression is accepted by this module.
globalThis.MechanizePlaywrightTarget = (() => {
  function publicTarget(element,action){
    const sensitive=node=>node.matches('input[type="password"],[data-mechanize-secret]')||/password|username|user.?name|login|secret|token|credit.?card|cc-number|cc-csc|one-time-code|api.?key|security.?code|authorization|otp|captcha/i.test([node.id,node.getAttribute('name'),node.getAttribute('autocomplete'),node.getAttribute('aria-label'),node.getAttribute('placeholder'),node.getAttribute('title'),...[...(node.labels||[])].map(l=>l.textContent)].join(' '));
    if(!element.isConnected||sensitive(element)||element.closest('[data-mechanize-secret]'))return false;
    if(action==='element.fill'&&!(element.tagName==='TEXTAREA'||element.tagName==='INPUT'&&['text','search','email','tel','url','number'].includes(element.type)))return false;
    return ![...element.querySelectorAll('input,textarea,select,[contenteditable],[data-mechanize-secret]')].some(sensitive);
  }
  const source=publicTarget.toString();
  function semanticSnapshot(locator,injected){
    if(!injected?.utils||typeof injected.querySelectorAll!=='function'||typeof injected.parseSelector!=='function')return;
    const attribute=value=>'"'+value.replace(/\\/g,'\\\\').replace(/"/g,'\\"')+'"s';
    let selector;
    if(locator?.strategy==='role'&&/^[a-z]+$/.test(locator.value))selector='internal:role='+locator.value+(locator.name===undefined?'':'[name='+attribute(locator.name)+']');
    else if(locator?.strategy==='label')selector='internal:label='+JSON.stringify(locator.value)+'s';
    else if(locator?.strategy==='testId')selector='internal:testid=[data-testid='+attribute(locator.value)+']';
    else if(locator?.strategy==='id')selector='css=[id='+JSON.stringify(locator.value)+']';
    else return;
    // Use the same pinned Playwright role/name/visibility and shadow traversal
    // as getByRole/getByLabel, bound to the original immutable typed locator.
    const peers=injected.querySelectorAll(injected.parseSelector(selector),this.ownerDocument),rank=peers.indexOf(this);
    if(rank<0||locator.index===undefined&&peers.length!==1||locator.index!==undefined&&rank!==locator.index)return;
    return JSON.stringify([this.tagName,injected.utils.getAriaRole(this),injected.utils.getElementAccessibleNameText(this,false),...['id','name','role','type','aria-label','aria-labelledby','title','autocomplete','data-testid','href'].map(k=>this.getAttribute(k)),this.textContent,...[...(this.labels||[])].map(l=>l.textContent),rank]);
  }
  const snapshotSource=semanticSnapshot.toString();
  const boundarySource=`function(action,input,signature,locator,injected){const safe=${source},snapshot=${snapshotSource};if(!safe(this,action)||snapshot.call(this,locator,injected)!==signature)return false;if(action==='element.fill')return this.ownerDocument.activeElement===this;if(action!=='element.press'||input.type!=='mousePressed')return false;const hit=this.ownerDocument.elementFromPoint(input.x,input.y);return hit===this||!!hit&&this.contains(hit);}`;
  // Playwright 1.64's public ElementHandle.evaluate packages the fixed source
  // as argument 3 and the single exact element handle as its final argument.
  function pinnedObject(params,result){
    const a=params?.arguments;
    if(params?.functionDeclaration!=='(utilityScript, ...args) => utilityScript.evaluate(...args)'||params.returnByValue!==true||params.awaitPromise!==true||result?.exceptionDetails||result?.result?.value!==true||!Array.isArray(a)||a.length!==8||a[1]?.value!==true||a[2]?.value!==true||a[3]?.value!=='('+source+')'||a[4]?.value!==2||a[5]?.value?.h!==0||typeof a[7]?.objectId!=='string')return;
    return {objectId:a[7].objectId,action:a[6]?.value};
  }
  const querySource="(injected2, params2) => {\n              const elements = injected2.querySelectorAll(params2.info.parsed, params2.scope || document);\n              if (params2.markTargets === \"all\")\n                injected2.markTargetElements(new Set(elements));\n              else if (params2.markTargets === \"first\" && elements.length)\n                injected2.markTargetElements(/* @__PURE__ */ new Set([elements[0]]));\n              else if (params2.markTargets === \"first\")\n                injected2.markTargetElements(/* @__PURE__ */ new Set());\n              injected2.checkDeprecatedSelectorUsage(params2.info.parsed, elements);\n              if (params2.info.strict && elements.length > 1)\n                throw injected2.strictModeViolationError(params2.info.parsed, elements);\n              if (!elements.length && !params2.callWithoutMatches)\n                return \"--playwright--no--result--value--\";\n              const func = injected2.eval(\"(\" + params2.functionText + \")\");\n              return func({ injected: injected2, elements, info: params2.info, frameVisible: params2.frameVisible }, params2.arg);\n            }";
  function queryObject(params,result){
    const a=params?.arguments;
    if(params?.functionDeclaration!=='(utilityScript, ...args) => utilityScript.evaluate(...args)'||params.returnByValue!==true||params.awaitPromise!==true||result?.exceptionDetails||result?.result?.type!=='number'||(!Number.isSafeInteger(result.result.value)||result.result.value<0)||!Array.isArray(a)||a.length!==8||a[1]?.value!==true||a[2]?.value!==true||a[3]?.value!==querySource||a[4]?.value!==2||a[5]?.value?.h!==0||typeof a[7]?.objectId!=='string')return;
    const fields=a[6]?.value?.o;
    if(!Array.isArray(fields)||fields.filter(field=>field?.k==='functionText').length!==1||fields.find(field=>field?.k==='functionText')?.v!=='({ elements }) => elements.length')return;
    return a[7].objectId;
  }
  return {publicTarget,snapshotSource,boundarySource,pinnedObject,querySource,queryObject};
})();
if(typeof module!=='undefined')module.exports=globalThis.MechanizePlaywrightTarget;
