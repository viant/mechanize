import {computeAccessibleName,getRole} from 'dom-accessibility-api';

// The mature name algorithm receives only an inert sanitized tree. Neither
// editable values nor designated-secret attributes reach the dependency.
const attributes=['id','for','name','type','role','aria-label','aria-labelledby','aria-owns','aria-hidden','aria-disabled','aria-checked','aria-level','alt','title','scope','size','multiple','hidden','disabled','slot','contenteditable'];
const valueAttributes=new Set(['value','aria-valuenow','aria-valuetext']);
export const version='dom-accessibility-api@0.7.1';
export function role(element){return ['HTML','BODY'].includes(element.tagName)?'generic':getRole(element)||'generic';}
export function createProjection(document,policy){
 const maximum=20000,maximumStyles=20000;
 const projected=document.implementation.createHTMLDocument('');
 Object.defineProperty(projected,'defaultView',{value:document.defaultView});
 const byOriginal=new WeakMap(),originalByClone=new WeakMap(),secretNodes=new WeakSet(),tainted=new WeakSet(),styles=new WeakMap();
 let nodes=0,styleReads=0,active; const publicSources=[];
 const safe=value=>policy.redact(String(value||''));
 function taintAncestors(source){for(let i=0;source&&i<64;i++,source=source.parentElement||source.getRootNode?.().host)tainted.add(source);}
 function clone(source,depth=0){
  if(depth>64)throw Error('projectionLimit');
  if(++nodes>maximum)throw Error('projectionLimit');
  if(source.nodeType===3){const raw=source.textContent;const value=safe(raw);if(value!==raw)taintAncestors(source.parentElement);return projected.createTextNode(value);}
  if(source.nodeType!==1)return null;
  if(['SCRIPT','STYLE','NOSCRIPT','TEMPLATE'].includes(source.tagName))return null;
  const isSecret=policy.secret(source);
  const copy=isSecret?projected.createElement('span'):projected.createElementNS(source.namespaceURI,source.localName);
  byOriginal.set(source,copy);originalByClone.set(copy,source);
  if(isSecret){taintAncestors(source.parentElement||source.getRootNode?.().host);secretNodes.add(source);copy.textContent='[redacted]';copy.setAttribute('aria-hidden','true');return copy;}
  publicSources.push(source);
  for(const key of attributes)if(source.hasAttribute(key)){const raw=source.getAttribute(key),value=safe(raw);if(raw!==value)taintAncestors(source);copy.setAttribute(key,value);}
  // Role inference needs href presence, never its potentially private URL.
  if(source.hasAttribute('href'))copy.setAttribute('href','#');
  const editable=['INPUT','TEXTAREA','SELECT'].includes(source.tagName)||(source.isContentEditable||(source.hasAttribute('contenteditable')&&source.getAttribute('contenteditable')!=='false'))||['textbox','combobox','spinbutton','slider'].includes(source.getAttribute('role'));
  const labelledButton=source.tagName==='INPUT'&&['button','submit','reset'].includes(source.type);
  if(labelledButton&&source.hasAttribute('value'))copy.setAttribute('value',safe(source.getAttribute('value')));
  if(editable&&!labelledButton){
   Object.defineProperty(copy,'value',{get(){if(active)active.valueDependent=true;return '';}});
   for(const key of ['selectedOptions','selectedIndex'])Object.defineProperty(copy,key,{get(){if(active)active.valueDependent=true;return key==='selectedIndex'?-1:[];}});
   const get=copy.getAttribute.bind(copy);
   copy.getAttribute=key=>{if(valueAttributes.has(key)){if(active)active.valueDependent=true;return null;}return get(key);};
  }
  if(!(source.isContentEditable||(source.hasAttribute('contenteditable')&&source.getAttribute('contenteditable')!=='false')))for(const child of source.tagName==='SLOT'?(source.assignedNodes?.({flatten:true})?.length?source.assignedNodes({flatten:true}):source.childNodes):source.shadowRoot?[]:source.childNodes){const next=clone(child,depth+1);if(next)copy.append(next);}
  else Object.defineProperty(copy,'textContent',{get(){if(active)active.valueDependent=true;return '';}});
  if(source.shadowRoot){for(const child of source.shadowRoot.childNodes){const next=clone(child,depth+1);if(next)copy.append(next);}}
  return copy;
 }
 const root=clone(document.documentElement);projected.replaceChild(root,projected.documentElement);
 function sourceReferences(element){
  const scope=element.getRootNode();
  return ['aria-labelledby','aria-owns'].flatMap(key=>(element.getAttribute(key)||'').split(/\s+/).filter(Boolean).map(id=>scope.getElementById?.(id)).filter(Boolean));
 }
 // A private referenced label must not silently fall back to an ordinary name.
 const checked=new WeakSet();
 function privateReference(source,seen=new Set(),depth=0){
  if(policy.secret(source)||tainted.has(source))return true;
  if(depth>64)return true;
  if(seen.has(source)||checked.has(source))return false;
  seen.add(source);
  // Flattened composed trees cannot preserve duplicate ID reference scopes.
  if(source.getRootNode()!==document&&(source.hasAttribute('aria-labelledby')||source.hasAttribute('aria-owns'))){tainted.add(source);return true;}
  if(sourceReferences(source).some(ref=>privateReference(ref,seen,depth+1))){tainted.add(source);return true;}
  checked.add(source);return false;
 }
 for(const source of publicSources)privateReference(source);

 function style(copy,pseudo){
  const source=originalByClone.get(copy);if(!source||secretNodes.has(source))return {getPropertyValue:key=>key==='display'?'none':''};
  let cache=styles.get(source);if(!cache){cache=new Map();styles.set(source,cache);}
  const key=pseudo||'';if(!cache.has(key)){
   if(++styleReads>maximumStyles)throw Error('projectionLimit');
   const original=document.defaultView.getComputedStyle(source,pseudo);
   cache.set(key,{display:source.tagName==='BR'?'block':original.display,visibility:original.visibility,content:pseudo?safe(original.content):''});
  }
  const values=cache.get(key);return {getPropertyValue:key=>values[key]||''};
 }
 return {nodes, name(element){
  if(policy.secret(element)||tainted.has(element))return {supported:false,reason:'privateName'};
  const copy=byOriginal.get(element);if(!copy)return {supported:false,reason:'projectionUnavailable'};
  active={valueDependent:false};
  try{
   const raw=computeAccessibleName(copy,{getComputedStyle:style,computedStyleSupportsPseudoElements:!document.defaultView.navigator.userAgent.includes('jsdom')});
   const value=safe(raw).replace(/\s+/g,' ').trim();
   if(active.valueDependent)return {supported:false,reason:'editableValueName'};
   if(value!==raw.replace(/\s+/g,' ').trim())return {supported:false,reason:'privateName'};
   if(value.length>256)return {supported:false,reason:'nameLimit'};
   return {supported:true,value};
  }finally{active=undefined;}
 }};
}
