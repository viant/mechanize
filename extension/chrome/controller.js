// Controller authority is ephemeral, document-bound and separate from target access.
globalThis.MechanizeController = {
  install(chrome, native) {
    let origins = new Set(), policyState='unavailable', policyFence=null;
    const sessions = new Map(), pending = new Map(), refusals = new Map();
    const localhostPatterns=new Set(['localhost:*','http://localhost:*','https://localhost:*']);
    const exactOrigin=value=>{try{const u=new URL(value);return typeof value==='string'&&value.length<=512&&u.origin===value&&!u.username&&!u.password&&(u.protocol==='https:'||u.protocol==='http:'&&['localhost','127.0.0.1'].includes(u.hostname));}catch{return false;}};
    const policyOrigin=value=>localhostPatterns.has(value)||exactOrigin(value);
    const originAllowed=value=>{
      if(!exactOrigin(value))return false;
      const u=new URL(value);
      return [...origins].some(pattern=>pattern===value||localhostPatterns.has(pattern)&&u.hostname==='localhost'&&(!u.port||Number(u.port)>=1&&Number(u.port)<=65535)&&(pattern==='localhost:*'||pattern===u.protocol+'//localhost:*'));
    };
    const exact = (v, keys) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join() === keys.sort().join();
    const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
    // Client negotiation metadata is validated here and never forwarded into
    // the native authority request, whose closed schema has no such fields.
    const metadata = m => !Object.hasOwn(m,'params') ||
      m.operation === 'tools/list' && exact(m.params,[]) ||
      m.operation === 'initialize' && exact(m.params,['protocolVersion','capabilities','clientInfo']) &&
      typeof m.params.protocolVersion === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(m.params.protocolVersion) &&
      object(m.params.capabilities) && object(m.params.clientInfo) &&
      Object.keys(m.params.clientInfo).every(k=>['name','version','title'].includes(k)) &&
      ['name','version'].every(k=>typeof m.params.clientInfo[k]==='string' && m.params.clientInfo[k].length>0 && m.params.clientInfo[k].length<=128) &&
      (!Object.hasOwn(m.params.clientInfo,'title') || typeof m.params.clientInfo.title==='string' && m.params.clientInfo.title.length<=128);
    const emit = (p, v) => { try { p.postMessage(v); } catch {} };
    const resultLimit=12*1024*1024,imageLimit=8*1024*1024,chunkBytes=96*1024;
    let reservedResultBytes=0;
    const releaseResult=p=>{if(p.assembly){const a=p.assembly;if(!a.finalizing&&a.reserved){reservedResultBytes-=a.totalBytes;a.reserved=false;}p.assembly=null;}};
    const finishResult=(id,p,error,result)=>{
      if(pending.get(id)!==p)return;
      pending.delete(id);clearTimeout(p.timer);releaseResult(p);
      const s=sessions.get(p.session);if(!s)return;
      emit(s.port,{type:'result',requestId:p.requestId,...(error?{error,...(p.operation==='tools/call'?{dispatchState:'unknown'}:{})}:{result})});
    };
    const decodeBase64=(data,max)=>{
      if(typeof data!=='string'||!data.length||data.length>4*Math.ceil(max/3)||data.length%4||/[^A-Za-z0-9+/=]/.test(data))throw Error();
      const binary=atob(data);if(binary.length>max||btoa(binary)!==data)throw Error();
      return Uint8Array.from(binary,x=>x.charCodeAt(0));
    };
    const annotations=value=>object(value)&&Object.keys(value).every(k=>['audience','priority','lastModified'].includes(k))&&
      (!Object.hasOwn(value,'audience')||Array.isArray(value.audience)&&value.audience.length<=2&&value.audience.every(role=>role==='user'||role==='assistant'))&&
      (!Object.hasOwn(value,'priority')||typeof value.priority==='number'&&Number.isFinite(value.priority)&&value.priority>=0&&value.priority<=1)&&
      (!Object.hasOwn(value,'lastModified')||typeof value.lastModified==='string'&&value.lastModified.length<=64&&/^\d{4}-\d{2}-\d{2}T/.test(value.lastModified)&&Number.isFinite(Date.parse(value.lastModified)));
    const toolResult=value=>{
      if(!object(value)||Object.keys(value).some(k=>!['content','structuredContent','isError'].includes(k))||!Array.isArray(value.content)||value.content.length>32||Object.hasOwn(value,'structuredContent')&&!object(value.structuredContent)||Object.hasOwn(value,'isError')&&typeof value.isError!=='boolean')return false;
      let bytes=0;
      try{for(const block of value.content){
        if(!object(block)||Object.hasOwn(block,'annotations')&&!annotations(block.annotations))return false;
        if(block.type==='text'){if(!exact(block,['type','text',...(Object.hasOwn(block,'annotations')?['annotations']:[])])||typeof block.text!=='string')return false;}
        else if(block.type==='image'){if(!exact(block,['type','data','mimeType',...(Object.hasOwn(block,'annotations')?['annotations']:[])])||!['image/png','image/jpeg','image/webp','image/gif'].includes(block.mimeType))return false;bytes+=decodeBase64(block.data,imageLimit).length;if(bytes>imageLimit)return false;}
        else return false;
      }
      return new TextEncoder().encode(JSON.stringify(value)).length<=resultLimit;
      }catch{return false;}
    };
    const currentResult=(p,s,m)=>sessions.get(p.session)===s&&s?.approved&&Date.now()<p.deadline&&policyState==='ready'&&originAllowed(s.origin)&&
      ['brokerEpoch','channelEpoch','scopeHash'].every(k=>native.binding()?.[k]===s.binding[k]&&(!m||m[k]===s.binding[k]));
    const completeChunks=async(id,p,s)=>{
      const a=p.assembly;
      try{
        const bytes=new Uint8Array(a.totalBytes);let offset=0;for(const part of a.parts){bytes.set(part,offset);offset+=part.length;}a.parts=[];
        const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),x=>x.toString(16).padStart(2,'0')).join('');
        if(pending.get(id)!==p)return;
        if(hash!==a.sha256||!currentResult(p,s)||!await live(s)||pending.get(id)!==p||!currentResult(p,s))throw Error();
        const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
        if(!toolResult(value)||!currentResult(p,s))throw Error();
        finishResult(id,p,null,value);
      }catch{finishResult(id,p,Date.now()>=p.deadline?'resultTransferTimeout':'resultTransferInvalid');}
      finally{if(a.reserved){reservedResultBytes-=a.totalBytes;a.reserved=false;}a.parts=[];}
    };
    const receiveChunk=m=>{
      const p=pending.get(m.requestId);if(!p)return true;
      const s=sessions.get(p.session);
      try{
        if(p.operation!=='tools/call'||!exact(m,['type','requestId','sessionId','brokerEpoch','channelEpoch','scopeHash','deadlineUnixMs','sequence','count','totalBytes','sha256','data'])||!currentResult(p,s,m)||m.sessionId!==p.session||m.deadlineUnixMs!==p.deadline||!Number.isSafeInteger(m.sequence)||m.sequence<0||!Number.isSafeInteger(m.count)||m.count<1||m.count>128||!Number.isSafeInteger(m.totalBytes)||m.totalBytes<1||m.totalBytes>resultLimit||m.count!==Math.ceil(m.totalBytes/chunkBytes)||typeof m.sha256!=='string'||!/^[a-f0-9]{64}$/.test(m.sha256)||new TextEncoder().encode(JSON.stringify(m)).length>192*1024)throw Error();
        if(!p.assembly){if(m.sequence!==0)throw Error();if(reservedResultBytes+m.totalBytes>2*resultLimit){finishResult(m.requestId,p,'resultTransferTooLarge');return true;}reservedResultBytes+=m.totalBytes;p.assembly={count:m.count,totalBytes:m.totalBytes,sha256:m.sha256,parts:[],sequence:0,finalizing:false,reserved:true};}
        const a=p.assembly;
        if(a.finalizing||m.sequence!==a.sequence||m.count!==a.count||m.totalBytes!==a.totalBytes||m.sha256!==a.sha256)throw Error();
        const part=decodeBase64(m.data,chunkBytes),expected=Math.min(chunkBytes,m.totalBytes-m.sequence*chunkBytes);
        if(expected<=0||part.length!==expected)throw Error();a.parts.push(part);a.sequence++;
        if(a.sequence===a.count){a.finalizing=true;void completeChunks(m.requestId,p,s);}
      }catch{finishResult(m.requestId,p,Date.now()>=p.deadline?'resultTransferTimeout':'resultTransferInvalid');}
      return true;
    };
    const revoke = id => {
      const s = sessions.get(id); if (!s) return;
      sessions.delete(id); clearTimeout(s.expiry);
      try { if (native.binding()) native.send({type:"controllerClosed",sessionId:id,...native.binding()}); } catch {}
      for (const [key, p] of pending) if (p.session === id) { clearTimeout(p.timer); releaseResult(p); pending.delete(key); }
      try { s.port.disconnect(); } catch {}
    };
    const live = async s => {
      const f = await chrome.webNavigation.getFrame({tabId:s.tabId, frameId:0});
      const binding=native.binding();
      return binding && ['brokerEpoch','channelEpoch','scopeHash'].every(k=>binding[k]===s.binding[k]) && policyState==='ready' && originAllowed(s.origin) && f && f.documentId === s.documentId && new URL(f.url).origin === s.origin;
    };
    chrome.runtime.onConnectExternal?.addListener(p => {
      const sender = p.sender;
      // Chrome marks these fields optional in MessageSender. Absence cannot
      // establish authority; report only closed reasons and field presence.
      const senderPresence={origin:typeof sender?.origin==='string',frameId:Number.isInteger(sender?.frameId),tabId:Number.isInteger(sender?.tab?.id),documentId:typeof sender?.documentId==='string'};
      const refuse=(code,stage='senderQualification')=>{
        // Allow queued port messages to reach the receiver before closing.
        // Keep only this denied notification lane alive briefly, with no session
        // or native authority. A consumed diagnostic can be acknowledged early.
        if(refusals.size>=32){try{p.disconnect();}catch{}return;}
        let closed=false,timer;
        const finish=()=>{if(closed)return;closed=true;clearTimeout(timer);refusals.delete(p);try{p.disconnect();}catch{}};
        timer=setTimeout(finish,1000);refusals.set(p,finish);
        p.onMessage.addListener(m=>{if(exact(m,['type'])&&m.type==='setupRefusedAck')finish();});
        p.onDisconnect.addListener(()=>{closed=true;clearTimeout(timer);refusals.delete(p);});
        emit(p,{type:'setupRefused',stage,code,senderPresence});
      };
      let origin;
      try { const u=new URL(sender?.url);if(u.username||u.password)throw Error();origin = u.origin; } catch { refuse('senderURLInvalid'); return; }
      if(p.name!=='mechanize-controller-v1'){refuse('controllerPortNameInvalid');return;}
      if(policyState!=='ready'){refuse({unavailable:'controllerPolicyUnavailable',disabled:'controllerPolicyDisabled',invalid:'controllerPolicyInvalid'}[policyState],'policyQualification');return;}
      if(!originAllowed(origin)){refuse('controllerOriginDenied');return;}
      if(Object.values(senderPresence).some(present=>!present)){refuse('senderMetadataUnavailable');return;}
      if(sender.origin!==origin){refuse('senderOriginMismatch');return;}
      if(sender.frameId!==0){refuse('senderFrameDenied');return;}
      if(sender.tab.id<0){refuse('senderTabInvalid');return;}
      if(!sender.documentId||sender.documentId.length>128){refuse('senderDocumentInvalid');return;}
      if(sessions.size>=8){refuse('controllerCapacity');return;}
      const binding = native.binding();
      if(!binding){refuse('nativeChannelUnavailable','nativeQualification');return;}
      const id = crypto.randomUUID();
      const s = {port:p, binding:{...binding}, origin, tabId:sender.tab.id, documentId:sender.documentId, approved:false, seen:new Set(), tools:new Set()};
      sessions.set(id,s);
      s.expiry = setTimeout(() => revoke(id), 300000);
      p.onDisconnect.addListener(() => { clearTimeout(s.expiry); revoke(id); });
      emit(p,{type:'approvalRequired'});
      native.send({type:'controllerOpen',sessionId:id,origin,documentId:s.documentId,tabId:s.tabId,...binding});
      p.onMessage.addListener(async m => {
        if (sessions.get(id) !== s || !s.approved || !exact(m,['type','requestId','operation','deadlineUnixMs',...(m?.operation==='tools/call' || m && ['initialize','tools/list'].includes(m.operation) && Object.hasOwn(m,'params') ? ['params'] : [])]) ||
            m.type !== 'request' || !['connection.status','tools.list','browser.inventory.summary','tools/list','tools/call','initialize'].includes(m.operation) || typeof m.requestId !== 'string' || !/^[A-Za-z0-9._:-]{1,64}$/.test(m.requestId) ||
            s.seen.has(m.requestId) || s.seen.size >= 128 || pending.size >= 16 || !Number.isSafeInteger(m.deadlineUnixMs) || m.deadlineUnixMs <= Date.now() || m.deadlineUnixMs > Date.now()+10000) { revoke(id); return; }
        if (new TextEncoder().encode(JSON.stringify(m)).length>65536 || m.operation!=='tools/call' && !metadata(m) || m.operation==='tools/call' && (!exact(m.params,['name','arguments']) || !s.tools.has(m.params.name) || !m.params.arguments || typeof m.params.arguments!=='object' || Array.isArray(m.params.arguments) || new TextEncoder().encode(JSON.stringify(m.params.arguments)).length>49152)) {revoke(id);return;}
        s.seen.add(m.requestId);
        try {
          if (!await live(s) || sessions.get(id) !== s) { revoke(id); return; }
          const binding = native.binding();
          if (!binding) { revoke(id); return; }
          const requestId = crypto.randomUUID();
          const timer = setTimeout(() => { const held=pending.get(requestId);if(held)finishResult(requestId,held,m.operation==='tools/call'?'resultTransferTimeout':'deadlineExceeded'); }, Math.max(1,m.deadlineUnixMs-Date.now()));
          pending.set(requestId,{session:id, requestId:m.requestId, operation:m.operation, timer, deadline:m.deadlineUnixMs});
          native.send({type:'controllerRequest',requestId,operation:m.operation,deadlineUnixMs:m.deadlineUnixMs,origin,documentId:s.documentId,sessionId:id,...(m.operation==='tools/call'?{params:m.params}:{}),...binding});
        } catch { revoke(id); }
      });
    });
    chrome.webNavigation.onCommitted.addListener(e => { for (const [id,s] of sessions) if (e.tabId === s.tabId && e.frameId === 0) revoke(id); });
    chrome.tabs.onRemoved.addListener(tabId => { for (const [id,s] of sessions) if (s.tabId === tabId) revoke(id); });
    return {
      fence: () => native.binding(),
      reset() { origins = new Set(); policyState='unavailable'; policyFence=null; for (const id of [...sessions.keys()]) revoke(id); },
      receive(m) {
        if (['controllerPolicy','controllerApproval','controllerRevocation'].includes(m?.type)) {
          const b = native.binding();
          if (!b || ['brokerEpoch','channelEpoch','scopeHash'].some(k=>m[k]!==b[k])) return true;
          if (m.type === 'controllerPolicy') {
            const valid=exact(m,['type','enabled','origins','brokerEpoch','channelEpoch','scopeHash']) && typeof m.enabled === 'boolean' && Array.isArray(m.origins) && m.origins.length <= 20 && m.origins.every(policyOrigin);
            const nextState=valid?(m.enabled?'ready':'disabled'):'invalid';
            const nextOrigins=new Set(valid&&m.enabled?m.origins:[]);
            const nextFence=JSON.stringify([b.brokerEpoch,b.channelEpoch,b.scopeHash]);
            // Identical policy synchronization is not a new authorization or
            // revocation. Preserve the original bounded document-session timer.
            if(valid&&policyFence===nextFence&&policyState===nextState&&origins.size===nextOrigins.size&&[...origins].every(o=>nextOrigins.has(o)))return true;
            for (const id of [...sessions.keys()]) revoke(id);
            origins=nextOrigins;policyState=nextState;policyFence=valid?nextFence:null;
          } else if (m.type === 'controllerRevocation') revoke(m.sessionId);
          else {
            const s = sessions.get(m.sessionId);
            if (s && exact(m,['type','sessionId','brokerEpoch','channelEpoch','scopeHash'])) {
              live(s).then(valid=>{if (valid && sessions.get(m.sessionId)===s) {s.approved=true;emit(s.port,{type:'approved',conversationId:m.sessionId});}else revoke(m.sessionId);}).catch(()=>revoke(m.sessionId));
            }
          }
          return true;
        }
        if(m?.type==='controllerResultChunk')return receiveChunk(m);
        if (m?.type !== 'controllerResult') return false;
        const p = pending.get(m.requestId); if (!p) return true;
        if(p.assembly){finishResult(m.requestId,p,Date.now()>=p.deadline?'resultTransferTimeout':'resultTransferInvalid');return true;}
        if(Date.now()>=p.deadline){finishResult(m.requestId,p,p.operation==='tools/call'?'resultTransferTimeout':'deadlineExceeded');return true;}
        pending.delete(m.requestId); clearTimeout(p.timer);
        const s = sessions.get(p.session);
        if (!s || Date.now() >= p.deadline) return true;
        if(!currentResult(p,s)){emit(s.port,{type:'result',requestId:p.requestId,error:'resultTransferInvalid',...(p.operation==='tools/call'?{dispatchState:'unknown'}:{})});return true;}
        if(exact(m,['type','requestId','error'])){const error=['unavailable','resultTooLarge','resultTransferInvalid','resultTransferTimeout','resultTransferTooLarge'].includes(m.error)?m.error:'unavailable';emit(s.port,{type:'result',requestId:p.requestId,error,...(p.operation==='tools/call'?{dispatchState:'unknown'}:{})});return true;}
        // Never expose arbitrary native payloads to a website.
        if (p.operation==='initialize' && exact(m,['type','requestId','result']) && exact(m.result,['protocolVersion','capabilities','serverInfo']) && typeof m.result.protocolVersion==='string' && /^\d{4}-\d{2}-\d{2}$/.test(m.result.protocolVersion) && exact(m.result.capabilities,['tools']) && exact(m.result.serverInfo,['name','version']) && m.result.serverInfo.name==='mechanize' && typeof m.result.serverInfo.version==='string' && m.result.serverInfo.version.length<=128) {emit(s.port,{type:'result',requestId:p.requestId,result:m.result});return true;}
        if (p.operation==='tools/list' && exact(m,['type','requestId','result']) && exact(m.result,['tools']) && Array.isArray(m.result.tools) && m.result.tools.length<=64 && m.result.tools.every(t=>t && typeof t.name==='string' && (/^mechanize_[a-z_]{1,64}$/.test(t.name) || ['skill_list','skill_get'].includes(t.name)) && t.inputSchema && t.inputSchema.type==='object') && new TextEncoder().encode(JSON.stringify(m.result)).length<=192*1024) {
          s.tools=new Set(m.result.tools.map(t=>t.name));emit(s.port,{type:'result',requestId:p.requestId,result:m.result});return true;
        }
        if (p.operation==='tools/call' && exact(m,['type','requestId','result']) && toolResult(m.result) && new TextEncoder().encode(JSON.stringify(m.result)).length<=192*1024) {emit(s.port,{type:'result',requestId:p.requestId,result:m.result});return true;}
        if (p.operation === 'connection.status' && exact(m,['type','requestId','ready']) && typeof m.ready === 'boolean') emit(s.port,{type:'result',requestId:p.requestId,ready:m.ready});
        else if (p.operation === 'tools.list' && exact(m,['type','requestId','tools']) && Array.isArray(m.tools) && m.tools.length === 3 && m.tools.every((t,i)=>t===['connection.status','tools.list','browser.inventory.summary'][i])) emit(s.port,{type:'result',requestId:p.requestId,tools:[...m.tools]});
        else if (p.operation === 'browser.inventory.summary' && exact(m,['type','requestId','documentCount','pendingCount','unknownCount']) && ['documentCount','pendingCount','unknownCount'].every(k=>Number.isSafeInteger(m[k]) && m[k]>=0 && m[k]<=65536)) emit(s.port,{type:'result',requestId:p.requestId,documentCount:m.documentCount,pendingCount:m.pendingCount,unknownCount:m.unknownCount});
        else emit(s.port,{type:'result',requestId:p.requestId,error:'unavailable',...(p.operation==='tools/call'?{dispatchState:'unknown'}:{})});
        return true;
      }
    };
  }
};
