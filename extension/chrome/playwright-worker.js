// Private native-port adapter. No runtime/page message entry point is installed.
globalThis.MechanizePlaywrightWorker = (() => {
  const prefix = 'playwrightAttempt:';
  const PRIVATE_BYTES=512*1024;
  const JOURNAL_KEY='mechanizePlaywrightJournalV1', JOURNAL_BYTES=512*1024, RECORD_BYTES=4096, JOURNAL_CAPACITY=512;
  const id = value => typeof value === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(value);
  const sameIdentity = (a,b) => a && b && ['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'].every(k => a[k] === b[k]);
  const closed = (v,required,optional=[]) => v && typeof v === 'object' && !Array.isArray(v) && required.every(k=>Object.hasOwn(v,k)) && Object.keys(v).every(k=>required.includes(k)||optional.includes(k));
  const freeze = value => { if(value && typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value; };
  const fail = code => Object.assign(new Error('Private Playwright relay denied'),{code});
  const input = (method,params) => method==='Input.insertText'||method==='Input.dispatchKeyEvent'&&['rawKeyDown','keyDown','char'].includes(params?.type)||method==='Input.dispatchMouseEvent'&&params?.type==='mousePressed';
  function create(api,hooks) {
    let active=null, lane=Promise.resolve();
    const current=async binding=>{
      let timer;
      try{return await Promise.race([Promise.resolve().then(()=>hooks.current(binding)),new Promise(resolve=>{timer=setTimeout(()=>resolve(false),Math.max(0,binding.command.deadlineUnixMs-Date.now()));})]);}
      catch{return false;}finally{clearTimeout(timer);}
    };
    const receiptCurrent=async held=>hooks.port()===held.originalPort&&Date.now()<held.command.deadlineUnixMs&&await (hooks.receiptCurrent?hooks.receiptCurrent(held):current(held));
    // Revokes all further DOM/CDP commands without prematurely deciding the
    // original receipt. This slot is bounded by the original execution timer.
    // Scoped relay close rejects new commands; it does not detach CDP or cancel
    // an already issued original input ACK in the transport.
    const finalizationOnly=held=>{held.receiptOnly=true;held.closed=true;held.unsubscribe?.();held.session?.close();};
    const relay=MechanizePlaywrightRelay.create(api,current);
    const canonical=value=>JSON.stringify(value&&typeof value==='object'?Array.isArray(value)?value.map(v=>JSON.parse(canonical(v))):Object.fromEntries(Object.keys(value).sort().map(k=>[k,JSON.parse(canonical(value[k]))])):value);
    const copy=value=>JSON.parse(JSON.stringify(value));
    const codes=new Set(('AttemptCapacity AttemptConflict ChildExited ChildLaunch ExecutionRequired IntentRequired RuntimeQualification AttemptReplay AuthorityChanged AuthorityRequired AuthorityDenied BindingChanged BindingDenied BindingRequired Busy CDPDenied CommandDenied Deadline DocumentChanged EnvelopeDenied FingerprintMismatch FrameTooLarge HostDeadline HostDenied HostDisconnected HostRequired InputReplay InputSequenceDenied InputUncertain Interrupted IPCFrame IPCProtocol IPCWrite LocatorDenied OriginDenied PrivateDOMDenied ReadDenied ReadInputDenied ReadTooLarge ReceiptCapacity ReceiptDenied ReceiptFinal ReceiptPending ReceiptUncertain RedactionDenied RelayDenied RequestReplay TargetChanged TargetDenied TargetUnpinned Unavailable Uncertain JournalInvalid').split(' ').map(v=>'playwright'+v));
    function validRecord(record){
      const identity=record?.identity,lease=record?.controlLease,r=record?.receipt;
      if(!closed(record,['phase','requestId','attemptId','identity','controlLease','brokerEpoch','channelEpoch','scopeHash','fingerprintSHA256'],['receipt'])||!id(record.attemptId)||!id(record.requestId)||!['ready','input','done'].includes(record.phase)||
        !closed(identity,['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'])||!['profileChannel','browserInstance','documentId'].every(k=>id(identity[k]))||!Number.isSafeInteger(identity.tabId)||identity.tabId<1||identity.frameId!==0||!Number.isSafeInteger(identity.documentGeneration)||identity.documentGeneration<1||
        !closed(lease,['id','generation'])||!id(lease.id)||!Number.isSafeInteger(lease.generation)||lease.generation<1||!['brokerEpoch','channelEpoch'].every(k=>id(record[k]))||!/^([a-f0-9]{64})$/.test(record.scopeHash)||!/^([a-f0-9]{64})$/.test(record.fingerprintSHA256)||(record.phase==='done')!==Boolean(r)||new TextEncoder().encode(JSON.stringify(record)).length>RECORD_BYTES)throw fail('playwrightJournalInvalid');
      if(r&&(!closed(r,['requestId','attemptId','identity','controlLease','fingerprintVersion','fingerprintSHA256','dispatchState','effectState'],['error','inputSemantics'])||r.requestId!==record.requestId||r.attemptId!==record.attemptId||!sameIdentity(r.identity,identity)||canonical(r.identity)!==canonical(identity)||canonical(r.controlLease)!==canonical(lease)||r.fingerprintVersion!==2||r.fingerprintSHA256!==record.fingerprintSHA256||!['notDispatched','dispatched','unknown'].includes(r.dispatchState)||r.effectState!==({notDispatched:'none',dispatched:'unverified',unknown:'unknown'})[r.dispatchState]||r.inputSemantics!==undefined&&r.inputSemantics!=='Local Playwright over scoped extension CDP'||r.error&&(!codes.has(r.error.code)||canonical(r.error)!==canonical(MechanizeProtocol.error(r.error.code,'Local Playwright receipt requires reconciliation',r.dispatchState)))))throw fail('playwrightJournalInvalid');
      return record;
    }
    const core=record=>{const result={...record};delete result.phase;delete result.receipt;return canonical(result);};
    const advances=(before,after)=>core(before)===core(after)&&(canonical(before)===canonical(after)||before.phase!=='done'&&['ready','input','done'].indexOf(after.phase)>['ready','input','done'].indexOf(before.phase));
    function decodeJournal(value){
      if(value===undefined)return {version:1,records:{}};
      if(!closed(value,['version','records'])||value.version!==1||!value.records||typeof value.records!=='object'||Array.isArray(value.records)||Object.keys(value.records).length>JOURNAL_CAPACITY||new TextEncoder().encode(JSON.stringify(value)).length>JOURNAL_BYTES)throw fail('playwrightJournalInvalid');
      for(const [key,record] of Object.entries(value.records))if(validRecord(record).attemptId!==key)throw fail('playwrightJournalInvalid');
      return copy(value);
    }
    let journalReady, journalLane=Promise.resolve();
    async function persistJournal(value){
      if(new TextEncoder().encode(JSON.stringify(value)).length>JOURNAL_BYTES)throw fail('playwrightReceiptCapacity');
      try{await api.storage.local.set({[JOURNAL_KEY]:value});}catch{ /* Exact readback below is the only lost-ack recovery. */ }
      if(canonical((await api.storage.local.get(JOURNAL_KEY))[JOURNAL_KEY])!==canonical(value))throw fail('playwrightJournalInvalid');
    }
    function initializeJournal(){
      return journalReady ||= (async()=>{
        if(typeof api.storage.local?.setAccessLevel!=='function')throw fail('playwrightJournalInvalid');
        await api.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
        const journal=decodeJournal((await api.storage.local.get(JOURNAL_KEY))[JOURNAL_KEY]),session=await api.storage.session.get(null);let changed=false;
        for(const [key,value] of Object.entries(session))if(key.startsWith(prefix)){
          const record=validRecord(value);if(key!==prefix+record.attemptId)throw fail('playwrightJournalInvalid');
          const retained=journal.records[record.attemptId];
          if(retained){if(!advances(record,retained))throw fail('playwrightJournalInvalid');}
          else{if(Object.keys(journal.records).length>=JOURNAL_CAPACITY)throw fail('playwrightReceiptCapacity');journal.records[record.attemptId]=copy(record);changed=true;}
        }
        if(changed)await persistJournal(journal);
      })();
    }
    async function journalSnapshot(){
      await initializeJournal();
      const journal=decodeJournal((await api.storage.local.get(JOURNAL_KEY))[JOURNAL_KEY]);
      return Object.fromEntries(Object.values(journal.records).map(record=>[prefix+record.attemptId,record]));
    }
    const write=record=>{
      const task=journalLane.then(async()=>{
        validRecord(record);await initializeJournal();const journal=decodeJournal((await api.storage.local.get(JOURNAL_KEY))[JOURNAL_KEY]),before=journal.records[record.attemptId];
        if(before&&!advances(before,record)||!before&&record.phase!=='ready')throw fail('playwrightJournalInvalid');
        if(!before&&Object.keys(journal.records).length>=JOURNAL_CAPACITY)throw fail('playwrightReceiptCapacity');
        journal.records[record.attemptId]=copy(record);await persistJournal(journal);
        // Compatibility mirror only: all authority reads use durable local data.
        await api.storage.session.set({[prefix+record.attemptId]:copy(record)});
      });journalLane=task.catch(()=>{});return task;
    };
    const receipt=(record,state,code)=>({requestId:record.requestId,attemptId:record.attemptId,identity:record.identity,controlLease:record.controlLease,fingerprintVersion:2,fingerprintSHA256:record.fingerprintSHA256,dispatchState:state,effectState:state==='unknown'?'unknown':state==='dispatched'?'unverified':'none',...(code?{error:MechanizeProtocol.error(codes.has(code)?code:'playwrightUnavailable','Local Playwright receipt requires reconciliation',state)}:{})});
    async function finish(held,closedCode) {
      held.closed=true;clearTimeout(held.timer);held.unsubscribe?.();held.session?.close();
      try {
        if(held.record&&!held.record.receipt){
          const state=held.possible?'unknown':'notDispatched';
          held.record.receipt=receipt(held.record,state,closedCode||(held.possible?'playwrightReceiptUncertain':'playwrightInterrupted'));
          held.record.phase='done';
          if(held.possible)hooks.unknown(held.command.attemptId,true,held.record||held.command);
          await write(held.record);
        }
      } finally {if(active===held){active=null;hooks.release(held);}}
    }
    async function recover() {
      const saved=await journalSnapshot();
      for(const [key,record] of Object.entries(saved)){
        if(!record.receipt){record.receipt=receipt(record,record.phase==='input'?'unknown':'notDispatched',record.phase==='input'?'playwrightReceiptUncertain':'playwrightInterrupted');record.phase='done';await write(record);}
        if(record.receipt.dispatchState==='unknown')hooks.unknown(record.attemptId,true,record);
      }
    }
    async function query(command) {
      const record=(await journalSnapshot())[prefix+command.attemptId];
      if(!record)return null;
      if(!sameIdentity(record.identity,command.identity)||['brokerEpoch','channelEpoch','scopeHash'].some(k=>record[k]!==command[k]))throw MechanizeProtocol.error('staleIdentity','Original Playwright receipt identity required');
      return {...(record.receipt||receipt(record,record.phase==='input'?'unknown':'notDispatched','playwrightReceiptPending')),requestId:command.requestId,receiptAvailable:Boolean(record.receipt)};
    }
    async function retireUnknownTarget(command,proveAbsent) {
      if(active)throw fail('playwrightBusy');
      const key=prefix+command.attemptId,record=(await journalSnapshot())[key];
      if(!record||record.phase!=='done'||record.receipt?.dispatchState!=='unknown'||record.receipt.effectState!=='unknown'||!sameIdentity(record.identity,command.identity)||canonical(record.controlLease)!==canonical(command.controlLease)||record.fingerprintSHA256!==command.fingerprintSHA256||command.fingerprintVersion!==2||record.scopeHash!==command.scopeHash)throw fail('playwrightBindingDenied');
      const before=canonical(record);await proveAbsent();
      if(active||canonical((await journalSnapshot())[key])!==before)throw fail('playwrightAuthorityChanged');
      await proveAbsent();return copy(record);
    }
    async function retireKnownSource(command,proveAbsent) {
      if(active||!command.controlLease)return false;
      const stable=(a,b)=>a&&b&&['profileChannel','browserInstance','tabId','frameId','documentId'].every(k=>a[k]===b[k]);
      const snapshot=async()=>Object.values(await journalSnapshot()).filter(record=>stable(record.identity,command.identity));
      const records=await snapshot();
      if(!records.length||records.some(record=>record.phase!=='done'||!record.receipt||record.receipt.dispatchState==='unknown'))return false;
      const own=records.some(record=>sameIdentity(record.identity,command.identity)&&['brokerEpoch','channelEpoch','scopeHash'].every(k=>record[k]===command[k])&&record.controlLease.id===command.controlLease.id&&record.controlLease.generation===command.controlLease.generation&&record.receipt.dispatchState==='dispatched');
      if(!own)return false;
      const before=canonical(records);await proveAbsent();
      if(active||canonical(await snapshot())!==before)throw fail('playwrightAuthorityChanged');
      await proveAbsent();return true;
    }
    async function exportReceipts(command,readRenderer) {
      const stableIdentity=(a,b)=>a&&b&&['profileChannel','browserInstance','tabId','frameId','documentId'].every(k=>a[k]===b[k]);
      const canonical=v=>JSON.stringify(v&&typeof v==='object'?Array.isArray(v)?v.map(x=>JSON.parse(canonical(x))):Object.fromEntries(Object.keys(v).sort().map(k=>[k,JSON.parse(canonical(v[k]))])):v);
      const retained=async()=>Object.entries(await journalSnapshot()).filter(([k,r])=>k.startsWith(prefix)&&stableIdentity(r?.identity,command.identity)).sort(([a],[b])=>a.localeCompare(b)).map(([,r])=>r);
      const records=await retained();
      if(!records.length)return readRenderer(command);
      const stamp=canonical(records),rows=[];
      for(const record of records){
        const r=record.receipt;
        if(record.phase!=='done'||!r||!['dispatched','notDispatched','unknown'].includes(r.dispatchState)||!['none','unverified','verified','unknown'].includes(r.effectState)||!/^([a-f0-9]{64})$/.test(record.fingerprintSHA256))throw MechanizeProtocol.error('receiptExportUnavailable','Exact immutable Playwright audit receipt required');
        rows.push({attemptId:record.attemptId,fingerprintVersion:2,fingerprintSHA256:record.fingerprintSHA256,dispatchState:r.dispatchState,effectState:r.effectState,...(r.error?{errorCode:'unclassified',errorDispatchState:r.dispatchState}:{})});
      }
      // A destroyed target has no renderer/recording readiness to report. Its
      // immutable UNKNOWN rows are audit data, never a NoUnknown manifest.
      if(rows.some(row=>row.dispatchState==='unknown')&&records.every(record=>record.receipt.dispatchState!=='unknown'||hooks.retiredUnknown?.(record))){
        const args=command.args,total=rows.length;
        if(args.offset>total||args.expectedRevision!==undefined&&args.expectedRevision!==total)throw MechanizeProtocol.error('receiptRevisionMismatch','Exact audit revision required');
        const receipts=rows.slice(args.offset,args.offset+args.limit),nextOffset=args.offset+receipts.length;
        return {version:2,requestId:command.requestId,identity:{...command.identity},total,revision:total,offset:args.offset,nextOffset,truncated:nextOffset<total,receipts,readiness:null};
      }
      let first,page,offset=0;
      const rendererRows=[];
      do {
        let timer;
        try{page=await Promise.race([readRenderer({...command,args:{offset,limit:64,...(first?{expectedRevision:first.revision}:{})}}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(MechanizeProtocol.error('dispatchExpired','Receipt export deadline expired')),Math.max(0,command.deadlineUnixMs-Date.now()));})]);}
        finally{clearTimeout(timer);}
        if(page?.error||page?.version!==2||!stableIdentity(page.identity,command.identity)||!Number.isSafeInteger(page.total)||page.total<0||page.total>512||page.revision!==page.total||page.offset!==offset||!Array.isArray(page.receipts)||page.receipts.length>64||page.nextOffset!==offset+page.receipts.length||page.nextOffset>page.total||page.truncated!==(page.nextOffset<page.total)||page.truncated&&page.receipts.length===0||first&&(page.total!==first.total||page.revision!==first.revision||canonical(page.readiness)!==canonical(first.readiness)))throw MechanizeProtocol.error('receiptSnapshotChanged','Exact renderer receipt snapshot required');
        first ||= page;rendererRows.push(...page.receipts);offset=page.nextOffset;
      }while(page.truncated);
      const all=[...rendererRows,...rows].sort((a,b)=>a.attemptId.localeCompare(b.attemptId)),total=all.length;
      if(total>512||new Set(all.map(r=>r.attemptId)).size!==total||canonical(await retained())!==stamp)throw MechanizeProtocol.error('receiptSnapshotChanged','Combined receipt history changed or exceeds capacity');
      const args=command.args;
      if(args.offset>total||args.expectedRevision!==undefined&&args.expectedRevision!==total)throw MechanizeProtocol.error('receiptRevisionMismatch','Combined receipt revision changed');
      const receipts=all.slice(args.offset,args.offset+args.limit),nextOffset=args.offset+receipts.length;
      return {...page,requestId:command.requestId,total,revision:total,offset:args.offset,nextOffset,truncated:nextOffset<total,receipts};
    }
    async function handle(message,originalPort) {
      let held=active;
      const response={type:'playwright.result',requestId:message?.requestId,relayId:message?.relayId};
      const post=value=>{if(new TextEncoder().encode(JSON.stringify(value)).length>PRIVATE_BYTES)throw fail('playwrightFrameTooLarge');if(hooks.port()===originalPort)originalPort.postMessage(value);};
      try {
        const extra={ 'playwright.open':['command','origin'],'playwright.send':['method','params'],'playwright.redact':['value'],'playwright.close':[],'playwright.receipt':['dispatchState','effectState'] }[message?.type];
        if(!extra||!closed(message,['type','requestId','relayId','deadlineUnixMs',...extra],message.type==='playwright.receipt'?['errorCode','inputSemantics']:message.type==='playwright.open'?['controlBadge']:[])||!id(message.requestId)||!id(message.relayId)||!Number.isSafeInteger(message.deadlineUnixMs)||message.deadlineUnixMs<=Date.now()||message.deadlineUnixMs>Date.now()+30000||new TextEncoder().encode(JSON.stringify(message)).length>(message.type==='playwright.send'?PRIVATE_BYTES:MechanizeProtocol.MAX_BYTES))throw fail('playwrightEnvelopeDenied');
        if(message.type==='playwright.open'){
          if(message.controlBadge!==undefined&&message.controlBadge!==true)throw fail('playwrightEnvelopeDenied');
          if(active)throw fail('playwrightBusy');
          const command=freeze(JSON.parse(JSON.stringify(message.command)));
          MechanizeProtocol.validate(command);
          if(!id(command.requestId)||!closed(command.identity,['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'])||!closed(command.locator,['strategy','value','exact'],['name','index','order'])||!['id','testId','role','label'].includes(command.locator.strategy)||command.locator.exact!==true||typeof command.locator.value!=='string'||!command.locator.value||command.locator.value.length>1024||command.locator.name!==undefined&&(command.locator.strategy!=='role'||typeof command.locator.name!=='string'||!command.locator.name||command.locator.name.length>1024))throw fail('playwrightCommandDenied');
          const mutation=['element.press','element.fill'].includes(command.action);
          if(!mutation&&!(command.action==='read'&&closed(command.args,['attribute'])&&command.args.attribute==='text')||command.type!==undefined||command.identity.frameId!==0||command.deadlineUnixMs!==message.deadlineUnixMs||typeof message.origin!=='string'||new URL(message.origin).origin!==message.origin)throw fail('playwrightCommandDenied');
          if(mutation&&(command.fingerprintVersion!==2||(await MechanizeFingerprint.mutationV2(command)).sha256!==command.fingerprintSHA256))throw fail('playwrightFingerprintMismatch');
          held={command,identity:command.identity,origin:message.origin,originalPort,relayId:message.relayId,closed:false,possible:false,mutation,wireRequests:new Set([message.requestId])};
          await hooks.acquire(held);
          active=held;
          if(!await current(held))throw fail('playwrightAuthorityChanged');
          if(mutation){
            const saved=await journalSnapshot(),browser=await api.storage.session.get('browserIntent:'+command.attemptId);
            if(saved[prefix+command.attemptId]||browser['browserIntent:'+command.attemptId])throw fail('playwrightAttemptReplay');
            if(Object.keys(saved).filter(k=>k.startsWith(prefix)).length>=512)throw fail('playwrightReceiptCapacity');
            held.record={phase:'ready',requestId:command.requestId,attemptId:command.attemptId,identity:command.identity,controlLease:command.controlLease,brokerEpoch:command.brokerEpoch,channelEpoch:command.channelEpoch,scopeHash:command.scopeHash,fingerprintSHA256:command.fingerprintSHA256};
            await write(held.record);
          }
          held.session=await relay.open(held,command.deadlineUnixMs);
          if(held.closed||!await current(held))throw fail('playwrightAuthorityChanged');
          held.unsubscribe=held.session.onEvent(event=>{
            if(held.closed)return;
            Promise.resolve(current(held)).then(authorized=>{if(authorized&&!held.closed)post({type:'playwright.event',relayId:held.relayId,method:event.method,params:event.params||{}});}).catch(()=>{});
          });
          held.timer=setTimeout(()=>{held.closed=true;void enqueue(()=>finish(held));},Math.max(1,command.deadlineUnixMs-Date.now()));
          let controlBadgeWindow;
          if(message.controlBadge===true){
            try {
              const tab=await api.tabs.get(command.identity.tabId);
              const window=await api.windows.get(tab.windowId);
              if(tab.id===command.identity.tabId&&Number.isSafeInteger(tab.windowId)&&window.id===tab.windowId&&window.type==='normal'&&window.state!=='minimized'&&[window.left,window.top,window.width,window.height].every(n=>Number.isFinite(n)&&Math.abs(n)<=100000)&&window.width>=120&&window.height>=48){
                controlBadgeWindow={x:window.left,y:window.top,width:window.width,height:window.height};
              }
            }catch{} // Presentation unavailable must not replay or block the action.
            if(held.closed||!await current(held))throw fail('playwrightAuthorityChanged');
          }
          post({...response,result:{opened:true,...(controlBadgeWindow?{controlBadgeWindow}:{})}});return;
        }
        if(!held||held.originalPort!==originalPort||held.relayId!==message.relayId||message.deadlineUnixMs>held.command.deadlineUnixMs)throw fail('playwrightAuthorityChanged');
        const finalizing=message.type==='playwright.receipt'||message.type==='playwright.close';
        // send() owns the fresh authority check in relay.validate immediately
        // before CDP; input/release also validate before journal/sequence changes.
        // Other boundaries retain their own gate, and every result is rechecked.
        if(finalizing?!await receiptCurrent(held):held.closed||message.type!=='playwright.send'&&!await current(held))throw fail('playwrightAuthorityChanged');
        if(held.wireRequests.has(message.requestId)||held.wireRequests.size>=4096)throw fail('playwrightRequestReplay');
        held.wireRequests.add(message.requestId);
        if(message.type==='playwright.close'){if(held.record&&!held.record.receipt&&held.possible)finalizationOnly(held);else await finish(held);post({...response,result:{closed:true}});return;}
        if(message.type==='playwright.redact'){
          if(typeof message.value!=='string'||message.value.length>32768)throw fail('playwrightRedactionDenied');
          const value=hooks.redact(message.value);
          if(typeof value!=='string'||!await current(held))throw fail('playwrightRedactionDenied');
          post({...response,result:{value}});return;
        }
        if(message.type==='playwright.receipt'){
          if(!held.record||held.record.receipt||!['notDispatched','dispatched','unknown'].includes(message.dispatchState)||!['none','unverified','unknown'].includes(message.effectState)||message.dispatchState==='notDispatched'&&held.possible||message.dispatchState==='dispatched'&&(!held.possible||held.uncertain||!held.inputAcknowledged||held.releaseRequired&&!held.releaseAcknowledged)||message.effectState!==({notDispatched:'none',dispatched:'unverified',unknown:'unknown'})[message.dispatchState]||message.errorCode!==undefined&&(!id(message.errorCode)||!message.errorCode.startsWith('playwright'))||message.inputSemantics!==undefined&&message.inputSemantics!=='Local Playwright over scoped extension CDP')throw fail('playwrightReceiptDenied');
          const result=receipt(held.record,message.dispatchState,message.errorCode);
          if(message.inputSemantics)result.inputSemantics=message.inputSemantics;
          // Acknowledgement follows durable journal completion, never precedes it.
          await write({...held.record,phase:'done',receipt:result});
          held.record={...held.record,phase:'done',receipt:result};
          hooks.unknown(held.command.attemptId,message.dispatchState==='unknown',held.record);
          if(held.receiptOnly)await finish(held);
          post({...response,result:{persisted:true}});return;
        }
        if(held.record?.receipt)throw fail('playwrightReceiptFinal');
        const priorPossible=held.possible;
        const actual=input(message.method,message.params);
        const release=message.method==='Input.dispatchMouseEvent'&&message.params?.type==='mouseReleased'||message.method==='Input.dispatchKeyEvent'&&message.params?.type==='keyUp';
        // send() always validates immediately before CDP. An additional early
        // validation is needed only before changing input journal/sequence state.
        if(actual||release)await held.session.validate(message.method,message.params,message.deadlineUnixMs);
        if(release){if(!held.possible||held.released)throw fail('playwrightInputSequenceDenied');held.released=true;}
        if(actual){
          if(!held.mutation)throw fail('playwrightReadInputDenied');
          if(held.possible)throw fail('playwrightInputReplay');
          if(held.uncertain)throw fail('playwrightInputUncertain');
          if(!held.possible){await write({...held.record,phase:'input'});held.record.phase='input';}
          if(!await current(held))throw fail('playwrightAuthorityChanged');
          held.possible=true;held.releaseRequired=Boolean(held.releaseRequired||message.method!=='Input.insertText');held.releaseAcknowledged=false;held.released=false;
        }
        let result;
        try {result=await held.session.send(message.method,message.params,message.deadlineUnixMs,actual?()=>{held.inputCrossed=true;}:undefined);}
        catch(error){if(actual){if(!priorPossible&&error?.dispatchState==='notDispatched')held.possible=false;else{held.uncertain=true;hooks.unknown(held.command.attemptId,true,held.record||held.command);}}throw error;}
        if(actual)held.inputAcknowledged=true;
        if(release)held.releaseAcknowledged=true;
        if(!await current(held)){
          // A completed original input/release may navigate its own document.
          // Acknowledge only that CDP result; subsequent commands stay denied.
          if(!(release||actual&&!held.releaseRequired)||!held.record||held.uncertain||!await receiptCurrent(held))throw fail('playwrightAuthorityChanged');
          finalizationOnly(held);
        }
        post({...response,result:result||{}});
      } catch(error) {
        const state=held?.possible?'unknown':'notDispatched';
        const code=id(error?.code)&&error.code.startsWith('playwright')?error.code:'playwrightUnavailable';
        let terminal;
        if(held&&active===held&&!held.receiptOnly){
          await finish(held,code).catch(()=>{if(held.possible)hooks.unknown(held.command.attemptId,true,held.record||held.command);});
          // Only a read-back of the exact original journal proves completion.
          // Cleanup failures must never replace its authoritative dispatch state.
          if(held.record?.receipt){try{
            const saved=(await journalSnapshot())[prefix+held.command.attemptId];
            if(saved?.phase==='done'&&JSON.stringify(saved)===JSON.stringify(held.record))terminal=saved.receipt;
          }catch{}}
        }
        post({...response,errorCode:code,dispatchState:state,...(terminal?{result:{receipt:terminal}}:{})});
      }
    }
    function enqueue(fn){const operation=lane.then(fn);lane=operation.catch(()=>{});return operation;}
    return {recover,query,exportReceipts,journalSnapshot,retireKnownSource:(command,proveAbsent)=>enqueue(()=>retireKnownSource(command,proveAbsent)),retireUnknownTarget:(command,proveAbsent)=>enqueue(()=>retireUnknownTarget(command,proveAbsent)),receive:(message,originalPort)=>enqueue(()=>handle(message,originalPort)),invalidate(predicate=()=>true,retainFinalization=false){const held=active;if(held&&predicate(held)){if(retainFinalization&&held.record&&!held.record.receipt&&held.possible)finalizationOnly(held);else{held.closed=true;held.session?.close();void enqueue(()=>finish(held));}}}};
  }
  return {create};
})();
if(typeof module!=='undefined')module.exports=globalThis.MechanizePlaywrightWorker;
