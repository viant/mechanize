// Browser-side MCP Transport interface. Bundle this source into the controller
// shell; no local HTTP endpoint, credential or native-host name is configured.
export class MechanizeExtensionTransport {
  constructor({extensionId, runtime = globalThis.chrome?.runtime, requestTimeoutMs = 9000}) {
    if (!/^[a-p]{32}$/.test(extensionId) || !runtime?.connect || !Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 100 || requestTimeoutMs > 9000) throw Error('Invalid Mechanize extension transport configuration');
    this.extensionId=extensionId;this.runtime=runtime;this.timeout=requestTimeoutMs;this.pending=new Map();this.closed=false;this.queue=Promise.resolve();this.queued=0;
  }
  async start() {
    if (this.port || this.closed) throw Error('Transport already started or closed');
    this.port=this.runtime.connect(this.extensionId,{name:'mechanize-controller-v1'});
    this.approval=new Promise((resolve,reject)=>{this.approve=resolve;this.rejectApproval=reject;});
    this.approval.catch(()=>{});
    this.port.onMessage.addListener(m=>{
      if (m?.type==='approvalRequired') {this.onapprovalrequired?.();return;}
      if (m?.type==='approved' && typeof m.conversationId==='string') {this.conversationId=m.conversationId;this.approve();return;}
      if (m?.type!=='result') return;
      const p=this.pending.get(m.requestId);if (!p) return;
      this.pending.delete(m.requestId);clearTimeout(p.timer);
      if (m.result) p.resolve(m.result);else p.reject(Error('Mechanize request unavailable; an operation may require reconciliation'));
    });
    this.port.onDisconnect.addListener(()=>this.finish());
  }
  async request(method, params) {
    if(this.closed || this.queued>=16) throw Error('Mechanize transport queue unavailable');
    this.queued++;
    const next=this.queue.then(()=>this.performRequest(method,params));
    this.queue=next.catch(()=>{});
    try{return await next;}finally{this.queued--;}
  }
  async performRequest(method, params) {
    await this.approval;
    if (this.closed || this.pending.size>=16) throw Error('Mechanize transport unavailable');
    const id=crypto.randomUUID();
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{this.pending.delete(id);reject(Error('Mechanize deadline exceeded; do not replay an uncertain operation'));},this.timeout);
      this.pending.set(id,{resolve,reject,timer});
      try {this.port.postMessage({type:'request',requestId:id,operation:method,deadlineUnixMs:Date.now()+this.timeout,...(method==='tools/call'?{params}:{})});}
      catch {clearTimeout(timer);this.pending.delete(id);reject(Error('Mechanize transport unavailable'));}
    });
  }
  async send(message) {
    if (!message || message.jsonrpc!=='2.0') throw Error('JSON-RPC 2.0 message required');
    // An SDK abort closes this conversation instead of allowing queued or
    // already-started work to outlive its transport. Use the canonical
    // operation_cancel tool when only one automation should be stopped.
    if (message.method==='notifications/cancelled' && message.id===undefined) {await this.close();return;}
    if (message.method==='notifications/initialized' && message.id===undefined) return;
    if (!['initialize','tools/list','tools/call'].includes(message.method) || message.id===undefined) {
      if (message.id!==undefined) this.onmessage?.({jsonrpc:'2.0',id:message.id,error:{code:-32601,message:'Method unavailable'}});
      return;
    }
    try {
      let result;
      if (message.method==='initialize') {
        // A successful local negotiation requires an authorized round-trip to
        // the actual canonical host catalog; approval is never synthesized.
        result=await this.request('initialize');
        await this.request('tools/list');
      } else result=await this.request(message.method,message.method==='tools/call'?{name:message.params?.name,arguments:message.params?.arguments ?? {}}:undefined);
      this.onmessage?.({jsonrpc:'2.0',id:message.id,result});
    } catch {
      this.onmessage?.({jsonrpc:'2.0',id:message.id,error:{code:-32000,message:'Mechanize transport unavailable; inspect operation status before retrying'}});
    }
  }
  finish() {
    if (this.closed) return;
    this.closed=true;this.rejectApproval?.(Error('Mechanize connection closed'));
    for (const p of this.pending.values()){clearTimeout(p.timer);p.reject(Error('Mechanize connection closed; do not replay an uncertain operation'));}
    this.pending.clear();this.onclose?.();
  }
  async close() {try {this.port?.disconnect();}finally{this.finish();}}
}
