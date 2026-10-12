// Inert browser-port fixture for the actual Go controller initialization test.
const fs=require('node:fs'),vm=require('node:vm'),readline=require('node:readline');
const events={},output=value=>process.stdout.write(JSON.stringify(value)+'\n');
const event=key=>({addListener:listener=>events[key]=listener});
let bridge,binding;
const origin=process.argv[3]||'https://shell.fixture.test',policyOrigin=process.argv[4]||origin,callMode=['call','image'].includes(process.argv[2]),catalogMode=['catalog','call','image'].includes(process.argv[2]);
const chrome={runtime:{onConnectExternal:event('external')},webNavigation:{onCommitted:event('navigate'),getFrame:async()=>({url:origin+'/app',documentId:'controller-document'})},tabs:{onRemoved:event('removed')}};
const context=vm.createContext({URL,Date,TextEncoder,TextDecoder,atob,btoa,crypto:require('node:crypto').webcrypto,setTimeout,clearTimeout});
let receiverSource=fs.readFileSync(require('node:path').join(__dirname,'../controller.js'),'utf8');
// The only receiver change in 0.1.63 was this catalog-count bound. Exercise
// exactly the installed 0.1.62 closed contract without changing production JS.
if(process.argv[5]==='0.1.62'){
 if(receiverSource.split('m.result.tools.length<=64').length!==2)throw new Error('catalog capacity seam changed');
 receiverSource=receiverSource.replace('m.result.tools.length<=64','m.result.tools.length<=32');
}
vm.runInContext(receiverSource,context);
const port={name:'mechanize-controller-v1',sender:{url:origin+'/app',origin,frameId:0,tab:{id:7},documentId:'controller-document'},onMessage:event('message'),onDisconnect:event('disconnect'),disconnect(){output({type:'fixtureFailure',code:'disconnected'});process.exitCode=1;},postMessage(value){
 if(value.type==='approved')void events.message(catalogMode?{type:'request',requestId:'browser-catalog',operation:'tools/list',deadlineUnixMs:Date.now()+5000}:{type:'request',requestId:'browser-initialize',operation:'initialize',deadlineUnixMs:Date.now()+5000,params:{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'controller-fixture',version:'1.0'}}});
 if(value.type==='result'&&callMode&&value.requestId==='browser-catalog'&&value.result){void events.message({type:'request',requestId:'browser-call',operation:'tools/call',deadlineUnixMs:Date.now()+5000,params:{name:'mechanize_describe',arguments:{}}});return;}
 if(value.type==='result'){process.stdout.write(JSON.stringify({type:'fixtureBrowserResult',value})+'\n',()=>process.exit(0));}
}};
readline.createInterface({input:process.stdin}).on('line',line=>{
 const frame=JSON.parse(line);
 if(!bridge){binding=frame;bridge=context.MechanizeController.install(chrome,{binding:()=>binding,send:output});bridge.receive({type:'controllerPolicy',enabled:true,origins:[policyOrigin],...binding});events.external(port);}
 else bridge.receive(frame);
});
