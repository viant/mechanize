import {copyFile,cp,mkdir,lstat,readdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {dirname,resolve} from 'node:path';

// Build-time copy of the canonical fingerprint. Production imports are wholly
// inside the reviewed RuntimeRoot; this script is not a runtime authorization.
const source=dirname(fileURLToPath(import.meta.url));
if(process.argv[2]){
  const destination=resolve(process.argv[2]);
  try{await lstat(destination);throw Error('New runtime destination required');}catch(error){if(error.code!=='ENOENT')throw error;}
  const dependency=resolve(source,'node_modules/playwright-core');
  async function refuseLinks(path){
    const stat=await lstat(path);if(stat.isSymbolicLink())throw Error('Runtime dependency symlinks denied');
    if(stat.isDirectory())for(const entry of await readdir(path))await refuseLinks(resolve(path,entry));
  }
  await refuseLinks(dependency);
  await mkdir(destination,{recursive:true});
  for(const [from,to] of [['fingerprint.js','fingerprint.cjs'],['playwright-target.js','target.cjs']])await copyFile(resolve(source,'../../extension/chrome',from),resolve(destination,to));
  for(const name of ['engine.mjs','relay.mjs','sidecar.mjs','package.json','package-lock.json'])await copyFile(resolve(source,name),resolve(destination,name));
  await mkdir(resolve(destination,'node_modules'),{recursive:true});
  // Only the reviewed declared dependency. npm's .bin and unrelated packages
  // are never imported into the application runtime tree.
  await cp(dependency,resolve(destination,'node_modules/playwright-core'),{recursive:true,dereference:false});
}else for(const [from,to] of [['fingerprint.js','fingerprint.cjs'],['playwright-target.js','target.cjs']])await copyFile(resolve(source,'../../extension/chrome',from),resolve(source,to));
