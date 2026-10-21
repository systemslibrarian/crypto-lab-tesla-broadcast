import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';

const root=process.cwd();
const cases=JSON.parse(fs.readFileSync(path.join(root,'scripts/mutations.json'),'utf8'));
function run(bin,args){
 const result=spawnSync(bin,args,{cwd:root,encoding:'utf8',env:{...process.env,CI:'1'},timeout:180000});
 return {code:result.status,output:(result.stdout||'')+'\n'+(result.stderr||'')};
}
function build(){
 const r=run('npm',['run','build']);
 if(r.code!==0)throw Error('DOES NOT BUILD:\n'+r.output.slice(-1800));
 const files=fs.readdirSync(path.join(root,'dist/assets')).filter(f=>f.endsWith('.js')).sort();
 const digest=crypto.createHash('sha256');
 for(const file of files){digest.update(file);digest.update(fs.readFileSync(path.join(root,'dist/assets',file)))}
 return digest.digest('hex');
}
function command(c){return c.browser?['npx',['playwright','test','e2e/claims.spec.ts','--grep',c.test,'--workers=1']]:['npm',['test','--','-t',c.test]]}
let passed=0;
for(const c of cases){
 const file=path.join(root,c.file),original=fs.readFileSync(file,'utf8');
 if(original.split(c.from).length!==2)throw Error(c.name+': source anchor is not unique');
 const [bin,args]=command(c);
 const baseline=run(bin,args);
 if(baseline.code!==0)throw Error(c.name+': baseline did not pass:\n'+baseline.output.slice(-1800));
 const oldHash=build();
 let failure;
 try{
  fs.writeFileSync(file,original.replace(c.from,c.to));
  const diff=run('git',['diff','--',c.file]);
  if(!diff.output.includes('+')||!diff.output.includes('-'))throw Error('EMPTY DIFF');
  const newHash=build();
  if(newHash===oldHash)throw Error('BUNDLE HASH DID NOT MOVE');
  const mutated=run(bin,args);
  if(mutated.code===0)throw Error('SURVIVED: the named test stayed green');
  if(/DOES NOT BUILD|webServer was not able to start|ERR_CONNECTION_REFUSED/.test(mutated.output))throw Error('INFRASTRUCTURE FAILURE, NOT A KILL');
  if(!mutated.output.includes(c.test))throw Error('WRONG TEST FAILED:\n'+mutated.output.slice(-1400));
  console.log('KILLED '+c.name+' by '+c.test+' ('+oldHash.slice(0,8)+' → '+newHash.slice(0,8)+')');
  passed++;
 }catch(error){failure=error}
 finally{
  fs.writeFileSync(file,original);
  const restoredHash=build();
  if(restoredHash!==oldHash)throw Error(c.name+': restored bundle hash differs');
 }
 if(failure)throw Error(c.name+': '+failure.message);
}
console.log(passed+'/'+cases.length+' concrete source mutations killed; each baseline passed, diff was non-empty, build succeeded, bundle moved and restored.');
