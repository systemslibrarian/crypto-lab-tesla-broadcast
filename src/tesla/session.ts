import {verifyAnchor,type Parameters} from '../crypto/anchor';
import {F,authenticateKey} from './chain';
import {validTag,type Packet} from './packet';
import {safe} from './time';

/** A receiver buffers only packets that were safe on arrival. Time comes from the caller. */
export class ReceiverSession {
 private seen=new Set<string>();
 private buffer=new Map<string,Packet>();
 readonly accepted:number[]=[];
 readonly rejected:number[]=[];
 readonly unsafe:number[]=[];
 readonly lost:number[]=[];
 constructor(private readonly p:Parameters,private readonly anchor:Uint8Array,signature:Uint8Array,publicKey:Uint8Array){
  if(!verifyAnchor(anchor,p,signature,publicKey))throw new Error('Bootstrap failed: invalid signed chain commitment');
 }
 arrive(packet:Packet,localTime:number,bound:number):'buffered'|'duplicate'|'unsafe'{
  const id=JSON.stringify([packet.index,packet.message,Array.from(packet.tag)]);
  if(this.seen.has(id))return 'duplicate';
  const check=safe(localTime,bound,packet.index,this.p);
  if(!check.safe){this.unsafe.push(packet.index);return 'unsafe'}
  this.seen.add(id);this.buffer.set(id,packet);return 'buffered';
 }
 dropDisclosure(index:number){this.lost.push(index)}
 async disclose(index:number,key:Uint8Array):Promise<{authenticated:boolean;hops:number;released:number[]}>{
  if(!Number.isInteger(index)||index<1||index>this.p.n)throw new RangeError('Invalid disclosure index');
  const check=await authenticateKey(key,index,this.anchor);
  if(!check.valid)return {authenticated:false,hops:check.hops,released:[]};
  const released:number[]=[];
  for(const [id,packet] of [...this.buffer].sort(([,a],[,b])=>a.index-b.index)){
   const i=packet.index;
   if(i>index)continue;
   // F(K_j)=K_(j-1): a later authenticated disclosure recovers earlier MAC keys.
   let earlier=key;
   for(let j=index;j>i;j--)earlier=await F(earlier);
   if(await validTag(earlier,packet)){this.accepted.push(i);released.push(i)}
   else this.rejected.push(i);
   this.buffer.delete(id);
  }
  return {authenticated:true,hops:check.hops,released};
 }
 get waiting(){return [...this.buffer.values()].map(p=>p.index).sort((a,b)=>a-b)}
}
