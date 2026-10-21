import {verifyAnchor,type Parameters} from '../crypto/anchor';
import {authenticateKey} from './chain';
import {validTag,type Packet} from './packet';
import {safe} from './time';
export type Verdict={signature:boolean;safety:boolean;chain:boolean;mac:boolean;accepted:boolean;x:number;reason:string};
export async function receive(packet:Packet,key:Uint8Array,arrivalLocal:number,bound:number,p:Parameters,anchor:Uint8Array,signature:Uint8Array,publicKey:Uint8Array):Promise<Verdict>{
 const signatureOk=verifyAnchor(anchor,p,signature,publicKey);
 if(!signatureOk)return {signature:false,safety:false,chain:false,mac:false,accepted:false,x:NaN,reason:'Invalid signed chain commitment'};
 const timing=safe(arrivalLocal,bound,packet.index,p);
 if(!timing.safe)return {signature:true,safety:false,chain:false,mac:false,accepted:false,x:timing.x,reason:'Key may already be public: discarded before buffering'};
 const verified=await authenticateKey(key,packet.index,anchor);
 if(!verified.valid)return {signature:true,safety:true,chain:false,mac:false,accepted:false,x:timing.x,reason:'Disclosed key does not chain to signed anchor'};
 const mac=await validTag(key,packet);
 return {signature:true,safety:true,chain:true,mac,accepted:mac,x:timing.x,reason:mac?'All local checks accepted':'MAC failed'};
}

