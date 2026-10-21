import {ed25519} from '@noble/curves/ed25519.js';
const enc=new TextEncoder();
export type Parameters={t0:number;interval:number;delay:number;n:number};
export function encodeAnchor(root:Uint8Array,p:Parameters):Uint8Array{
 if(root.length!==32||!Number.isSafeInteger(p.t0)||!Number.isSafeInteger(p.interval)||p.interval<=0||!Number.isInteger(p.delay)||p.delay<1||!Number.isInteger(p.n)||p.n<1||p.n>4096)throw new RangeError('Invalid chain commitment or parameters');
 return enc.encode(`TESLA-LAB/anchor/v1:${Array.from(root).map(b=>b.toString(16).padStart(2,'0')).join('')}:${p.t0}:${p.interval}:${p.delay}:${p.n}`);
}
export function signAnchor(root:Uint8Array,p:Parameters,privateKey:Uint8Array):{signature:Uint8Array;publicKey:Uint8Array}{
 const bytes=encodeAnchor(root,p);return {signature:ed25519.sign(bytes,privateKey),publicKey:ed25519.getPublicKey(privateKey)};
}
export function verifyAnchor(root:Uint8Array,p:Parameters,signature:Uint8Array,publicKey:Uint8Array):boolean{
 try{return ed25519.verify(signature,encodeAnchor(root,p),publicKey)}catch{return false}
}

