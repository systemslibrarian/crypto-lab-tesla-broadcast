import {mac,equal} from '../crypto/hmac';
export async function F(key:Uint8Array):Promise<Uint8Array>{return mac(key,new Uint8Array([0]))}
export async function Fprime(key:Uint8Array):Promise<Uint8Array>{return mac(key,new Uint8Array([1]))}
export async function build(n:number):Promise<Uint8Array[]>{
 if(!Number.isInteger(n)||n<1||n>4096)throw new RangeError('Chain length must be 1–4096');
 const chain:Uint8Array[]=Array(n+1);chain[n]=crypto.getRandomValues(new Uint8Array(32));
 for(let i=n-1;i>=0;i--)chain[i]=await F(chain[i+1]);
 return chain;
}
export async function authenticateKey(key:Uint8Array,index:number,anchor:Uint8Array):Promise<{valid:boolean;hops:number}>{
 if(!Number.isInteger(index)||index<0||index>4096||key.length!==32||anchor.length!==32)throw new RangeError('Invalid key, index or anchor');
 let current=key;for(let i=0;i<index;i++)current=await F(current);
 return {valid:equal(current,anchor),hops:index};
}

