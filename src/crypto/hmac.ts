/** HMAC-SHA-256 and truncation use WebCrypto. */
export async function mac(key:Uint8Array,data:Uint8Array):Promise<Uint8Array>{
 const k=await crypto.subtle.importKey('raw',new Uint8Array(key),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 return new Uint8Array(await crypto.subtle.sign('HMAC',k,new Uint8Array(data)));
}
export function truncate(tag:Uint8Array,bits:number):Uint8Array{
 if(!Number.isInteger(bits)||bits<8||bits>256||bits%8)throw new RangeError('Tag length must be whole bytes from 8 to 256 bits');
 return tag.slice(0,bits/8);
}
export function equal(a:Uint8Array,b:Uint8Array):boolean{
 if(a.length!==b.length)return false;let diff=0;for(let i=0;i<a.length;i++)diff|=a[i]^b[i];return diff===0;
}

