import {mac,equal,truncate} from '../crypto/hmac';
import {Fprime} from './chain';
const enc=new TextEncoder();
export type Packet={index:number;message:string;tag:Uint8Array;disclosed:Uint8Array|null};
export function tagInput(index:number,message:string):Uint8Array {
 if(!Number.isInteger(index)||index<1||index>4096||message.length>4096)throw new RangeError('Invalid packet index or message length');
 const body=enc.encode(message),out=new Uint8Array(15+4+4+body.length);out.set(enc.encode('TESLA-LAB/tag/1'),0);
 const view=new DataView(out.buffer);view.setUint32(15,index);view.setUint32(19,body.length);out.set(body,23);return out;
}
export async function createPacket(key:Uint8Array,index:number,message:string,bits:number,disclosed:Uint8Array|null=null):Promise<Packet>{
 const k=await Fprime(key);return {index,message,tag:truncate(await mac(k,tagInput(index,message)),bits),disclosed};
}
export async function validTag(key:Uint8Array,packet:Packet):Promise<boolean>{
 const expected=truncate(await mac(await Fprime(key),tagInput(packet.index,packet.message)),packet.tag.length*8);
 return equal(expected,packet.tag);
}

