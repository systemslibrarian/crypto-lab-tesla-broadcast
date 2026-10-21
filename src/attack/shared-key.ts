import {mac} from '../crypto/hmac';
export async function receiverForgery(shared:Uint8Array,message:string){return mac(shared,new TextEncoder().encode(message))}

