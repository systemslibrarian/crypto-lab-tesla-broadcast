import {createPacket} from '../tesla/packet';
import {disclosureTime} from '../tesla/time';
import type {Parameters} from '../crypto/anchor';
/** Attacker receives only a publicly disclosed key, not the sender's secret chain. */
export async function forgeAfterDisclosure(publicKey:Uint8Array,index:number,p:Parameters,bits=32){
 const packet=await createPacket(publicKey,index,'FAKE: reroute the broadcast',bits,publicKey);
 return {packet,senderArrival:disclosureTime(index,p)};
}

