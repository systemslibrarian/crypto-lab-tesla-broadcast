import {describe,it,expect} from 'vitest';
import {mac,truncate} from '../crypto/hmac';
import {sha256} from '../crypto/sha256';
import {signAnchor,verifyAnchor} from '../crypto/anchor';
import {ed25519} from '@noble/curves/ed25519.js';
import {build,authenticateKey,Fprime} from './chain';
import {createPacket} from './packet';
import {receive} from './receiver';
import {safe,disclosureTime} from './time';
import {forgeAfterDisclosure} from '../attack/spoofer';
import {airtime} from '../bandwidth';
const hex=(bytes:Uint8Array)=>Buffer.from(bytes).toString('hex');

describe('primary-source primitive vectors',()=>{
 it('RFC 4231 HMAC-SHA-256 case 1 and long-key case 6',async()=>{
  expect(hex(await mac(new Uint8Array(20).fill(0x0b),new TextEncoder().encode('Hi There')))).toBe('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
  const long=await mac(new Uint8Array(131).fill(0xaa),new TextEncoder().encode('Test Using Larger Than Block-Size Key - Hash Key First'));
  expect(hex(long)).toBe('60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54');
  expect(truncate(long,128)).toHaveLength(16);
 });
 it('SHA-256 abc and two-block message',async()=>{
  expect(hex(await sha256(new TextEncoder().encode('abc')))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  expect(hex(await sha256(new TextEncoder().encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')))).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
 });
 it('RFC 8032 Ed25519 test 1 and signed parameters',()=>{
  const privateKey=Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60','hex');
  const publicKey=Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a','hex');
  expect(hex(signAnchor(new Uint8Array(32),{t0:0,interval:10,delay:2,n:8},privateKey).publicKey)).toBe(hex(publicKey));
  expect(hex(ed25519.sign(new Uint8Array(),privateKey))).toBe('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
  const params={t0:0,interval:10,delay:2,n:8},root=new Uint8Array(32),signed=signAnchor(root,params,privateKey);
  expect(verifyAnchor(root,params,signed.signature,signed.publicKey)).toBe(true);
  expect(verifyAnchor(root,{...params,delay:1},signed.signature,signed.publicKey)).toBe(false);
 });
});
describe('RFC 4082 timing and key authentication',()=>{
 it('every disclosed key verifies to the signed root, but a modified key does not',async()=>{
  const chain=await build(8);
  for(let i=0;i<chain.length;i++)expect((await authenticateKey(chain[i],i,chain[0])).valid).toBe(true);
  const wrong=chain[4].slice();wrong[0]^=1;expect((await authenticateKey(wrong,4,chain[0])).valid).toBe(false);
  expect(hex(await Fprime(chain[4]))).not.toBe(hex(chain[4]));
 });
 it('forgery is accepted iff the assumed clock bound underestimates the true lag',async()=>{
  const chain=await build(8),key=crypto.getRandomValues(new Uint8Array(32));
  for(const interval of [5,10,20])for(const delay of [1,2,3])for(let trueLag=0;trueLag<=10;trueLag+=2)for(let bound=0;bound<=10;bound+=2){
   const p={t0:0,interval,delay,n:8},signed=signAnchor(chain[0],p,key);
   const {packet,senderArrival}=await forgeAfterDisclosure(chain[2],2,p);
   const verdict=await receive(packet,chain[2],senderArrival-trueLag,bound,p,chain[0],signed.signature,signed.publicKey);
   expect(verdict.accepted,JSON.stringify({interval,delay,trueLag,bound})).toBe(bound<trueLag);
   expect(verdict.x).toBe(Math.floor((senderArrival-trueLag+bound)/interval));
   expect(disclosureTime(2,p)).toBe((2+delay)*interval);
  }
 });
 it('rejects an invalid commitment, unsafe packet, wrong key and wrong MAC in order',async()=>{
  const chain=await build(8),p={t0:0,interval:10,delay:2,n:8},keys=signAnchor(chain[0],p,crypto.getRandomValues(new Uint8Array(32)));
  const good=await createPacket(chain[2],2,'real message',32),arrival=25;
  expect((await receive(good,chain[2],arrival,4,p,chain[0],keys.signature,keys.publicKey)).accepted).toBe(true);
  expect((await receive(good,chain[2],arrival,4,{...p,delay:3},chain[0],keys.signature,keys.publicKey)).reason).toMatch(/commitment/);
  expect((await receive(good,chain[2],40,4,p,chain[0],keys.signature,keys.publicKey)).reason).toMatch(/public/);
  expect((await receive(good,chain[3],arrival,4,p,chain[0],keys.signature,keys.publicKey)).reason).toMatch(/does not chain|MAC failed/);
  expect((await receive({...good,tag:new Uint8Array(4)},chain[2],arrival,4,p,chain[0],keys.signature,keys.publicKey)).reason).toBe('MAC failed');
  expect(safe(40,4,2,p).safe).toBe(false);
  expect(airtime(32,128,20)).toBe(8);
  expect(airtime(20,100,20)).toBe(6); // The bandwidth comparison need not be a selectable whole-byte tag.
 });
});
