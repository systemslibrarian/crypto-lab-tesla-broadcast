import './styles.css';
import {mac,truncate,equal} from './crypto/hmac';
import {signAnchor,verifyAnchor,type Parameters} from './crypto/anchor';
import {build,authenticateKey,Fprime} from './tesla/chain';
import {tagInput} from './tesla/packet';
import {receive} from './tesla/receiver';
import {forgeAfterDisclosure} from './attack/spoofer';
import {receiverForgery} from './attack/shared-key';
import {airtime} from './bandwidth';

const root=document.querySelector<HTMLElement>('#exhibit')!;
root.innerHTML=`
<section aria-labelledby="intro"><h2 id="intro">A secret that arrives after the message</h2><p>A broadcaster must prove messages to many listeners, but it cannot give them a shared signing secret: any listener could forge. TESLA gives each message a MAC, keeps its key secret until later, and requires receivers to reject any packet that may have arrived after disclosure.</p><p class="warn card"><strong>Model:</strong> WebCrypto HMAC-SHA-256 and an Ed25519 signed key-chain commitment are real; clocks, radio, delivery and the adversary's scheduling are simulated. This is RFC 4082's TESLA shape, not OSNMA message parsing or a deployed receiver. Not production crypto — a teaching demo.</p></section>
<section aria-labelledby="shared"><h2 id="shared">1 · A shared-key MAC is forgeable by a listener</h2><p>Give every receiver the broadcaster's HMAC key and receiver 2 can forge a message that receiver 1 verifies. An Ed25519 signature avoids that problem but costs more bytes: at 20 bits/s a 384-bit signature alone takes 19.2 seconds.</p><button id="shared-run">Have receiver 2 forge a broadcast</button><output id="shared-out" aria-live="polite">No packet sent.</output></section>
<section aria-labelledby="chain"><h2 id="chain">2 · Commit once, reveal later</h2><p>Choose a random K₈ and compute Kᵢ = HMAC(Kᵢ₊₁, 00). The signed anchor K₀ and interval parameters are checked first. Message MAC keys use a separate F′(Kᵢ) = HMAC(Kᵢ, 01). Later keys hash forward to the anchor, even if intermediate radio packets were lost.</p><label for="loss">Lost disclosures before K₄: <span id="loss-label">0</span></label><input id="loss" type="range" min="0" max="3" value="0"><button id="chain-run">Verify disclosed K₄</button><output id="chain-out" aria-live="polite">No key verified yet.</output><p>Here F and F′ use HMAC-SHA-256 with distinct one-byte inputs. RFC 4082 names a pseudorandom function without prescribing this exact instantiation.</p></section>
<section aria-labelledby="timing"><h2 id="timing">3 · The clock-bound test</h2><p>Packets for interval i = 2 disclose their MAC key at i + d. A spoofer hears it, makes a valid MAC over a new message, and delivers immediately. The receiver sees local time T = sender time − true lag δ. It assumes the lag is at most Dₜ. Compute x = floor((T + Dₜ − T₀)/Tᵢₙₜ); the packet is safe only if x &lt; i + d.</p><div class="grid"><div><label for="lag">True lag δ: <span id="lag-value">4</span> s</label><input id="lag" type="range" min="0" max="10" value="4"><label for="bound">Assumed maximum lag Dₜ: <span id="bound-value">5</span> s</label><input id="bound" type="range" min="0" max="10" value="5"><label for="interval">Interval Tᵢₙₜ: <span id="interval-value">10</span> s</label><input id="interval" type="range" min="5" max="20" value="10"><label for="delay">Disclosure delay d: <span id="delay-value">2</span></label><input id="delay" type="range" min="1" max="3" value="2"><button id="spoof">Spoof interval 2</button></div><div><div class="output" id="timeline">Sender intervals: 0 | 1 | 2 (MAC) | 3 | 4 (key revealed). Receiver clock lags 4 s.</div><output id="timing-out" aria-live="polite">Default bound covers the true lag. Try Dₜ below δ and spoof.</output></div></div><p>A too-large assumed bound can discard a genuine late packet, hurting availability. A too-small bound accepts a spoof with real keys and a real valid tag. This boundary is a property of the timing assumption.</p></section>
<section aria-labelledby="bandwidth"><h2 id="bandwidth">4 · Bits on the air</h2><div class="grid"><div><label for="tag-bits">Tag bits (whole bytes): <span id="tag-value">32</span></label><input id="tag-bits" type="range" min="8" max="256" step="8" value="32"><label for="key-bits">Key bits: <span id="key-value">128</span></label><input id="key-bits" type="number" min="1" max="256" value="128"><label for="rate">Channel rate in bits/s: <span id="rate-value">20</span></label><input id="rate" type="number" min="1" max="10000" value="20"><button id="guess">Try 10,000 guessed tags</button><button id="guess-cancel" disabled>Cancel</button><button id="offline">Forge after disclosure</button></div><div><output id="airtime" aria-live="polite">32 + 128 = 160 bits → 8 seconds at 20 bits/s. The alternative 20 + 100 = 120 bits → 6 seconds.</output><output id="guesses" aria-live="polite">No forgery trial yet.</output><output id="offline-out" aria-live="polite">No disclosed-key forgery yet.</output></div></div><p>A truncated tag has about one random-guess success in 2ᵗ attempts; that is a bound for guessing a secure MAC key, not a guarantee of perfect entropy. After Kᵢ is disclosed, anyone can make a valid MAC for that old interval. A tag alone does not prove authorship to a third party.</p></section>
<section aria-labelledby="osnma"><h2 id="osnma">5 · An operational adaptation: Galileo OSNMA</h2><p>The <a href="https://www.gsc-europa.eu/node/7200">European GNSS Service Centre</a> says Galileo OSNMA adapts TESLA and announced its Initial Service operational on July 24, 2025. The <a href="https://www.euspa.europa.eu/sites/default/files/2024-03/Galileo_OSNMA_Receiver_Guidelines_v1.3.pdf">Receiver Guidelines, issue 1.3</a>, describe 30-second subframes, tags using HMAC-SHA-256 or CMAC-AES, and chains using SHA-256 or SHA3-256. This lab implements RFC 4082's teaching shape; it does not implement OSNMA formats or act as an OSNMA receiver.</p><details><summary>Sources, assumptions, and related labs</summary><ul><li><a href="https://www.rfc-editor.org/rfc/rfc4082">RFC 4082 §§2.2, 3.2–3.5</a> — chain and safe-packet test</li><li><a href="https://toc.cryptobook.us/">Boneh &amp; Shoup, v0.6 §14.7</a> — bandwidth framing and one-way-on-iterates assumption</li><li><a href="https://www.rfc-editor.org/rfc/rfc4231">RFC 4231</a> — HMAC test cases</li><li><a href="https://github.com/systemslibrarian/crypto-lab-time-trust">Time Trust</a> — clock values as an untrusted input</li><li><a href="https://github.com/systemslibrarian/crypto-lab-pulse-chain">Pulse Chain</a> — a hash chain used for a different purpose</li><li><a href="https://github.com/systemslibrarian/crypto-lab-mac-race">MAC Race</a> — underlying message authentication</li></ul><p>Outside scope: real time synchronization, real networks, µTESLA, multi-level chains, per-chain nonce and position hardening, and the book's no-delay variant.</p></details></section>`;
const el=(id:string)=>document.getElementById(id)!;
const hex=(a:Uint8Array)=>Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');
const fmt=(n:number)=>Number.isFinite(n)?n.toFixed(2):'invalid';
let chain:Uint8Array[]=[],secret=new Uint8Array(),signed:{signature:Uint8Array;publicKey:Uint8Array}|null=null,run=0,guessRun=0;
const parameters=():Parameters=>({t0:0,interval:Number((el('interval') as HTMLInputElement).value),delay:Number((el('delay') as HTMLInputElement).value),n:8});
function retire(id:string){el(id).textContent='Retired: inputs changed. Run the check again.';el(id).className=''}
function labels(){for(const [input,label] of [['lag','lag-value'],['bound','bound-value'],['interval','interval-value'],['delay','delay-value'],['loss','loss-label'],['tag-bits','tag-value'],['key-bits','key-value'],['rate','rate-value']])el(label).textContent=(el(input) as HTMLInputElement).value;
 const p=parameters(),delta=Number((el('lag') as HTMLInputElement).value);el('timeline').textContent=`Sender intervals: 0 | 1 | 2 (MAC) | ${Array.from({length:p.delay-1},(_,i)=>3+i).join(' | ')}${p.delay>1?' | ':''}${2+p.delay} (key revealed). Tᵢₙₜ=${p.interval}s; receiver clock is ${delta}s behind.`;
 try{const t=Number((el('tag-bits') as HTMLInputElement).value),k=Number((el('key-bits') as HTMLInputElement).value),rate=Number((el('rate') as HTMLInputElement).value);el('airtime').textContent=`${t} + ${k} = ${t+k} bits → ${fmt(airtime(t,k,rate))} seconds at ${rate} bits/s. Presets: (32+128)/20=8 s; (20+100)/20=6 s.`}catch{el('airtime').textContent='Enter a positive key length and channel rate.'}}
async function bootstrap(){chain=await build(8);secret=crypto.getRandomValues(new Uint8Array(32));signed=signAnchor(chain[0],parameters(),secret)}
function cancelByInput(){run++;retire('timing-out');retire('chain-out');if(chain.length)signed=signAnchor(chain[0],parameters(),secret);labels()}
for(const id of ['lag','bound','interval','delay','loss'])el(id).addEventListener('input',cancelByInput);
for(const id of ['tag-bits','key-bits','rate'])el(id).addEventListener('input',()=>{guessRun++;retire('guesses');labels()});
el('shared-run').addEventListener('click',async()=>{
 const shared=crypto.getRandomValues(new Uint8Array(32)),message='FAKE: receiver 2 impersonates the broadcaster',tag=await receiverForgery(shared,message);
 const verified=equal(tag,await mac(shared,new TextEncoder().encode(message)));
 el('shared-out').className=verified?'alarm':'warn';el('shared-out').textContent=`${verified?'ALARM — VALID TAG, AND FORGED BY A RECEIVER':'Rejected'}\nReceiver 1 computes a real HMAC and ${verified?'accepts':'rejects'} the forged message. Shared key: ${hex(shared)}; message: ${message}; full tag: ${hex(tag)}.`;
});
el('chain-run').addEventListener('click',async()=>{
 if(!signed)return;const p=parameters(),signatureOk=verifyAnchor(chain[0],p,signed.signature,signed.publicKey);
 if(!signatureOk){el('chain-out').className='warn';el('chain-out').textContent='Bootstrap failed: Ed25519 signature over the anchor and parameters is invalid.';return}
 const verified=await authenticateKey(chain[4],4,chain[0]);
 const loss=Number((el('loss') as HTMLInputElement).value);
 el('chain-out').className=verified.valid?'good':'warn';el('chain-out').textContent=`${verified.valid?'VERIFIED':'REJECTED'} — Ed25519 anchor signature valid; K₄ ${hex(chain[4])} hashed ${verified.hops} times to signed K₀ ${hex(chain[0])}. ${loss} earlier disclosure(s) marked lost; K₄ still checks. Signature: ${signed.signature.length*8} bits.`;
});
el('spoof').addEventListener('click',async()=>{
 if(!signed){el('timing-out').textContent='Bootstrap is still loading.';return}
 const id=++run,p=parameters(),lag=Number((el('lag') as HTMLInputElement).value),bound=Number((el('bound') as HTMLInputElement).value),commitment=signed;
 const {packet,senderArrival}=await forgeAfterDisclosure(chain[2],2,p);
 const arrivalLocal=senderArrival-lag;
 const result=await receive(packet,chain[2],arrivalLocal,bound,p,chain[0],commitment.signature,commitment.publicKey);
 if(id!==run)return;
 const checks=`Ed25519 anchor ${result.signature?'valid':'invalid'} → safety x=${result.x}, i+d=${2+p.delay}: ${result.safety?'passes':'rejects'} → ${result.safety?`key chain ${result.chain?'valid':'invalid'} → HMAC ${result.mac?'valid':'invalid'}`:'key and MAC not checked after discard'}`;
 el('timing-out').className=result.accepted?'alarm':'good';
 el('timing-out').textContent=`Sender disclosed K₂ at ${senderArrival}s. Forgery arrived on receiver clock at ${arrivalLocal}s (true lag ${lag}s). Receiver assumed bound ${bound}s.\n${checks}.\n${result.accepted?'ALARM — AUTHENTICATED, AND FORGED. Every local cryptographic check passed because the time bound was false.':'REJECTED — key may already be public. The safe-packet test discarded it before buffering.'}\nPacket tag: ${hex(packet.tag)}; disclosed K₂: ${hex(chain[2])}.`;
});
el('guess-cancel').addEventListener('click',()=>{guessRun++;el('guesses').textContent='Cancelled: incomplete trials are not a rate.';(el('guess') as HTMLButtonElement).disabled=false;(el('guess-cancel') as HTMLButtonElement).disabled=true});
el('guess').addEventListener('click',async()=>{
 const id=++guessRun,t=Number((el('tag-bits') as HTMLInputElement).value),target=truncate(await mac(crypto.getRandomValues(new Uint8Array(32)),tagInput(2,'fixed challenge')),t);
 (el('guess') as HTMLButtonElement).disabled=true;(el('guess-cancel') as HTMLButtonElement).disabled=false;let wins=0;
 for(let offset=0;offset<10000;offset+=500){
  if(id!==guessRun)return;
  const attempts=crypto.getRandomValues(new Uint8Array(500*t/8));
  for(let j=0;j<500;j++)wins+=Number(equal(attempts.slice(j*t/8,(j+1)*t/8),target));
  el('guesses').textContent=`${offset+500} / 10,000 random tags checked by the real HMAC verifier…`;
  await new Promise(resolve=>setTimeout(resolve,0));
 }
 if(id!==guessRun)return;
 (el('guess') as HTMLButtonElement).disabled=false;(el('guess-cancel') as HTMLButtonElement).disabled=true;
 el('guesses').textContent=`${wins} accepted in 10,000 guesses for a ${t}-bit tag. Expected mean = 10,000 / 2^${t} = ${(10000/2**t).toFixed(4)}. ${t===8?'Try again: independent trials fluctuate.':'Shorten to 8 bits to make a hit observable.'}\nTAG VERIFIES — AND ANYONE COULD HAVE MADE IT after the interval key is disclosed (no third-party proof of authorship).`;
});
el('offline').addEventListener('click',async()=>{
 if(!signed){el('offline-out').textContent='Bootstrap is still loading.';return}
 const forgedMessage='FAKE: historical interval 2',disclosed=chain[2],key=await Fprime(disclosed);
 const tag=truncate(await mac(key,tagInput(2,forgedMessage)),Number((el('tag-bits') as HTMLInputElement).value));
 const offline=equal(tag,truncate(await mac(await Fprime(disclosed),tagInput(2,forgedMessage)),tag.length*8));
 el('offline-out').className=offline?'alarm':'warn';
 el('offline-out').textContent=`${offline?'TAG VERIFIES — AND ANYONE COULD HAVE MADE IT':'Offline tag rejected'}\nAfter K₂ disclosure, a receiver created a new valid tag for “${forgedMessage}” using only public K₂. The offline checker recomputed F′(K₂) and HMAC: ${offline?'valid':'invalid'}. K₂=${hex(disclosed)}; tag=${hex(tag)}. This does not pass the earlier safe-packet arrival test.`;
});
labels();bootstrap().catch(error=>{el('timing-out').textContent=`Initialization failed: ${String(error)}`});
