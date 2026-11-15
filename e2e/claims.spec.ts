import {test,expect} from '@playwright/test';
import {createHmac} from 'node:crypto';
const hmac=(key:Buffer,message:Buffer)=>createHmac('sha256',key).update(message).digest();
const packetInput=(index:number,message:string)=>{
 const body=Buffer.from(message),tag=Buffer.from('TESLA-LAB/tag/1'),head=Buffer.alloc(23+body.length);
 tag.copy(head);head.writeUInt32BE(index,15);head.writeUInt32BE(body.length,19);body.copy(head,23);return head;
};
test('the displayed clock inequality and actual HMAC explain both forged verdicts',async({page})=>{
 await page.goto('./');await page.getByRole('button',{name:'Spoof interval 2'}).click();
 const outcome=page.locator('#timing-out');await expect(outcome).toContainText('REJECTED');
 await page.locator('#bound').fill('2');await expect(outcome).toContainText('Retired');
 await page.getByRole('button',{name:'Spoof interval 2'}).click();await expect(outcome).toContainText('AUTHENTICATED');
 const text=await outcome.innerText(),t=text.match(/disclosed K₂ at (\d+)s.*clock at (\d+)s \(true lag (\d+)s\).*bound (\d+)s.*safety x=(\d+), i\+d=(\d+)/s);
 expect(t).not.toBeNull();
 const [,sender,local,lag,bound,x,threshold]=t!.map(Number);
 const interval=Number(await page.locator('#interval').inputValue());
 expect(sender-Number(lag)).toBe(Number(local));
 expect(Math.floor((Number(local)+Number(bound))/interval)).toBe(Number(x));
 expect(Number(x)).toBeLessThan(Number(threshold));
 const wire=text.match(/Packet tag: ([0-9a-f]+); disclosed K₂: ([0-9a-f]+)/);expect(wire).not.toBeNull();
 const macKey=hmac(Buffer.from(wire![2],'hex'),Buffer.from([1]));
 expect(hmac(macKey,packetInput(2,'FAKE: reroute the broadcast')).subarray(0,4).toString('hex')).toBe(wire![1]);
 const data=await page.locator('#airtime').innerText();expect(data).toContain('8.00 seconds');expect(data).toContain('6 s');
 await page.locator('#bound').fill('8');await page.getByRole('button',{name:'Spoof interval 2'}).click();await expect(outcome).toContainText('REJECTED');
});
test('the disclosed chain and receiver-created tags rederive independently',async({page})=>{
 await page.goto('./');
 await page.getByRole('button',{name:'Have receiver 2 forge a broadcast'}).click();
 const shared=await page.locator('#shared-out').innerText();
 const parts=shared.match(/Shared key: ([0-9a-f]+); message: (.*); full tag: ([0-9a-f]+)/);
 expect(parts).not.toBeNull();
 expect(hmac(Buffer.from(parts![1],'hex'),Buffer.from(parts![2])).toString('hex')).toBe(parts![3]);
 await page.getByRole('button',{name:'Verify disclosed K₄'}).click();
 const chain=await page.locator('#chain-out').innerText();
 const keys=chain.match(/K₄ ([0-9a-f]+) hashed (\d+) times to signed K₀ ([0-9a-f]+)/);
 expect(keys).not.toBeNull();
 let k=Buffer.from(keys![1],'hex');for(let i=0;i<Number(keys![2]);i++)k=hmac(k,Buffer.from([0]));
 expect(k.toString('hex')).toBe(keys![3]);
 await page.getByRole('button',{name:'Forge after disclosure'}).click();
 const outcome=await page.locator('#offline-out').innerText();
 expect(outcome).toContain('TAG VERIFIES — AND ANYONE COULD HAVE MADE IT');
 const wire=outcome.match(/K₂=([0-9a-f]+); tag=([0-9a-f]+)/);
 expect(wire).not.toBeNull();
 const derived=hmac(Buffer.from(wire![1],'hex'),Buffer.from([1]));
 expect(hmac(derived,packetInput(2,'FAKE: historical interval 2')).subarray(0,wire![2].length/2).toString('hex')).toBe(wire![2]);
});
test('lost disclosures release real buffered packets, while a wide bound discards them',async({page})=>{
 await page.goto('./');
 await page.locator('#loss').fill('3');
 await page.getByRole('button',{name:'Verify disclosed K₄'}).click();
 const result=page.locator('#chain-out');
 await expect(result).toContainText('K₄ released 4 waiting packet(s)');
 const text=await result.innerText();
 for(const i of [1,2,3])expect(text).toContain(`K${i} disclosure lost`);
 expect(text).toContain('Authenticated intervals: 1, 2, 3, 4; unsafe genuine packets: 0');
 const keys=text.match(/K₄ ([0-9a-f]+) hashed (\d+) times to signed K₀ ([0-9a-f]+)/);
 expect(keys).not.toBeNull();
 let key=Buffer.from(keys![1],'hex');
 for(let i=0;i<Number(keys![2]);i++)key=hmac(key,Buffer.from([0]));
 expect(key.toString('hex')).toBe(keys![3]);
 await page.locator('#lag').fill('0');
 await page.locator('#interval').fill('5');
 await page.locator('#delay').fill('1');
 await page.locator('#bound').fill('10');
 await expect(result).toContainText('Retired');
 await page.getByRole('button',{name:'Verify disclosed K₄'}).click();
 await expect(result).toContainText('unsafe genuine packets: 4');
 await expect(result).toContainText('Authenticated intervals: none');
});
// Section 1 quotes what one Ed25519 signature costs on the channel; the chain
// read-out prints the bit length of the signature the page actually makes. The
// two must agree. An earlier revision called it "a 384-bit signature ... 19.2
// seconds"; 384 bits is the short-signature size Boneh-Shoup §14.7 uses, not
// Ed25519's 64 octets (RFC 8032 §5.1.6).
test('the quoted Ed25519 signature cost matches the signature the page really makes',async({page})=>{
 await page.goto('./');
 const quoted=(await page.locator('section[aria-labelledby="shared"]').innerText()).match(/its (\d+)-bit signature alone takes ([\d.]+) seconds/);
 expect(quoted).not.toBeNull();
 await page.getByRole('button',{name:'Verify disclosed K₄'}).click();
 const measured=(await page.locator('#chain-out').innerText()).match(/Signature: (\d+) bits/);
 expect(measured).not.toBeNull();
 expect(Number(quoted![1])).toBe(Number(measured![1]));
 expect(Number(measured![1])).toBe(512);
 const rate=Number(await page.locator('#rate').inputValue());
 expect(rate).toBe(20);
 expect(Number(quoted![2])).toBe(Number(measured![1])/rate);
 expect(Number(quoted![2])).toBe(25.6);
});
