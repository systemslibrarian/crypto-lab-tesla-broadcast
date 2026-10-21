export function airtime(tagBits:number,keyBits:number,bitsPerSecond:number):number{
 if(!Number.isInteger(tagBits)||tagBits<8||tagBits>256||!Number.isInteger(keyBits)||keyBits<1||!(bitsPerSecond>0))throw new RangeError('Invalid tag/key/rate');
 return (tagBits+keyBits)/bitsPerSecond;
}
