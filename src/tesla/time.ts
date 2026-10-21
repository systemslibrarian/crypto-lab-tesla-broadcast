import type {Parameters} from '../crypto/anchor';
/** Every time is supplied by the caller. Protocol code never reads a system clock. */
export function safe(arrivalLocal:number,bound:number,index:number,p:Parameters):{x:number;safe:boolean}{
 if(!Number.isFinite(arrivalLocal)||!Number.isFinite(bound)||bound<0||!Number.isInteger(index)||index<1||index>p.n)throw new RangeError('Invalid clock value or interval index');
 const x=Math.floor((arrivalLocal+bound-p.t0)/p.interval);
 return {x,safe:x<index+p.delay};
}
export function disclosureTime(index:number,p:Parameters):number{return p.t0+(index+p.delay)*p.interval}

