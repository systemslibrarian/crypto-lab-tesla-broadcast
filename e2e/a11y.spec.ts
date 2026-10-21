import AxeBuilder from '@axe-core/playwright';
import {expect,test,type Page} from '@playwright/test';

const WCAG=['wcag2a','wcag2aa','wcag21a','wcag21aa'];
async function scan(page:Page){
  await expect(page.locator('main#app h1')).toHaveCount(1);
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth+1);
  expect(overflow,'WCAG 1.4.10: no horizontal scroll at viewport width').toBe(false);
  const result=await new AxeBuilder({page}).withTags(WCAG).analyze();
  expect(result.violations.map(v=>`${v.id}: ${v.nodes.map(n=>n.target.join(',')).join('; ')}`)).toEqual([]);
  expect(result.incomplete.filter(v=>WCAG.some(t=>v.tags.includes(t))).map(v=>v.id),'axe must decide WCAG checks, not leave inconclusive contrast').toEqual([]);
  const best=await new AxeBuilder({page}).withRules(['region','landmark-one-main']).analyze();
  expect(best.violations.map(v=>v.id)).toEqual([]);
  const rgb=await page.evaluate(()=>{const h=getComputedStyle(document.documentElement),b=getComputedStyle(document.body);return [h.backgroundColor,b.color]});
  expect(rgb[0]).not.toBe('rgba(0, 0, 0, 0)');
}
for(const width of [1280,380])test(`production page: reachable states pass WCAG A/AA at ${width}px`,async({page})=>{
  test.setTimeout(120000);
  const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
  await page.setViewportSize({width,height:850});
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.goto('./');await expect(page.locator('#exhibit section').first()).toBeVisible();
  expect(await page.evaluate(()=>matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);
  await scan(page);
  await page.getByRole('button',{name:'Spoof interval 2'}).click();await expect(page.locator('#timing-out')).toContainText('REJECTED');await scan(page);await page.locator('#bound').fill('2');await page.getByRole('button',{name:'Spoof interval 2'}).click();await expect(page.locator('#timing-out')).toContainText('AUTHENTICATED');await scan(page);
  expect(errors).toEqual([]);
});
