import assert from 'node:assert/strict';
import https from 'node:https';
import {reviewBrowserRecovery} from './browser-review-acceptance.mjs';
import {assertFixtureActive, browserFixture, browserOrigin, secureBrowserOptions, secureRequestOptions} from './browser-security.mjs';
const fixture=browserFixture();
const {chromium}=await import(process.env.GOAUTH_BROWSER_PLAYWRIGHT_MODULE || 'playwright');
const {origin,port,hostile}=browserOrigin(process.argv[2]);
const raw=(path,method='GET',body,headers={})=>new Promise((resolve,reject)=>{
 const req=https.request(secureRequestOptions(fixture.ca,port,path,method,headers),response=>{let text='';response.on('data',chunk=>text+=chunk);response.on('end',()=>{let data;try{data=JSON.parse(text)}catch{}resolve({status:response.statusCode,data,headers:response.headers});});});req.on('error',reject);if(body!==undefined)req.write(JSON.stringify(body));req.end();
});
const delivered=async(to,template)=>{for(let attempt=0;attempt<100;attempt++){const value=await raw(`/fixture/delivery?to=${encodeURIComponent(to)}&template=${template}`);if(value.status===200)return value.data;await new Promise(resolve=>setTimeout(resolve,100));}throw new Error('Encrypted worker delivery not observed: '+template);};
const context=await chromium.launchPersistentContext(fixture.profile,secureBrowserOptions(process.env.GOAUTH_BROWSER_CHROMIUM_EXECUTABLE));
try {
  const page=await context.newPage();await page.goto(origin);await page.waitForFunction(()=>typeof window.request==='function');
  const call=(action,data={},method='POST')=>page.evaluate(async({action,data,method})=>{const response=await request(action,data,method);return{status:response.status,data:JSON.parse(document.querySelector('#result').textContent.split('\n').slice(1).join('\n'))};},{action,data,method});
  const email=`public.${crypto.randomUUID()}@example.test`,newEmail=`changed.${crypto.randomUUID()}@example.test`;
  let password='Public-Browser-Initial-Password-1';
  let response=await call('register',{email,password});assert.equal(response.status,201);assert(!JSON.stringify(response.data).includes('accessToken')&&!JSON.stringify(response.data).includes('refreshToken'));
  const cookies=await context.cookies(origin);for(const name of ['__Host-SSID','__Host-UUIDR']){const cookie=cookies.find(c=>c.name===name);assert(cookie&&cookie.secure&&cookie.httpOnly&&cookie.path==='/'&&cookie.sameSite==='Lax'&&!cookie.domain.startsWith('.'));}
  assert(!(await page.evaluate(()=>document.cookie)).includes('__Host-SSID='));
  assert.equal((await call('email-send')).status,202);let notice=await delivered(email,'email_challenge');assert.equal((await call('email-verify',{code:notice.data.code})).status,200);
  const login=()=>call('login',{scheme:'email',identifier:email,password,realm:'user'});
  assert.equal((await login()).status,200);assert.equal((await call('me',{},'GET')).status,200);
  const second=await context.newPage();await second.goto(origin);await second.waitForFunction(()=>typeof window.refresh==='function');
  const before=(await raw('/fixture/stats')).data.submitted;
  await new Promise(resolve=>setTimeout(resolve,36000)); // expire the actual canonical access token
  await Promise.all([page.evaluate(()=>refresh()),second.evaluate(()=>refresh())]);
  assert.equal((await raw('/fixture/stats')).data.submitted-before,1,'real example Web Locks must submit exactly one rotation');
  assert.equal((await call('me',{},'GET')).status,200);
  const cookieHeader=(await context.cookies(origin)).map(c=>c.name+'='+c.value).join('; ');
  assert.equal((await raw('/browser/me','GET',undefined,{Cookie:cookieHeader+'; __Host-SSID=duplicate'})).status,401);
  assert.equal((await raw('/browser/me','GET',undefined,{Cookie:cookieHeader,Authorization:'Bearer conflict'})).status,401);
  assert.equal((await raw('/browser/login','POST',{},{Origin:origin})).status,403);
  assert.equal((await raw('/browser/login','POST',{},{Origin:hostile,'X-Goauth-CSRF':'1'})).status,403);
  const attacker=await context.newPage();await attacker.goto(hostile);await assert.rejects(attacker.evaluate(async origin=>fetch(origin+'/browser/logout',{method:'POST',credentials:'include',headers:{'X-Goauth-CSRF':'1'}}),origin));
  const beforeLogout=(await raw('/fixture/stats')).data.submitted;
  await new Promise(resolve=>setTimeout(resolve,36000)); // logout must work with a genuinely expired access cookie
  assert.equal(await page.evaluate(async()=>{const response=await logout();return response?.status;}),204);
  await second.evaluate(()=>refresh());
  assert.equal((await raw('/fixture/stats')).data.submitted-beforeLogout,1,'logout refreshes once; a queued tab cannot revive the session');
  assert(!(await context.cookies(origin)).some(c=>['__Host-SSID','__Host-UUIDR'].includes(c.name)));
  assert.equal((await call('me',{},'GET')).status,401);
  assert.equal((await login()).status,200);assert.equal((await call('logout-all')).status,204);assert.equal((await call('me',{},'GET')).status,401);
  assert.equal((await call('reset-request',{email})).status,202);notice=await delivered(email,'password_reset');password='Public-Browser-Recovered-Password-2';assert.equal((await call('reset',{token:new URLSearchParams(new URL(notice.data.reset_url).hash.slice(1)).get('reset'),newPassword:password})).status,204);assert.equal((await login()).status,200);
  const changed='Public-Browser-Changed-Password-3';assert.equal((await call('password',{currentPassword:password,newPassword:changed})).status,200);password=changed;assert.equal((await call('me',{},'GET')).status,401);assert.equal((await login()).status,200);
  assert.equal((await call('email-change',{email:newEmail})).status,422);
  assert.equal((await call('email-change',{email:newEmail,currentPassword:'wrong'})).status,422);
  assert.equal((await call('email-change',{email:newEmail,currentPassword:password})).status,202);notice=await delivered(newEmail,'email_change');assert.equal((await call('email-confirm',{code:notice.data.code})).status,200);
  const previousNotice=await delivered(email,'email_changed');assert(!previousNotice.data?.code,'previous mailbox must not receive a confirmation credential');
  assert.equal((await call('login',{scheme:'email',identifier:newEmail,password,realm:'user'})).status,200);assert.equal((await call('me',{},'GET')).status,200);
  const api=await raw('/api/login','POST',{scheme:'email',identifier:newEmail,password,realm:'user'});assert.equal(api.status,200);assert(api.data.tokens.accessToken&&api.data.tokens.refreshToken&&!api.headers['set-cookie']);
  assert.equal((await raw('/api/me','GET',undefined,{Cookie:cookieHeader})).status,401);assert.equal((await raw('/api/me','GET',undefined,{Authorization:'Bearer '+api.data.tokens.accessToken})).status,200);
  await reviewBrowserRecovery({context, page, second, origin, raw, call, email: newEmail, password});
  const stats=(await raw('/fixture/stats')).data;assert(stats.encrypted>=3);
  assertFixtureActive(fixture.expiresAt);
  console.log('public nethttp PostgreSQL/HTTPS browser PASS: signup/delivered confirmation/login/me/expired access/two-tabs exactly1 rotation/logout/all/delivered reset/password/email; HttpOnly/CSRF/hostile/duplicates; bearer API no Set-Cookie');
} finally {await context.close();}
