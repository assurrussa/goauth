'use strict';
const output = document.querySelector('#result');
async function request(action, data = {}, method = 'POST') {
 const response = await fetch('/browser/' + action, {method, credentials:'same-origin', headers:{'Content-Type':'application/json','X-Goauth-CSRF':'1'}, ...(method === 'POST' ? {body:JSON.stringify(data)} : {})});
 const text = await response.text();
 let value = {}; try {value = JSON.parse(text);} catch {value = {message:text};}
 if (response.ok && value.accessExpiresAt) {
  localStorage.setItem('goauth-access-expiry', value.accessExpiresAt);
  localStorage.removeItem('goauth-refresh-blocked');
 }
 if (response.ok && ['logout','logout-all','password','email-confirm','reset'].includes(action)) localStorage.removeItem('goauth-access-expiry');
 output.textContent = response.status + '\n' + JSON.stringify(value,null,2);
 return response;
}
// Locks serialize cookie refresh rotation across tabs. Re-check expiry inside
// the lock, because another tab may already have refreshed the shared cookies.
async function refresh() {
 if (!navigator.locks) {output.textContent='This browser requires Web Locks for safe refresh across tabs.';return;}
 return navigator.locks.request('goauth-refresh', async () => {
  if (localStorage.getItem('goauth-refresh-blocked')) {output.textContent='Refresh outcome is uncertain or failed. Log in again.';return;}
  const expiry = Date.parse(localStorage.getItem('goauth-access-expiry') || '');
  if (expiry > Date.now() + 30000) {output.textContent='Access cookie is current.';return;}
  localStorage.setItem('goauth-refresh-blocked','1');
  try {return await request('refresh');}
  catch {output.textContent='Refresh outcome is uncertain. Log in again.';return;}
 });
}
for (const id of ['reset-request','reset','password','email-change','email-confirm']) document.getElementById(id).addEventListener('submit',async event=>{event.preventDefault();await request(id,Object.fromEntries(new FormData(event.target)));});
document.getElementById('auth').addEventListener('submit',async event=>{event.preventDefault();const data=Object.fromEntries(new FormData(event.target));const action=event.submitter.value;await request(action,action==='login'?{scheme:'email',identifier:data.email,password:data.password,realm:'user'}:data);event.target.password.value='';});
document.getElementById('code').addEventListener('submit',async event=>{event.preventDefault();await request('email-verify',Object.fromEntries(new FormData(event.target)));});
for(const id of ['email-send','logout','logout-all']) document.getElementById(id).addEventListener('click',()=>request(id));
document.getElementById('refresh').addEventListener('click',refresh);
document.getElementById('me').addEventListener('click',async()=>{await refresh();await request('me',{},'GET');});
if(location.hash.startsWith('#reset=')){document.querySelector('#reset [name=token]').value=new URLSearchParams(location.hash.slice(1)).get('reset');history.replaceState(null,'',location.pathname);}
