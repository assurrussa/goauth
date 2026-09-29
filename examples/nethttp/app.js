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
 if (response.ok && ['logout','logout-all','password','email-confirm','reset'].includes(action)) {
  localStorage.removeItem('goauth-access-expiry');
  // A queued tab must not rotate credentials after an invalidating operation.
  localStorage.setItem('goauth-refresh-blocked','1');
 }
 output.textContent = response.status + '\n' + JSON.stringify(value,null,2);
 return response;
}
// Every refresh and logout uses the same origin-wide Web Lock. A logout keeps
// the lock through refresh AND revocation, so a queued tab cannot rotate the
// just-issued credentials between those operations.
function hasRefreshLock() {
 if (navigator.locks) return true;
 output.textContent='This browser requires Web Locks for safe refresh across tabs.';
 return false;
}
async function refreshLocked() {
 if (localStorage.getItem('goauth-refresh-blocked')) {
  output.textContent='Refresh is blocked after logout, failure or an uncertain outcome. Log in again.';
  return false;
 }
 const expiry = Date.parse(localStorage.getItem('goauth-access-expiry') || '');
 if (expiry > Date.now() + 30000) return true;
 localStorage.setItem('goauth-refresh-blocked','1');
 try {
  const response = await request('refresh');
  // A successful response must also have installed usable expiry metadata.
  return response.ok && !localStorage.getItem('goauth-refresh-blocked');
 } catch {
  output.textContent='Refresh outcome is uncertain. Log in again.';
  return false;
 }
}
async function refresh() {
 if (!hasRefreshLock()) return false;
 return navigator.locks.request('goauth-refresh', refreshLocked);
}
async function logout(action = 'logout') {
 if (!['logout','logout-all'].includes(action)) throw new Error('Invalid logout action');
 if (!hasRefreshLock()) return;
 return navigator.locks.request('goauth-refresh', async () => {
  if (!await refreshLocked()) return;
  try {
   const response = await request(action);
   if (!response.ok) localStorage.setItem('goauth-refresh-blocked','1');
   return response;
  } catch {
   localStorage.setItem('goauth-refresh-blocked','1');
   output.textContent='Logout outcome is uncertain; server revocation was not confirmed. Log in again.';
  }
 });
}
for (const id of ['reset-request','reset','password','email-change','email-confirm']) document.getElementById(id).addEventListener('submit',async event=>{event.preventDefault();try {await request(id,Object.fromEntries(new FormData(event.target)));} finally {for(const input of event.target.querySelectorAll('input[type=\"password\"]')) input.value='';}});
document.getElementById('auth').addEventListener('submit',async event=>{event.preventDefault();const data=Object.fromEntries(new FormData(event.target));const action=event.submitter.value;await request(action,action==='login'?{scheme:'email',identifier:data.email,password:data.password,realm:'user'}:data);event.target.password.value='';});
document.getElementById('code').addEventListener('submit',async event=>{event.preventDefault();await request('email-verify',Object.fromEntries(new FormData(event.target)));});
document.getElementById('email-send').addEventListener('click',()=>request('email-send'));
for(const id of ['logout','logout-all']) document.getElementById(id).addEventListener('click',()=>logout(id));
document.getElementById('refresh').addEventListener('click',refresh);
document.getElementById('me').addEventListener('click',async()=>{await refresh();await request('me',{},'GET');});
if(location.hash.startsWith('#reset=')){document.querySelector('#reset [name=token]').value=new URLSearchParams(location.hash.slice(1)).get('reset');history.replaceState(null,'',location.pathname);}
