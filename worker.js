// HadesSave Admin API • Cloudflare Worker + KV. Secrets never appear in GitHub Pages.
const json = (data, status=200, extra={}) => new Response(JSON.stringify(data), {
  status, headers: {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...extra}
});
const bytes = s => new TextEncoder().encode(s);
const base64url = arr => btoa(String.fromCharCode(...new Uint8Array(arr))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
const equal = (a,b) => { if (typeof a !== 'string' || typeof b !== 'string') return false; let diff = a.length ^ b.length; for (let i=0;i<Math.max(a.length,b.length);i++) diff |= (a.charCodeAt(i)||0) ^ (b.charCodeAt(i)||0); return diff === 0; };
async function sign(input,secret) {
  const key=await crypto.subtle.importKey('raw',bytes(secret),'HMAC',false,['sign']);
  return base64url(await crypto.subtle.sign('HMAC',key,bytes(input)));
}
async function adminUser(req,env) {
  const bearer=(req.headers.get('Authorization')||'').replace(/^Bearer\s+/i,'');
  const [expiry,sig]=bearer.split('.');
  if (!expiry||!sig||!/^\d+$/.test(expiry)||Number(expiry)<Date.now()) return false;
  return equal(sig,await sign(expiry,env.SESSION_SECRET));
}
export default { async fetch(request,env) {
  const origin = request.headers.get('Origin')||'';
  const allowed=env.ALLOWED_ORIGIN||'';
  const cors = {'Access-Control-Allow-Origin': origin === allowed ? origin : allowed,
    'Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'Authorization, Content-Type','Vary':'Origin'};
  if (request.method==='OPTIONS') return new Response(null,{status:204,headers:cors});
  if (origin && origin !== allowed) return json({error:'Origin blocked'},403,cors);
  const url=new URL(request.url), path=url.pathname;
  const reply=(data,status=200)=>json(data,status,cors);
  if (!env.STORE || !env.ADMIN_PASSWORD || !env.SESSION_SECRET || !env.BOT_BRIDGE_KEY) return reply({error:'Worker is not configured'},503);
  let body={};
  if (request.method==='POST') {
    if (Number(request.headers.get('content-length')||0)>100000) return reply({error:'Payload too large'},413);
    try {body=await request.json();} catch{return reply({error:'Invalid JSON'},400);}
  }
  if (path==='/admin/login' && request.method==='POST') {
    if (!equal(String(body.password||''),env.ADMIN_PASSWORD)) return reply({error:'Неверный пароль'},401);
    const expiry=String(Date.now()+6*60*60*1000);
    return reply({token:expiry+'.'+await sign(expiry,env.SESSION_SECRET)});
  }
  const botPath=path.startsWith('/bot/');
  if (botPath) {
    const key=(request.headers.get('Authorization')||'').replace(/^Bearer\s+/i,'');
    if (!equal(key,env.BOT_BRIDGE_KEY)) return reply({error:'Unauthorized'},401);
    if (path==='/bot/sync'&&request.method==='POST') {
      if (!body || !Array.isArray(body.users) || !body.counts) return reply({error:'Bad state'},400);
      await env.STORE.put('state',JSON.stringify(body)); return reply({ok:true});
    }
    if (path==='/bot/tasks'&&request.method==='GET') {
      const listed=await env.STORE.list({prefix:'task:',limit:30});
      const tasks=(await Promise.all(listed.keys.map(k=>env.STORE.get(k.name,'json')))).filter(Boolean);
      return reply({tasks});
    }
    if (path==='/bot/ack'&&request.method==='POST') {
      if (!/^[\w-]{20,60}$/.test(String(body.id||''))) return reply({error:'Bad id'},400);
      await env.STORE.put('result:'+body.id,JSON.stringify({id:body.id,ok:!!body.ok,message:String(body.message||'').slice(0,450),at:new Date().toISOString()}),{expirationTtl:604800});
      await env.STORE.delete('task:'+body.id); return reply({ok:true});
    }
    return reply({error:'Not found'},404);
  }
  if (!await adminUser(request,env)) return reply({error:'Требуется авторизация'},401);
  if (path==='/admin/state'&&request.method==='GET') {
    return reply({state:await env.STORE.get('state','json')||{users:[],support:[],counts:{},config:{},synced_at:null}});
  }
  if (path==='/admin/command'&&request.method==='POST') {
    const actions=['premium_grant','premium_revoke','block','unblock','broadcast','support_reply','config_set'];
    if (!actions.includes(body.action)||typeof body.data!=='object'||!body.data) return reply({error:'Неподдерживаемая команда'},400);
    const id=crypto.randomUUID();
    await env.STORE.put('task:'+id,JSON.stringify({id,action:body.action,data:body.data,created_at:new Date().toISOString()}),{expirationTtl:86400});
    return reply({ok:true,id,status:'queued'});
  }
  if (path==='/admin/result'&&request.method==='GET') {
    const id=url.searchParams.get('id')||'';
    if (!/^[\w-]{20,60}$/.test(id)) return reply({error:'Bad id'},400);
    const result=await env.STORE.get('result:'+id,'json');
    return reply({result:result||null});
  }
  return reply({error:'Not found'},404);
}};
