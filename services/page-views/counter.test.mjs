import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import worker from './worker.mjs';
const origin = 'https://signalforgeresearch.com';
function database() {
  const sql = new DatabaseSync(':memory:');
  for (const name of ['0001_page_views.sql','0002_analytics_events.sql']) sql.exec(readFileSync(new URL('migrations/'+name,import.meta.url),'utf8'));
  return { sql, DB: {
    prepare(query) { let args=[]; return { bind(...v){args=v;return this;}, async first(){return sql.prepare(query).get(...args);}, query, get args(){return args;} }; },
    async batch(statements) {
      sql.exec('BEGIN');
      try { const result=statements.map(s=>{const q=sql.prepare(s.query);return {results:q.columns().length?q.all(...s.args):(q.run(...s.args),[])};});sql.exec('COMMIT');return result; }
      catch(e){sql.exec('ROLLBACK');throw e;}
    }
  }};
}
function req(path='/views',method='GET',data,headers={}) {
  return new Request('https://counter.example'+path,{method,headers:{Origin:origin,'Content-Type':'application/json','CF-Connecting-IP':'192.0.2.3','User-Agent':'Test browser',...headers},...(data===undefined?{}:{body:typeof data==='string'?data:JSON.stringify(data)})});
}
const event = {type:'pageview',page:'/index.html?private=yes',referrer:'https://referrer.example/path?secret=yes#fragment',session:'12345678-1234-1234-1234-123456789abc'};

test('events store request details privately, sanitize URLs, and increment only page views',async()=>{
 const env=database();try{
  assert.deepEqual(await(await worker.fetch(req(),env)).json(),{total:0,startedAt:null});
  const first=await(await worker.fetch(req('/event','POST',event),env)).json();assert.equal(first.total,1);
  await Promise.all(Array.from({length:20},()=>worker.fetch(req('/event','POST',event),env)));
  await worker.fetch(req('/event','POST',{...event,type:'download_click',target:'https://signalforgeresearch.com/report.pdf?secret=x'}),env);
  const total=await(await worker.fetch(req(),env)).json();assert.equal(total.total,21);assert.equal(total.startedAt,first.startedAt);
  const row=env.sql.prepare('SELECT * FROM analytics_events ORDER BY id LIMIT 1').get();
  assert.equal(row.ip_address,'192.0.2.3');assert.equal(row.user_agent,'Test browser');assert.equal(row.page_path,'/index.html');
  assert.equal(row.referrer,'https://referrer.example/path');assert.ok(Number.isFinite(Date.parse(row.occurred_at)));
  assert.equal(env.sql.prepare('SELECT target FROM analytics_events ORDER BY id DESC LIMIT 1').get().target,'https://signalforgeresearch.com/report.pdf');
  assert.deepEqual(Object.keys(total).sort(),['startedAt','total']);
 }finally{env.sql.close();}
});
test('pixels remain separate, preference headers skip logs, and old records expire without resetting total',async()=>{
 const env=database();try{
  await worker.fetch(req('/event','POST',event),env);
  env.sql.exec("UPDATE analytics_events SET occurred_at='2000-01-01T00:00:00Z'");
  const path='/pixel/'+'a'.repeat(32)+'.gif';
  const pixel=await worker.fetch(req(path),env);assert.equal(pixel.headers.get('Content-Type'),'image/gif');assert.equal((await pixel.arrayBuffer()).byteLength,42);
  const rows=env.sql.prepare('SELECT * FROM analytics_events').all();assert.equal(rows.length,1);assert.equal(rows[0].event_type,'pixel_request');
  assert.equal((await(await worker.fetch(req(),env)).json()).total,1);
  await worker.fetch(req(path,'GET',undefined,{'DNT':'1'}),env);
  await worker.fetch(req('/event','POST',event,{'Sec-GPC':'1'}),env);
  assert.equal(env.sql.prepare('SELECT count(*) AS n FROM analytics_events').get().n,1);
 }finally{env.sql.close();}
});
test('validation, preflight, failures, and origins prevent unwanted writes',async()=>{
 const env=database();try{
  for(const [request,status] of [
   [req('/event','POST',event,{Origin:'https://other.example'}),403],
   [req('/event','POST','{'),400],[req('/event','POST','x'.repeat(4097)),413],
   [req('/event','POST',{...event,type:'pixel_request'}),400],
   [req('/event','POST',{...event,page:'https://other.example/'}),400],
   [req('/event','POST',event,{'Content-Type':'text/plain'}),415],
   [req('/views','POST',event),405],[req('/event','OPTIONS'),204],
   [req('/asset/not-allowed.png'),404],[req('/pixel/not-a-token.gif'),404]
  ]) assert.equal((await worker.fetch(request,env)).status,status);
  assert.equal(env.sql.prepare('SELECT count(*) AS n FROM analytics_events').get().n,0);
  assert.equal((await worker.fetch(req('/event','POST',event),{})).status,503);
 }finally{env.sql.close();}
});
test('allowlisted images proxy successful responses and record image requests',async()=>{
 const env=database(), original=globalThis.fetch;
 try{
  globalThis.fetch=async(url)=>{assert.equal(url,'https://signalforgeresearch.com/assets/signal-forge-logo.png');return new Response('image bytes');};
  const response=await worker.fetch(req('/asset/signal-forge-logo.png'),env);
  assert.equal(response.status,200);assert.equal(await response.text(),'image bytes');
  assert.equal(env.sql.prepare('SELECT event_type FROM analytics_events').get().event_type,'asset_request');
  globalThis.fetch=async()=>new Response('',{status:404});assert.equal((await worker.fetch(req('/asset/signal-forge-logo.png'),env)).status,502);
  assert.equal(env.sql.prepare('SELECT count(*) AS n FROM analytics_events').get().n,1);
 }finally{globalThis.fetch=original;env.sql.close();}
});
const source=readFileSync(new URL('../../docs/assets/page-views.js',import.meta.url),'utf8').replace(/const endpoint = .*?;/, 'const endpoint = "";');
async function browser({optOut=false,enabled=true,fail=false}={}){
 const calls=[],listeners={},storage=new Map(),label={textContent:''},element={hidden:true,querySelector:()=>label};
 vm.runInNewContext(enabled?source.replace('const endpoint = "";','const endpoint = "https://counter.example";'):source,{
  URL,AbortSignal,crypto:{randomUUID:()=>event.session},
  navigator:{globalPrivacyControl:optOut},location:{hostname:'signalforgeresearch.com',pathname:'/',href:origin+'/'},
  sessionStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v)},
  document:{referrer:'https://referrer.example/',querySelectorAll:()=>[element],addEventListener:(name,fn)=>{listeners[name]=fn;}},
  fetch:async(url,options)=>{calls.push({url:url.href,...options});if(fail)throw Error('blocked');return {ok:true,json:async()=>({total:42,startedAt:'2026-10-27T00:00:00Z'})};},
 });
 await new Promise(resolve=>setTimeout(resolve,0));return {calls,listeners,storage,label,element};
}
test('browser honors opt-out, records clicks, uses no credentials, and handles unavailable tracking',async()=>{
 const normal=await browser();assert.equal(normal.label.textContent,'42');assert.equal(normal.calls[0].credentials,'omit');assert.equal(normal.storage.size,1);
 assert.equal(JSON.parse(normal.calls[0].body).type,'pageview');
 normal.listeners.click({target:{closest:()=>({href:origin+'/report.pdf',hasAttribute:()=>false})}});
 assert.equal(JSON.parse(normal.calls[1].body).type,'download_click');
 const off=await browser({optOut:true});assert.equal(off.storage.size,0);assert.equal(off.calls[0].body,undefined);assert.equal(off.calls[0].url,'https://counter.example/views');
 assert.equal((await browser({enabled:false})).calls.length,0);assert.equal((await browser({fail:true})).element.hidden,true);
});
