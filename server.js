'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const ROOT=__dirname, PUB=path.join(ROOT,'public'), DATA=path.join(ROOT,'data','portal.json'), CFG=path.join(ROOT,'data','admin.json');
let PORT=Number(process.env.PORT||3045), HOST=process.env.HOST||'127.0.0.1';
const INITIAL_PASSWORD=crypto.randomBytes(21).toString('base64url');
const MAX_BODY=90000, TTL=12*60*60*1000;
// Nenhum filtro por Discord, jogador conectado ou servidor MTA.
// O status ao vivo vem somente da plataforma ou da opção manual de administrador.
const platformDomains={twitch:['twitch.tv','www.twitch.tv'],youtube:['youtube.com','www.youtube.com','youtu.be'],tiktok:['tiktok.com','www.tiktok.com'],kick:['kick.com','www.kick.com']};
for (const line of (fs.existsSync(path.join(ROOT,'.env'))?fs.readFileSync(path.join(ROOT,'.env'),'utf8'):'').split(/\r?\n/)){
  const m=line.match(/^([A-Z][A-Z0-9_]*)=(.*)$/); if(m && process.env[m[1]]===undefined) process.env[m[1]]=m[2].replace(/^['"]|['"]$/g,'');
}
PORT=Number(process.env.PORT||3045);HOST=process.env.HOST||'127.0.0.1';
fs.mkdirSync(path.dirname(DATA),{recursive:true});
const initial = ()=>({streamers:[
  {id:'demo1',name:'Streamer Exemplo',platform:'twitch',handle:'complexo_exemplo',url:'https://www.twitch.tv/complexo_exemplo',bio:'Exemplo de perfil. Substitua por um streamer real pelo painel.',photo:'',banner:'',manualStatus:'offline',featured:true,demo:true,createdAt:Date.now()},
  {id:'demo2',name:'Criador do Complexo',platform:'youtube',handle:'@canalexemplo',url:'https://www.youtube.com/@canalexemplo',bio:'Cadastre o link do canal para atualizar os dados oficiais.',photo:'',banner:'',manualStatus:'offline',featured:false,demo:true,createdAt:Date.now()},
  {id:'demo3',name:'Parceiro em Destaque',platform:'kick',handle:'exemplo',url:'https://kick.com/exemplo',bio:'O visual se adapta a qualquer canal aprovado.',photo:'',banner:'',manualStatus:'offline',featured:false,demo:true,createdAt:Date.now()}
 ],team:[
  {id:'team1',name:'A definir',role:'Direção Geral',department:'Diretoria',photo:'',bio:'Cadastre o responsável e sua foto no painel.',priority:1,demo:true},
  {id:'team2',name:'A definir',role:'Coordenação',department:'Gestão',photo:'',bio:'Cargo demonstrativo editável.',priority:2,demo:true},
  {id:'team3',name:'A definir',role:'Gestão de Streamers',department:'Comunidade',photo:'',bio:'Cargo demonstrativo editável.',priority:3,demo:true}
 ],applications:[],ranking:{},settings:{discord:'https://discord.gg/complexorp',heroEyebrow:'O PRÓXIMO CAPÍTULO COMEÇA AQUI',heroTitle:'SUA HISTÓRIA. NOSSO COMPLEXO.',heroText:'Uma cidade de novas conexões, histórias marcantes e roleplay para quem vive cada detalhe.',rules:[{title:'Respeito acima de tudo',description:'Trate todos os jogadores e a equipe com respeito. Preconceito, assédio e ofensas não são permitidos.'},{title:'Roleplay responsável',description:'Valorize a interpretação e respeite as situações da cidade. Evite atitudes antirroleplay.'},{title:'Fair play',description:'É proibido utilizar programas ou vantagens indevidas que prejudiquem a experiência dos demais.'},{title:'Siga as orientações da equipe',description:'A equipe é responsável por mediar conflitos e fazer cumprir as regras completas publicadas no Discord.'}]}});
function atomic(file,obj){const tmp=file+'.tmp';fs.writeFileSync(tmp,JSON.stringify(obj,null,2)+'\n',{mode:0o600});fs.renameSync(tmp,file);}
if(!fs.existsSync(DATA))atomic(DATA,initial());
let db=JSON.parse(fs.readFileSync(DATA,'utf8'));
function passwd(password,salt){return crypto.scryptSync(password,salt,64).toString('hex');}
if(!fs.existsSync(CFG)){if(!process.env.ADMIN_PASSWORD)console.warn('SENHA INICIAL GERADA: '+INITIAL_PASSWORD+' (salve antes de fechar)');const salt=crypto.randomBytes(24).toString('hex');atomic(CFG,{salt,hash:passwd(process.env.ADMIN_PASSWORD||INITIAL_PASSWORD,salt)});}
let cfg=JSON.parse(fs.readFileSync(CFG,'utf8'));
const sessions=new Map(), attempts=new Map(), applicantAttempts=new Map();
const now=()=>Date.now();
function save(){atomic(DATA,db);}
function cmpPassword(password){try{return crypto.timingSafeEqual(Buffer.from(passwd(password,cfg.salt),'hex'),Buffer.from(cfg.hash,'hex'));}catch{return false;}}
function sid(req){return ((req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('cpxsid='))||'').slice(7);}
function admin(req){const s=sessions.get(sid(req));if(!s)return false;if(s.exp<now()){sessions.delete(sid(req));return false;}return true;}
function cookie(req,token,expire=false){const secure=req.socket.encrypted||process.env.FORCE_HTTPS==='1';return `cpxsid=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${expire?0:43200}${secure?'; Secure':''}`;}
function json(res,status,data,h={}){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...h});res.end(JSON.stringify(data));}
function error(res,status,msg){json(res,status,{error:msg});}
function fail(status,msg){const e=new Error(msg);e.status=status;throw e;}
async function body(req,max=MAX_BODY){let raw='',len=0;for await(const chunk of req){len+=chunk.length;if(len>max)fail(413,'Envio muito grande.');raw+=chunk;}let b;try{b=JSON.parse(raw);}catch{fail(400,'JSON inválido.');}if(!b||typeof b!=='object'||Array.isArray(b))fail(400,'Dados inválidos.');return b;}
function str(v,n=160){return String(v==null?'':v).trim().slice(0,n);}
function url(v,platform){let u;try{u=new URL(str(v,1500));}catch{fail(400,'Informe um link HTTPS completo.');}if(u.protocol!=='https:'||u.username||u.password)fail(400,'Somente URLs HTTPS válidas.');if(platform&&!platformDomains[platform].includes(u.hostname.toLowerCase()))fail(400,'O link não corresponde à plataforma.');return u.toString();}
function optUrl(v){const x=str(v,1500);return /^\/uploads\/[a-f0-9]{36}\.(png|jpg|webp)$/.test(x)?x:(x?url(x):'');}
function streamerForm(b,old={}){
  const name=str(b.name,70), platform=str(b.platform,12).toLowerCase(), handle=str(b.handle,100), link=url(b.url,platform);
  if(name.length<2)fail(400,'Informe o nome do streamer.');if(!platformDomains[platform])fail(400,'Plataforma inválida.');if(!handle)fail(400,'Informe o usuário/ID do canal.');
  return {...old,id:old.id||crypto.randomUUID(),name,platform,handle,url:link,bio:str(b.bio,220),photo:optUrl(b.photo),banner:optUrl(b.banner),manualStatus:['auto','offline','manual-live'].includes(b.manualStatus)?b.manualStatus:'auto',manualTitle:str(b.manualTitle,140),featured:!!b.featured,demo:false,createdAt:old.createdAt||now(),updatedAt:now(),youtubeId:platform==='youtube'?(str(b.youtubeId,36)||old.youtubeId||''):''};
}
function teamForm(b,old={}){const name=str(b.name,70),role=str(b.role,70);if(!name||!role)fail(400,'Informe nome e cargo.');return {...old,id:old.id||crypto.randomUUID(),name,role,department:str(b.department,50),photo:optUrl(b.photo),bio:str(b.bio,240),priority:Math.max(0,Math.min(999,Number(b.priority)||10)),demo:false};}
function appForm(b){const platform=str(b.platform,12).toLowerCase();if(!platformDomains[platform])fail(400,'Plataforma inválida.');const link=url(b.url,platform);const handle=(new URL(link).pathname.split('/').filter(Boolean).pop()||'').slice(0,100);if(!handle)fail(400,'Informe o link direto do canal.');return {id:crypto.randomUUID(),platform,url:link,name:str(b.name,70)||handle,handle,createdAt:now(),status:'pending'};}
function sameOrigin(req){const origin=req.headers.origin;if(!origin){const site=req.headers['sec-fetch-site'];return !site||['same-origin','none'].includes(site);}try{return new URL(origin).host===req.headers.host;}catch{return false;}}
function limit(map,key,max,windowMs){let v=map.get(key);if(!v||v.until<now())v={num:0,until:now()+windowMs};v.num++;map.set(key,v);return v.num<=max;}
function publicStreamer(s){
 const live=liveCache.get(s.id)||{};
 const maxAge=s.platform==='youtube'?36*60*1000:4*60*1000;
 const platformLive=Boolean(live.verified&&live.isLive&&live.checkedAt&&now()-live.checkedAt<maxAge);
 const manualLive=s.manualStatus==='manual-live';
 const isLive=manualLive||(s.manualStatus!=='offline'&&platformLive);
 return {id:s.id,name:s.name,platform:s.platform,url:s.url,handle:s.handle,bio:s.bio,photo:s.photo||live.photo||'',banner:s.banner||live.banner||'',isLive,platformLive,manualLive,verified:!manualLive&&platformLive,updatedAt:live.checkedAt||null,viewers:isLive&&!manualLive?live.viewers??null:null,title:isLive?(manualLive?s.manualTitle||'Ao vivo no canal':live.title||'Transmissão ao vivo'):'',startedAt:isLive&&!manualLive?live.startedAt||null:null,followers:live.followers??null,featured:s.featured,demo:!!s.demo};
}
function localDay(){return new Intl.DateTimeFormat('sv-SE',{year:'numeric',month:'2-digit',day:'2-digit',timeZone:'America/Sao_Paulo'}).format(new Date());}
function monthly(){return localDay().slice(0,7);}
function publicBundle(){const streamers=db.streamers.map(publicStreamer).sort((a,b)=>Number(b.isLive)-Number(a.isLive)||Number(b.viewers||0)-Number(a.viewers||0)||Number(b.followers||0)-Number(a.followers||0)||a.name.localeCompare(b.name,'pt-BR'));
  const ranking=Object.entries(db.ranking[monthly()]||{}).map(([id,v])=>{const s=db.streamers.find(x=>x.id===id);return s?{id,name:s.name,photo:s.photo||liveCache.get(id)?.photo||'',minutes:v.minutes||0,days:Object.keys(v.days||{}).length,isLive:!!streamers.find(x=>x.id===id)?.isLive,platform:s.platform}:null;}).filter(Boolean).sort((a,b)=>b.minutes-a.minutes).slice(0,10);
  return {streamers,team:db.team.slice().sort((a,b)=>a.priority-b.priority),ranking,settings:db.settings,month:monthly(),updatedAt:syncTime,api:{twitch:!!(process.env.TWITCH_CLIENT_ID&&process.env.TWITCH_CLIENT_SECRET),kick:!!(process.env.KICK_CLIENT_ID&&process.env.KICK_CLIENT_SECRET),youtube:!!process.env.YOUTUBE_API_KEY,tiktok:false}};}
const liveCache=new Map();let syncTime=null, syncBusy=false, lastMinute=0;
async function fetchJson(endpoint,opts={}){const r=await fetch(endpoint,{...opts,signal:AbortSignal.timeout(9500)});if(!r.ok)throw Error('API HTTP '+r.status);return r.json();}
const oauth={};async function token(type,id,secret){if(oauth[type]&&oauth[type].exp>now())return oauth[type].token;const req=type==='twitch'?'https://id.twitch.tv/oauth2/token':'https://id.kick.com/oauth/token';const j=await fetchJson(req,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'client_credentials',client_id:id,client_secret:secret})});oauth[type]={token:j.access_token,exp:now()+(Number(j.expires_in||3600)-90)*1000};return j.access_token;}
function chunks(xs,n){const r=[];for(let i=0;i<xs.length;i+=n)r.push(xs.slice(i,i+n));return r;}
async function syncTwitch(){const channels=db.streamers.filter(s=>s.platform==='twitch'&&s.manualStatus==='auto');if(!channels.length||!process.env.TWITCH_CLIENT_ID||!process.env.TWITCH_CLIENT_SECRET)return;
 const id=process.env.TWITCH_CLIENT_ID,t=await token('twitch',id,process.env.TWITCH_CLIENT_SECRET),h={'Client-ID':id,Authorization:'Bearer '+t};
 for(const group of chunks(channels,90)){
   const q=new URLSearchParams();for(const s of group)q.append('login',s.handle.replace(/^@/,''));
   const users=(await fetchJson('https://api.twitch.tv/helix/users?'+q,{headers:h})).data||[];
   const byLogin=new Map(users.map(u=>[u.login.toLowerCase(),u]));
   const lq=new URLSearchParams();for(const s of group)lq.append('user_login',s.handle.replace(/^@/,''));
   const streams=(await fetchJson('https://api.twitch.tv/helix/streams?'+lq,{headers:h})).data||[];
   const byStream=new Map(streams.map(v=>[v.user_login.toLowerCase(),v]));
   for(const s of group){const u=byLogin.get(s.handle.replace(/^@/,'').toLowerCase()),v=byStream.get(s.handle.replace(/^@/,'').toLowerCase());
      const prev=liveCache.get(s.id)||{};liveCache.set(s.id,{...prev,verified:true,checkedAt:now(),isLive:!!v,photo:u?.profile_image_url||prev.photo||'',followers:prev.followers??null,description:u?.description||'',title:v?.title||'',banner:v?.thumbnail_url?.replace('{width}','800').replace('{height}','450')||u?.offline_image_url||prev.banner||'',viewers:v?.viewer_count??null,startedAt:v?.started_at||null});
      if(u&&(!prev.followersChecked||now()-prev.followersChecked>90*60*1000)){
        try{const f=await fetchJson('https://api.twitch.tv/helix/channels/followers?broadcaster_id='+encodeURIComponent(u.id),{headers:h});const rec=liveCache.get(s.id);rec.followers=f.total??rec.followers;rec.followersChecked=now();}catch(e){/* follower API may have additional permissions */}
      }
   }
 }
}
async function syncKick(){const arr=db.streamers.filter(s=>s.platform==='kick'&&s.manualStatus==='auto');if(!arr.length||!process.env.KICK_CLIENT_ID||!process.env.KICK_CLIENT_SECRET)return;
 const t=await token('kick',process.env.KICK_CLIENT_ID,process.env.KICK_CLIENT_SECRET);for(const group of chunks(arr,45)){
  const q=new URLSearchParams();for(const s of group)q.append('slug',s.handle.replace(/^@/,''));const j=await fetchJson('https://api.kick.com/public/v1/channels?'+q,{headers:{Authorization:'Bearer '+t}});
  const m=new Map((j.data||[]).map(x=>[String(x.slug||'').toLowerCase(),x]));
  for(const s of group){const ch=m.get(s.handle.toLowerCase());const v=ch?.stream,prev=liveCache.get(s.id)||{};
    liveCache.set(s.id,{...prev,verified:!!ch,checkedAt:now(),isLive:!!v?.is_live,title:ch?.stream_title||'',photo:ch?.profile_picture||prev.photo||'',banner:v?.thumbnail||ch?.banner_picture||prev.banner||'',viewers:v?.is_live?v.viewer_count??null:null,startedAt:v?.is_live?v.start_time||null:null});
  }
 }
}
let youtubeSearchCount=0,youtubeQuotaDate='';let youtubeIndex=0;
async function syncYouTube(){const key=process.env.YOUTUBE_API_KEY,arr=db.streamers.filter(s=>s.platform==='youtube'&&s.manualStatus==='auto');if(!key||!arr.length)return;
 // fetch channel metadata for small groups; live search is expensive and bounded globally by the daily search limit
 for(const group of chunks(arr,45)){
   const ids=[];for(const s of group){if(!s.youtubeId){const q=new URLSearchParams({part:'snippet,statistics',forHandle:s.handle.replace(/^@/,'@'),key});try{const x=(await fetchJson('https://www.googleapis.com/youtube/v3/channels?'+q)).items?.[0];if(x){s.youtubeId=x.id;save();}}catch{}}
     if(s.youtubeId)ids.push(s.youtubeId);
   }
   if(!ids.length)continue;
   const q=new URLSearchParams({part:'snippet,statistics',id:ids.join(','),key});const j=await fetchJson('https://www.googleapis.com/youtube/v3/channels?'+q);const m=new Map((j.items||[]).map(x=>[x.id,x]));
   for(const s of group){const item=m.get(s.youtubeId),prev=liveCache.get(s.id)||{};if(!item)continue;
     liveCache.set(s.id,{...prev,verified:prev.verified||false,photo:item.snippet?.thumbnails?.high?.url||item.snippet?.thumbnails?.default?.url||prev.photo||'',followers:item.statistics?.hiddenSubscriberCount?null:Number(item.statistics?.subscriberCount)||null,checkedAt:now()});
   }
 }
 const today=new Date().toISOString().slice(0,10);if(today!==youtubeQuotaDate){youtubeQuotaDate=today;youtubeSearchCount=0;}
 const max=Math.max(0,Math.min(90,Number(process.env.YOUTUBE_DAILY_SEARCH_LIMIT||30)));
 const available=arr.filter(x=>x.youtubeId);if(!available.length||youtubeSearchCount>=max)return;
 // Never claim a 1-minute refresh for YouTube: rotate through approved channels to conserve API quota.
 const s=available[youtubeIndex++%available.length];youtubeSearchCount++;
 try{const q=new URLSearchParams({part:'snippet',channelId:s.youtubeId,eventType:'live',type:'video',maxResults:'1',key});const j=await fetchJson('https://www.googleapis.com/youtube/v3/search?'+q);const item=j.items?.[0];const prev=liveCache.get(s.id)||{};
   liveCache.set(s.id,{...prev,verified:true,checkedAt:now(),isLive:!!item,title:item?.snippet?.title||'',banner:item?.snippet?.thumbnails?.high?.url||prev.banner||'',startedAt:item?.snippet?.publishedAt||null,viewers:null});
 }catch(e){console.warn('YouTube live:',e.message);}
}
function trackRanking(){const n=now(),month=monthly(),elapsed=lastMinute?Math.min(2,Math.floor((n-lastMinute)/60000)):0;lastMinute=n;if(!elapsed)return;const r=db.ranking[month]||={};
 for(const s of db.streamers){const l=publicStreamer(s);if(l.isLive&&l.verified&&!s.demo){const v=r[s.id]||={minutes:0,days:{}};v.minutes+=elapsed;v.days[localDay()]=true;}}save();}
async function synchronize(){if(syncBusy)return;syncBusy=true;const tasks=[['Twitch',syncTwitch],['Kick',syncKick]];for(const [name,fn] of tasks){try{await fn();}catch(e){console.warn(name,e.message);}}
 // YouTube profile + live search is capped to every 30 minutes rather than each poll
 if(!synchronize.lastYoutube||now()-synchronize.lastYoutube>30*60*1000){synchronize.lastYoutube=now();try{await syncYouTube();}catch(e){console.warn('YouTube',e.message);}}
 syncTime=new Date().toISOString();syncBusy=false;}
const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon','.webp':'image/webp'};
const routes={'/':'index.html','/streamers':'index.html','/equipe':'index.html','/como-jogar':'index.html','/regras':'index.html','/admin':'admin.html'};
const server=http.createServer(async(req,res)=>{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');res.setHeader('X-Frame-Options','DENY');res.setHeader('Content-Security-Policy',"default-src 'self'; img-src 'self' https: data:; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
 let p;try{p=new URL(req.url,'http://localhost').pathname;}catch{return error(res,400,'Endereço inválido.');}
 if(p.startsWith('/api/')){
  try{
   if(!['GET','POST','PUT','DELETE'].includes(req.method))fail(405,'Método inválido.');
   if(req.method!=='GET'&&!sameOrigin(req))fail(403,'Origem inválida.');
   if(['POST','PUT'].includes(req.method)&&!String(req.headers['content-type']||'').startsWith('application/json'))fail(415,'Use JSON.');
   if(p==='/api/public'&&req.method==='GET')return json(res,200,publicBundle());
   if(p==='/api/session'&&req.method==='GET')return json(res,200,{authenticated:admin(req),api:{twitch:!!(process.env.TWITCH_CLIENT_ID&&process.env.TWITCH_CLIENT_SECRET),youtube:!!process.env.YOUTUBE_API_KEY,kick:!!(process.env.KICK_CLIENT_ID&&process.env.KICK_CLIENT_SECRET)}});
   if(p==='/api/login'&&req.method==='POST'){
     const ip=req.socket.remoteAddress||'local';if(!limit(attempts,ip,10,15*60000))fail(429,'Muitas tentativas; tente novamente em 15 minutos.');const b=await body(req);
     if(!cmpPassword(String(b.password||'')))fail(401,'Senha incorreta.');attempts.delete(ip);const s=crypto.randomBytes(32).toString('hex');sessions.set(s,{exp:now()+TTL});return json(res,200,{ok:true},{'Set-Cookie':cookie(req,s)});
   }
   if(p==='/api/apply'&&req.method==='POST'){
     if(!limit(applicantAttempts,req.socket.remoteAddress||'local',6,60*60000))fail(429,'Limite de inscrições atingido.');const b=appForm(await body(req));
     if(db.applications.some(x=>x.status==='pending'&&x.url===b.url))fail(409,'Já existe uma inscrição pendente para este canal.');
     db.applications.unshift(b);save();return json(res,201,{ok:true,message:'Pedido enviado! A equipe analisará a inscrição.'});
   }
   if(!p.startsWith('/api/admin/'))fail(404,'Rota não encontrada.');
   if(!admin(req))fail(401,'Acesso restrito à equipe.');
   if(p==='/api/admin/all'&&req.method==='GET')return json(res,200,{...db,public:publicBundle()});
   if(p==='/api/admin/upload'&&req.method==='POST'){
     const b=await body(req,2600000);const raw=str(b.data,2600000), match=raw.match(/^data:image\/(png|jpeg|webp);base64,([a-zA-Z0-9+/=]+)$/);
     if(!match)fail(400,'Envie imagem PNG, JPG ou WEBP válida.');const contents=Buffer.from(match[2],'base64');if(contents.length>1600000||contents.length<50)fail(413,'Imagem precisa ter até 1,6 MB.');
     const valid=match[1]==='png'?contents.subarray(0,8).equals(Buffer.from('89504e470d0a1a0a','hex')):match[1]==='jpeg'?(contents[0]===255&&contents[1]===216&&contents[2]===255):(contents.toString('ascii',0,4)==='RIFF'&&contents.toString('ascii',8,12)==='WEBP');
     if(!valid)fail(400,'Conteúdo da imagem inválido.');const ext=match[1]==='jpeg'?'jpg':match[1];const folder=path.join(PUB,'uploads');fs.mkdirSync(folder,{recursive:true});const file=crypto.randomBytes(18).toString('hex')+'.'+ext;fs.writeFileSync(path.join(folder,file),contents,{flag:'wx'});return json(res,201,{url:'/uploads/'+file});
   }
   if(p==='/api/admin/logout'&&req.method==='POST'){sessions.delete(sid(req));return json(res,200,{ok:true},{'Set-Cookie':cookie(req,'',true)});}
   if(p==='/api/admin/password'&&req.method==='PUT'){const b=await body(req);if(!cmpPassword(String(b.current||'')))fail(403,'Senha atual inválida.');if(String(b.next||'').length<12)fail(400,'Nova senha precisa ter no mínimo 12 caracteres.');const salt=crypto.randomBytes(24).toString('hex');cfg={salt,hash:passwd(String(b.next),salt)};atomic(CFG,cfg);sessions.clear();return json(res,200,{ok:true});}
   if(p==='/api/admin/streamers'&&req.method==='POST'){const b=streamerForm(await body(req));if(db.streamers.some(x=>x.platform===b.platform&&x.url===b.url))fail(409,'Canal já cadastrado.');db.streamers.push(b);save();return json(res,201,b);}
   if(p==='/api/admin/team'&&req.method==='POST'){const b=teamForm(await body(req));db.team.push(b);save();return json(res,201,b);}
   if(p==='/api/admin/settings'&&req.method==='PUT'){const b=await body(req),s=b.settings||{};db.settings={...db.settings,discord:url(s.discord||db.settings.discord),heroEyebrow:str(s.heroEyebrow,90),heroTitle:str(s.heroTitle,120),heroText:str(s.heroText,230)};save();return json(res,200,{ok:true});}
   if(p==='/api/admin/rules'&&req.method==='PUT'){const b=await body(req);if(!Array.isArray(b.rules)||b.rules.length>40)fail(400,'Regras inválidas.');db.settings.rules=b.rules.map(x=>({title:str(x.title,110),description:str(x.description,600)})).filter(x=>x.title&&x.description);save();return json(res,200,{ok:true});}
   let m=p.match(/^\/api\/admin\/(streamers|team)\/([a-zA-Z0-9_-]+)$/);
   if(m){const items=db[m[1]],ix=items.findIndex(x=>x.id===m[2]);if(ix<0)fail(404,'Registro não encontrado.');if(req.method==='DELETE'){items.splice(ix,1);save();return json(res,200,{ok:true});}if(req.method==='PUT'){const b=m[1]==='streamers'?streamerForm(await body(req),items[ix]):teamForm(await body(req),items[ix]);items[ix]=b;save();return json(res,200,b);}}
   m=p.match(/^\/api\/admin\/applications\/([a-zA-Z0-9_-]+)\/(approve|reject)$/);
   if(m&&req.method==='POST'){
     const a=db.applications.find(x=>x.id===m[1]);if(!a||a.status!=='pending')fail(404,'Inscrição pendente não encontrada.');a.status=m[2]==='approve'?'approved':'rejected';a.reviewedAt=now();
     if(a.status==='approved'&&!db.streamers.some(x=>x.url===a.url))db.streamers.push(streamerForm({name:a.name,platform:a.platform,handle:a.handle,url:a.url,manualStatus:'auto'}));save();return json(res,200,{ok:true});
   }
   fail(404,'Rota não encontrada.');
  }catch(e){return error(res,e.status||500,e.status?e.message:'Erro interno do servidor.');}
 }
 if(req.method!=='GET')return error(res,405,'Método não permitido.');
 const target=routes[p]||p.replace(/^\//,'');const resolved=path.resolve(PUB,target);if(!resolved.startsWith(PUB+path.sep))return error(res,403,'Acesso negado.');fs.readFile(resolved,(err,data)=>{if(err)return error(res,404,'Página não encontrada.');res.writeHead(200,{'Content-Type':types[path.extname(resolved)]||'application/octet-stream','Cache-Control':'public, max-age=120'});res.end(data);});
});
if(require.main===module){server.listen(PORT,HOST,()=>{
 console.log('\nCOMPLEXO RP — PORTAL NO AR');console.log('Site:  http://'+HOST+':'+PORT);console.log('Painel: http://'+HOST+':'+PORT+'/admin');
 console.log('Lives: APIs de Twitch/Kick/YouTube ou seleção manual no painel. Sem bot Discord/MTA.\n');
 synchronize();setInterval(synchronize,60000).unref();setInterval(trackRanking,60000).unref();
 });}
module.exports={server,initial,streamerForm,teamForm,appForm,publicBundle,publicStreamer,liveCache};
