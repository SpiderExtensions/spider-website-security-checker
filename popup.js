const $ = id => document.getElementById(id);
let activeTab = null;
const setStatus = (score, verdict, summary, color, confidence='LOCAL PAGE ANALYSIS') => {
  $('scoreValue').textContent = score == null ? '--' : score;
  $('scoreRing').style.setProperty('--ring', color);
  $('scoreRing').style.background = `conic-gradient(${color} 0deg ${Math.max(0,Math.min(100,score||0))*3.6}deg,#29283e ${Math.max(0,Math.min(100,score||0))*3.6}deg 360deg)`;
  $('verdict').textContent = verdict; $('verdict').style.color = color;
  $('summary').textContent = summary; $('confidence').textContent = confidence;
};
function renderFindings(items){
  $('findingCount').textContent = `${items.length} SIGNAL${items.length===1?'':'S'}`;
  $('findingsList').innerHTML = items.map((f,i)=>`<div class="finding ${f.level}" style="animation-delay:${i*45}ms"><div class="finding-icon">${f.level==='good'?'✓':f.level==='bad'?'!':'◇'}</div><div class="finding-text"><div class="finding-title">${escapeHtml(f.title)}</div><div class="finding-desc">${escapeHtml(f.detail)}</div><div class="finding-tag">${f.level.toUpperCase()}</div></div></div>`).join('');
}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function getTab(){const tabs=await chrome.tabs.query({active:true,currentWindow:true});return tabs[0];}
async function loadTarget(){
  try{activeTab=await getTab();const u=new URL(activeTab.url);$('siteUrl').textContent=u.hostname;$('protocolMeta').textContent=`${u.protocol.replace(':','').toUpperCase()}  ·  ${u.port?`PORT ${u.port}`:'DEFAULT PORT'}  ·  READY`;
  }catch(e){$('siteUrl').textContent='This browser page cannot be scanned';$('protocolMeta').textContent='Open a regular website tab to begin';$('scanBtn').disabled=true;setStatus(null,'UNAVAILABLE','Browser internal pages cannot be inspected.','#ffc65c');}
}
async function scan(){
  if(!activeTab)return;
  $('scanBtn').disabled=true;$('buttonText').textContent='SCANNING WEBSITE';$('progressWrap').classList.remove('hidden');$('progressText').textContent='Inspecting page security signals';
  setStatus(null,'ANALYSING…','Checking connection, forms, embedded resources and URL patterns.','#8c7bff');
  try{
    const injected=await chrome.scripting.executeScript({target:{tabId:activeTab.id},func:()=>{
      const u=new URL(location.href), findings=[];let risk=0;
      const add=(level,title,detail,points=0)=>{findings.push({level,title,detail});risk+=points;};
      if(u.protocol==='https:')add('good','Encrypted connection','The page is loaded over HTTPS. This protects data in transit but does not prove the site is trustworthy.');
      else if(['http:'].includes(u.protocol))add('bad','No HTTPS encryption','The page uses plain HTTP. Information sent to it may be intercepted.',24);
      else add('warn','Unusual page protocol',`The page uses ${u.protocol}. Browser pages may not be inspectable.`,5);
      if(/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname))add('warn','IP address host','The site uses a raw IP address instead of a domain name.',10);
      if(u.hostname.split('.').length>=5)add('warn','Deep subdomain structure','Many subdomain levels can be used for misleading URLs; check the domain carefully.',7);
      const suspiciousWords=/(login|verify|secure|account|update|wallet|payment|signin|password|gift|prize|claim)/i;
      if(suspiciousWords.test(u.hostname) && /[-_]/.test(u.hostname))add('warn','Potentially deceptive domain','The hostname combines sensitive terms and separators. This is only a heuristic.',8);
      if(u.username||u.password)add('bad','Credentials embedded in URL','This URL contains a username or password before the hostname.',20);
      const forms=[...document.forms];let insecureForms=0,externalForms=0;
      for(const f of forms){const action=f.getAttribute('action')||location.href;try{const a=new URL(action,location.href);if(a.protocol!=='https:'&&a.protocol!=='http:')continue;if(a.protocol==='http:'&&location.protocol==='https:')insecureForms++;if(a.hostname!==u.hostname)externalForms++;}catch{}}
      if(insecureForms)add('bad','Insecure form destination',`${insecureForms} form(s) submit to an unencrypted HTTP destination.`,20);
      if(externalForms)add('warn','External form destination',`${externalForms} form(s) submit to a different hostname. This can be legitimate, but verify the recipient.`,7);
      const mixed=[...document.querySelectorAll('img[src],script[src],iframe[src],link[href],audio[src],video[src]')].filter(el=>{const raw=el.getAttribute('src')||el.getAttribute('href');try{return new URL(raw,location.href).protocol==='http:'&&location.protocol==='https:'}catch{return false}}).length;
      if(mixed)add('warn','Mixed-content references',`${mixed} resource(s) reference HTTP from this HTTPS page. Browsers may block some of them.`,9);else if(location.protocol==='https:')add('good','No obvious mixed content','No HTTP resource references were found among common page elements.');
      const frames=[...document.querySelectorAll('iframe')].filter(f=>{try{return new URL(f.src,location.href).hostname!==u.hostname}catch{return false}}).length;
      if(frames)add('warn','Third-party embedded frames',`${frames} iframe(s) load from another hostname. This is common, but embedded content deserves caution.`,4);
      const passwordFields=document.querySelectorAll('input[type="password"]').length;
      if(passwordFields&&location.protocol!=='https:')add('bad','Password field on HTTP page','A password field is present without HTTPS encryption.',20);
      if(!findings.length)add('warn','Limited page signals','The page exposed few signals that can be checked locally.',4);
      const title=document.title||u.hostname;
      return {url:location.href,host:u.hostname,title,findings,risk:Math.min(100,risk),counts:{forms:forms.length,frames:frames.length,mixed}};
    }});
    const data=injected?.[0]?.result;if(!data)throw new Error('No scan data returned');
    $('progressText').textContent='Checking public reputation signals';
    let remote={status:'unavailable',detail:'Public reputation lookup did not return a result.'};
    try{
      const resp=await fetch(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent('domain:'+new URL(data.url).hostname)}&size=1`,{headers:{'Accept':'application/json'}});
      if(resp.ok){const json=await resp.json();const result=json.results?.[0];if(result){const verdict=result.verdicts?.overall; if(verdict?.malicious===true){data.risk=Math.min(100,data.risk+45);data.findings.unshift({level:'bad',title:'Public scan flagged this domain',detail:'A recent public URL scan reports a malicious verdict. Avoid entering sensitive information.'});remote={status:'flagged',detail:'A public URL scan returned a malicious verdict.'};}else remote={status:'found',detail:'Public scan records exist, but a clean result does not guarantee safety.'};}else remote={status:'none',detail:'No matching public scan was found; this is not proof of safety.'};}
    }catch(e){remote={status:'unavailable',detail:'Public reputation service was unavailable or rate-limited.'};}
    const score=Math.min(98,Math.max(0,100-data.risk));let color,verdict,summary;
    if(data.risk>=35){color='#ff547b';verdict='HIGH RISK';summary='Several warning signs were detected. Avoid logging in, downloading files, or sharing payment details.';}
    else if(data.risk>=15){color='#ffc65c';verdict='USE CAUTION';summary='Some risk indicators were detected. Verify the domain and avoid sensitive actions until you trust it.';}
    else{color='#52e5b0';verdict='LOWER RISK';summary='Few common warning signs were found. This does not mean the website is guaranteed safe.';}
    if(remote.status==='flagged'){color='#ff547b';verdict='POTENTIALLY DANGEROUS';summary='A public scan flagged this domain. Leave the site and do not enter sensitive information.';}
    const conf=remote.status==='found'?'LOCAL + PUBLIC SCAN RECORD':remote.status==='flagged'?'LOCAL + PUBLIC WARNING':remote.status==='none'?'LOCAL ANALYSIS · NO PUBLIC RECORD':'LOCAL PAGE ANALYSIS · REPUTATION UNAVAILABLE';
    setStatus(score,verdict,summary,color,conf);renderFindings(data.findings);
    if(remote.status==='none'||remote.status==='unavailable'){$('findingsList').insertAdjacentHTML('beforeend',`<div class="finding warn"><div class="finding-icon">◇</div><div class="finding-text"><div class="finding-title">Public reputation check</div><div class="finding-desc">${escapeHtml(remote.detail)}</div><div class="finding-tag">LIMITATION</div></div></div>`);}
    $('protocolMeta').textContent=`${new URL(data.url).protocol.replace(':','').toUpperCase()} · SCAN COMPLETE · ${new Date().toLocaleTimeString()}`;
    await chrome.storage.local.set({lastScan:{url:data.url,score,verdict,at:Date.now()}});
  }catch(err){setStatus(null,'SCAN FAILED','Could not inspect this tab. Refresh the page or try a regular website tab.','#ffc65c');renderFindings([{level:'warn',title:'Page inspection unavailable',detail:'Some pages block script injection or are restricted by the browser.'}]);}
  finally{$('scanBtn').disabled=false;$('buttonText').textContent='SCAN AGAIN';$('progressWrap').classList.add('hidden');}
}
$('scanBtn').addEventListener('click',scan);loadTarget();
