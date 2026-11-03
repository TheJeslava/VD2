'use strict';
const $ = id => document.getElementById(id);
const glyphs = {
 grid:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
 history:'<path d="M3 5v5h5M3 10a9 9 0 1 1 1 7M12 7v5l3 2"/>',
 settings:'<path d="m9 3 1-1h4l1 3 3 1 2-1 2 4-2 2v3l2 2-2 4-3-1-2 1-1 2h-4l-1-2-3-1-2 1-2-4 2-2v-3L2 9l2-4 3 1 2-1z"/><circle cx="12" cy="12" r="3"/>',
 archive:'<rect x="3" y="4" width="18" height="4" rx="1"/><path d="M5 8v12h14V8m-10 4h6"/>',
 sliders:'<path d="M4 6h7m4 0h5M4 12h2m4 0h10M4 18h10m4 0h2"/><circle cx="13" cy="6" r="2"/><circle cx="8" cy="12" r="2"/><circle cx="16" cy="18" r="2"/>',
 terminal:'<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m6 9 3 3-3 3m6 0h5"/>',
 activity:'<path d="M2 12h5l3-8 4 16 3-8h5"/>',globe:'<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4.5" ry="9"/><path d="M3 12h18"/>',
 upload:'<path d="M5 15v5h14v-5M12 16V3m-5 5 5-5 5 5"/>',
 link:'<path d="m10 14 4-4m-6 4-1 1a3 3 0 0 0 4 4l3-3a4 4 0 0 0 0-6m2 0 1-1a3 3 0 0 0-4-4l-3 3a4 4 0 0 0 0 6"/>',
 shield:'<path d="m12 2 8 3v6c0 5-4 9-8 11-4-2-8-6-8-11V5z"/><path d="m8 12 3 3 5-6"/>',
 play:'<path d="m6 3 14 9-14 9z" fill="currentColor" stroke="none"/>',x:'<path d="m6 6 12 12M18 6 6 18"/>',
 file:'<path d="M5 3h9l5 5v13H5zM14 3v6h5M8 13h8m-8 4h6"/>',layers:'<path d="m12 3 10 5-10 5L2 8zm-9 10 9 5 9-5m-18 5 9 5 9-5"/>'
};
const icon = name => '<svg class="ico" aria-hidden="true" viewBox="0 0 24 24">'+glyphs[name]+'</svg>';
document.querySelectorAll('[data-icon]').forEach(el=>el.innerHTML=icon(el.dataset.icon));
const esc = value => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const when = time => new Date(time*1000).toLocaleTimeString('zh-CN',{hour12:false});
const stamp = time => new Date(time*1000).toLocaleString('zh-CN',{hour12:false});
const empty = (title,desc) => '<div class="empty">'+icon('layers')+'<div><strong>'+esc(title)+'</strong><p>'+esc(desc)+'</p></div></div>';
const defaults = {llm:false,off:[],noLlm:[]};
let prefs;
try { prefs=Object.assign({},defaults,JSON.parse(localStorage.getItem('vd2-prefs')||'{}')); } catch { prefs={...defaults}; }
const catalogue=[
 ['safety_guard','安全防护','隔离提示注入内容','all'],['surface_mapper','攻击面测绘','梳理端点与输入面','all',1],
 ['deep_finder','LLM 深挖','基于源码发现新候选','zip',1],['candidate_screener','候选筛选','筛选、去重并保留证据','all'],
 ['vulnerability_analyzer','漏洞分析','分析候选的来源与影响','all'],['second_order_analyzer','二次注入分析','追踪存储到触发的二阶链路','zip',1],
 ['logic_analyzer','隐性逻辑判定','审查业务规则与权限边界','zip',1],['poc_writer','POC 生成','生成复现步骤与请求工件','all'],
 ['coordinator','管线协调','去重、汇总并输出结论','all']];
const statusText={running:'进行中',done:'已完成',skipped:'已跳过',failed:'失败',warning:'有警告',idle:'待命'};
const verdictText={verified:'已证实',rejected:'未复现',inconclusive:'证据不足',unsupported:'不支持',error:'执行错误'};
const severityText={critical:'严重',high:'高危',medium:'中危',low:'低危',info:'信息'};
let mode='zip', file=null, current=null, findings=[], verdicts=[], jobs=[];
let timer=0, online=false, submitting=false, selection=0, phase='scan',resultTab='findings',view='work';
const busy = () => current && (current.status==='running'||current.verification==='running');
function showDialog(title,sub,html){
 $('dialogTitle').textContent=title;$('dialogSub').textContent=sub;$('dialogBody').innerHTML=html;
 if(!$('dialog').open)$('dialog').showModal();
}
$('close').onclick=()=>$('dialog').close();
$('dialog').addEventListener('click',e=>{if(e.target===$('dialog')){const r=$('dialog').getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)$('dialog').close();}});
let toastTimer;
function toast(msg){$('toast').textContent=msg;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').textContent='',3200);}
function settings(){
 const rows=catalogue.map(([id,label,hint,scope,opt])=>'<div class="settingsRow"><div><strong>'+label+'</strong><small>'+hint+' · '+(scope==='zip'?'ZIP':'ZIP / URL')+'</small></div>'+
 (opt?'<input class="switch mod" type="checkbox" data-id="'+id+'" aria-label="'+label+'模块" '+(!prefs.off.includes(id)?'checked':'')+'>':'<em>固定</em>')+
 '<input class="switch model" type="checkbox" data-id="'+id+'" aria-label="'+label+' LLM" '+(!prefs.noLlm.includes(id)?'checked':'')+'></div>').join('');
 showDialog('智能体设置','AGENT CONFIGURATION','<p class="help">配置在下一次挖掘时生效。启用 LLM 需要为本地执行器配置模型密钥。</p><label class="settingsRow"><strong>启用 LLM 辅助</strong><span></span><input id="llmMaster" class="switch" type="checkbox" '+(prefs.llm?'checked':'')+'></label><div class="settingsRow"><small>挖掘模块</small><em>模块</em><em>LLM</em></div>'+rows+
 '<p class="help" style="margin-top:14px">验证阶段固定执行 POC 收集、沙箱执行、证据研判和报告生成。各阶段使用 HTTP 证据进行判定。</p><div class="modalActions"><button class="primary" id="savePrefs">保存设置</button></div>');
 const toggle=()=>document.querySelectorAll('.model').forEach(box=>{const mod=document.querySelector('.mod[data-id="'+box.dataset.id+'"]');box.disabled=!$('llmMaster').checked||Boolean(mod&&!mod.checked);});
 $('llmMaster').onchange=toggle;document.querySelectorAll('.mod').forEach(box=>box.onchange=toggle);toggle();
 $('savePrefs').onclick=()=>{prefs={llm:$('llmMaster').checked,off:[...document.querySelectorAll('.mod:not(:checked)')].map(b=>b.dataset.id),noLlm:[...document.querySelectorAll('.model:not(:checked)')].map(b=>b.dataset.id)};
 try{localStorage.setItem('vd2-prefs',JSON.stringify(prefs));}catch{}$('dialog').close();if(!current)drawMonitor();toast('设置已保存，下次挖掘时生效');};
}
$('settings').onclick=$('navSettings').onclick=settings;
function setMode(next){
 mode=next;const zip=mode==='zip';$('zipMode').setAttribute('aria-pressed',String(zip));$('urlMode').setAttribute('aria-pressed',String(!zip));$('zipFields').hidden=!zip;
 $('urlLabel').textContent=zip?'关联靶场 URL':'目标 URL';$('optional').textContent=zip?'可选 · 启用 AWVS 探针':'必填 · AWVS 动态探测';
 $('url').required=!zip;$('formError').textContent='';if(!current)drawMonitor();
}
$('zipMode').onclick=()=>setMode('zip');$('urlMode').onclick=()=>setMode('url');
function pickFile(chosen){
 if(!chosen)return;
 if(!/\.zip$/i.test(chosen.name)||chosen.size>33554432){
   file=null;
   $('file').value='';
   $('fileTitle').textContent='点击选择或拖入 ZIP 文件';
   $('fileHint').textContent='.ZIP 格式　/　最大 32 MiB';
   $('formError').textContent='请选择不超过 32 MiB 的 .zip 文件';
   return;
 }
 file=chosen;$('fileTitle').textContent=file.name;$('fileHint').textContent=(file.size<1048576?Math.max(1,Math.ceil(file.size/1024))+' KiB':(file.size/1048576).toFixed(1)+' MiB')+'　/　点击更换文件';$('formError').textContent='';
}
$('file').onchange=e=>pickFile(e.target.files[0]);
for(const name of ['dragover','drop','dragleave'])$('drop').addEventListener(name,e=>{e.preventDefault();$('drop').classList.toggle('over',name==='dragover');if(name==='drop')pickFile(e.dataTransfer.files[0]);});
$('example').onclick=async()=>{
 try {
   const response=await fetch('lab-source.zip');
   if(!response.ok)throw Error('示例文件无法读取');
   pickFile(new File([await response.blob()],'lab-source.zip',{type:'application/zip'}));
   toast('已载入示例源码，提交后由本地引擎分析');
 } catch { $('formError').textContent='请从本地工作台服务打开页面，或手动选择 ZIP。'; }
};
function setView(next) {
 if (next !== view) {
   resetReview();
   resultTab = next === 'work' && current?.verification === 'done' ? 'verdicts' : 'findings';
 }
 view = next;
 const history = next === 'history', archive = next === 'archive';
 $('workView').hidden = history;
 $('historyView').hidden = !history;
 $('execution').hidden = $('executionLabel').hidden = archive;
 $('casePicker').hidden = !archive;
 $('crumb').textContent = history ? '任务历史' : archive ? '样例档案' : '分析工作台';
 $('pageTitle').textContent = history ? '任务历史' : archive ? '实验样例档案' : '漏洞研究工作台';
 $('subtitle').textContent = history ? '查看本地执行器保存的分析任务、证据与验证结果。'
   : archive ? '查看三份已归档的实验记录，对照源码、POC 与验证结论。' : '配置分析目标，跟踪智能体进度，逐条审阅漏洞证据。';
 $('browseCases').hidden = archive;
 document.querySelectorAll('[data-view]').forEach(b=>b.classList.toggle('active',b.dataset.view===next));
 if(history) loadHistory();
 if(archive) drawCases();
 if(!history) renderResults();
}
$('browseCases').onclick=()=>setView('archive');
document.querySelectorAll('[data-view]').forEach(b=>b.onclick=()=>setView(b.dataset.view));
function loadHistory(){
 $('history').innerHTML=jobs.map(j=>'<button class="historyRow" data-job="'+esc(j.id)+'">'+icon(j.mode==='zip'?'archive':'globe')+'<div><strong>'+esc(j.name)+'</strong><small>'+stamp(j.created)+' · '+kindName(j.kind)+' · '+esc(j.id)+'</small></div><span class="pill">'+esc(statusText[j.verification==='running'?'running':j.status])+'</span></button>').join('')||empty('暂无任务记录','完成第一次分析后，可在此重新打开结果。');
 $('history').querySelectorAll('[data-job]').forEach(b=>b.onclick=()=>{setView('work');openJob(b.dataset.job);});
}
const kindName = kind => ({zip:'ZIP 源码',url:'URL 探针',hybrid:'ZIP + URL'})[kind];
function setOnline(value){
 online=value;
 $('node').textContent=value?'本地执行器在线':'执行器未连接';
 $('liveText').textContent=value?'引擎已连接':'引擎离线';
 syncButton();
}
function syncButton(){
 $('start').disabled=!online||submitting||jobs.some(j=>j.status==='running'||j.verification==='running');
}
async function api(path, options){
 const response=await fetch(path,{cache:'no-store',...options});
 const data=await response.json();
 if(!response.ok)throw Error(data.error||'任务请求失败');
 return data;
}
function post(path,meta,body=null){
 return api(path,{method:'POST',headers:{'X-VD2':'1','X-Job':encodeURIComponent(JSON.stringify(meta))},body});
}
$('scanForm').onsubmit=async e=>{
 e.preventDefault();
 if(!online||submitting)return;
 if(mode==='zip'&&!file){$('formError').textContent='请先选择 ZIP 文件或载入示例 ZIP';return;}
 submitting=true;syncButton();$('formError').textContent='';
 try{
   const result=await post('/api/jobs',{mode,url:$('url').value.trim(),name:file?.name,settings:prefs},mode==='zip'?file:null);
   await openJob(result.id,'scan');
 }catch(error){$('formError').textContent=error.message;}
 finally{submitting=false;syncButton();}
};
$('findingTab').onclick=()=>{resultTab='findings';renderResults();};
$('verifyTab').onclick=()=>{resultTab='verdicts';renderResults();};
function verifyPrompt(){
 const j=current;
 if(!online||submitting||!j||busy())return;
 showDialog('运行漏洞验证','VULNCATCHER-VERIFY','<p class="help">验证器会向已部署的授权靶场发送基线与 POC 请求，保存响应证据和判定结果。</p><form id="verifyForm" style="padding:0"><label for="vurl">已部署的授权靶场 URL</label><input id="vurl" class="verifyInput" type="url" required placeholder="http://127.0.0.1:8080" value="'+esc(j.verifyUrl||j.url||'')+'" '+(j.mode==='url'?'readonly':'')+'><p id="verifyError" class="error" role="alert"></p><div class="modalActions"><button class="primary" id="goVerify">启动验证</button></div></form>');
 $('verifyForm').onsubmit=async e=>{
   e.preventDefault();$('goVerify').disabled=true;
   try{
     await post('/api/jobs/'+j.id+'/verify',{url:$('vurl').value.trim()});
     $('dialog').close();await openJob(j.id,'verify');
   }catch(error){$('verifyError').textContent=error.message;$('goVerify').disabled=false;}
 };
}
const verifySteps=[['poc_collector','POC 收集'],['sandbox_executor','沙箱执行'],['evidence_judge','证据研判'],['verification_reporter','验证报告']];
function plan(job,isVerify){
 const list=[];const push=(key,name,off=false,llm=false)=>list.push({key,name,off,llm});
 if(isVerify){verifySteps.forEach(([k,n])=>push(k,n));return list;}
 if(job.kind!=='zip')push('probe','AWVS 探针分析');
 if(job.mode==='zip')push('ingest','源码解包与索引');
 catalogue.forEach(([key,name,,scope])=>{
  if(scope==='zip'&&job.mode==='url')return;
  const llm=job.settings.llm&&!job.settings.noLlm.includes(key);
  push(key,name,job.settings.off.includes(key)||(key==='deep_finder'&&!llm),llm);
  if(key==='safety_guard'&&job.mode==='zip')push('rules','规则候选提取');
 });
 push('report','挖掘报告');return list;
}
// The clock only schedules HTTP reads. All module states and artifacts come from the engine.
let selectedJobId='';
let resultVersion='';
let monitorVersion='';
async function openJob(id,preferred){
 selectedJobId=id;
 selection++;
 clearTimeout(timer);
 resetReview();
 current=null; findings=[]; verdicts=[]; resultVersion=''; monitorVersion='';
 phase=preferred||'scan';resultTab=phase==='verify'?'verdicts':'findings';
 try{localStorage.setItem('vd2-engine-selected',id);}catch{}
 renderResults();drawMonitor();
 await refresh(selection, !preferred);
}
async function refresh(ticket, choosePhase=false){
 if(ticket!==selection)return;
 try{
   const list=await api('/api/jobs');
   if(!Array.isArray(list))throw Error('无法读取执行器任务');
   if(ticket!==selection)return;
   const historyChanged=JSON.stringify(jobs)!==JSON.stringify(list);
   jobs=list;
   if(!selectedJobId){
     let stored='';try{stored=localStorage.getItem('vd2-engine-selected');}catch{}
     const initial=list.find(j=>j.status==='running'||j.verification==='running')||list.find(j=>j.id===stored)||list[0];
     if(initial){selectedJobId=initial.id;choosePhase=true;}
   }
   if(selectedJobId&&!list.some(j=>j.id===selectedJobId)){
     selectedJobId='';current=null;findings=[];verdicts=[];resultVersion='';monitorVersion='';
     drawMonitor();renderResults();
   }
   if(selectedJobId){
     const id=selectedJobId;
     const job=await api('/api/jobs/'+id);
     if(ticket!==selection)return;
     const version=[id,job.status,job.verification,job.count,job.verifiedCount,job.error].join('/');
     if(version!==resultVersion){
       const [rows,checks]=await Promise.all([
         job.status==='done'?api('/api/jobs/'+id+'/findings'):[],
         job.verification==='done'?api('/api/jobs/'+id+'/verdicts'):[]
       ]);
       if(ticket!==selection)return;
       current=job; findings=rows; verdicts=checks; resultVersion=version;
       if(choosePhase&&job.verification!=='idle'){phase='verify';resultTab='verdicts';}
       if(view==='work')renderResults();
     }else{current=job;}
     const progress=[version,job.events.length,job.verificationEvents.length].join('/');
     if(progress!==monitorVersion){monitorVersion=progress;drawMonitor();}
   }
   if(!online){$('formError').textContent='';$('engineHelp').hidden=true;}
   setOnline(true);
   if(view==='history'&&historyChanged)loadHistory();
 }catch(error){
   if(ticket!==selection)return;
   setOnline(false);$('engineHelp').hidden=false;
   $('formError').textContent='无法连接本地引擎。请在 VD2 根目录运行 python3 frontend/server.py，然后打开 http://127.0.0.1:8765/';
   $('monitorFoot').textContent='执行器连接中断 · 等待重新连接';
 }finally{
   if(ticket===selection && location.protocol!=='file:' && (online || ['127.0.0.1','localhost'].includes(location.hostname)))
     timer=setTimeout(()=>refresh(ticket),online&&jobs.some(j=>j.status==='running'||j.verification==='running')?350:3000);
 }
}
function init(){
 drawMonitor();renderResults();syncButton();
 refresh(selection);
}
