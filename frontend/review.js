'use strict';

const cases = {
  zip: { title: 'Java 源码审计', tag: 'SOURCE AUDIT', icon: 'archive', note: '追踪输入如何到达危险调用' },
  url: { title: '反射型 XSS 探测', tag: 'DYNAMIC PROBE', icon: 'globe', note: '对照 HTTP 请求与验证结论' },
  hybrid: { title: '源码与探针联合分析', tag: 'CORRELATION', icon: 'layers', note: '并排审阅静态发现与动态证据' }
};
let archiveKind = 'zip';
let query = '', severity = 'all', selectedId = '', section = 'overview', scriptName = '';
let openGroup = null;

function resetReview() {
  query = ''; severity = 'all'; selectedId = ''; section = 'overview'; scriptName = ''; openGroup = null;
}

function openCase(kind) {
  archiveKind = kind;
  resultTab = 'findings';
  resetReview();
  setView('archive');
}

function drawCases() {
  $('casePicker').innerHTML = '<div class="sectionline"><h2><span class="sq"></span>选择实验记录</h2><span class="mono">CASE LIBRARY / 03</span></div><div class="caseGrid">' +
    Object.entries(cases).map(([kind, item], i) =>
      '<button class="caseCard" data-case="'+kind+'" aria-pressed="'+(archiveKind === kind)+'"><small>0'+(i+1)+' / '+item.tag+'</small><strong>'+icon(item.icon)+item.title+'</strong><span>'+item.note+'</span><b>'+SAMPLES[kind].findings.length+' 条发现　↗</b></button>').join('') + '</div>';
  $('casePicker').querySelectorAll('[data-case]').forEach(button => button.onclick = () => openCase(button.dataset.case));
}

const scanGroups = [
  ['目标接入', '解包、探测与输入防护', ['ingest', 'probe', 'safety_guard']],
  ['候选发现', '规则匹配与攻击面测绘', ['rules', 'surface_mapper', 'deep_finder', 'candidate_screener']],
  ['证据分析', '分析漏洞与二阶链路', ['vulnerability_analyzer', 'second_order_analyzer', 'logic_analyzer']],
  ['工件输出', '生成 POC 与完整报告', ['poc_writer', 'coordinator', 'report']]
];
const verifyGroups = verifySteps.map(([key, title], index) => [
  title, ['收集可回放的工件', '比较基线与探测请求', '根据证据逐项判定', '生成验证记录'][index], [key]
]);
function drawMonitor() {
  const verifying = current && phase === 'verify';
  const draft = { kind: mode === 'zip' && $('url').value.trim() ? 'hybrid' : mode, mode, settings: prefs };
  const steps = plan(current || draft, verifying);
  const events = current ? (verifying ? current.verificationEvents : current.events) : [];
  const state = current ? (verifying ? current.verification : current.status) : 'idle';
  const logged = new Map(events.map(e => [e.key, e]));
  const terminal = ['done','skipped','warning','failed'];
  const resolved = steps.filter(s=>terminal.includes(logged.get(s.key)?.state)).length;
  const active = [...logged.values()].find(e => e.state === 'running');
  const groups = verifying ? verifyGroups : scanGroups;
  const groupRows = groups.map(([title, hint, keys], index) => {
    const members = steps.filter(s => keys.includes(s.key));
    if (!members.length) return '';
    const ended = members.filter(s => terminal.includes(logged.get(s.key)?.state));
    const issue = members.map(s=>logged.get(s.key)?.state).find(v=>v==='failed'||v==='warning');
    const running = members.some(s => logged.get(s.key)?.state === 'running');
    const finished = ended.length === members.length;
    const skipped = finished && ended.every(s => logged.get(s.key).state === 'skipped');
    const code = issue || (running ? 'running' : skipped ? 'skipped' : finished ? 'done' : 'pending');
    const names = members.map(s => {
      const event = logged.get(s.key);
      return '<div class="moduleLine"><span>'+esc(s.name)+'</span><small>'+esc(event?.note || statusText[event?.state] || (s.off ? '配置已关闭' : '待执行'))+'</small></div>';
    }).join('');
    return '<details class="flowRow '+code+'" data-group="'+index+'" '+(openGroup===index?'open':'')+'><summary><span class="flowNode">'+
      (code==='done'?'✓':code==='skipped'?'–':String(index+1).padStart(2,'0'))+'</span><span class="flowLabel"><strong>'+title+'</strong><small>'+
      esc(running ? active?.name : hint)+'</small></span><span class="flowStatus">'+
      (issue?statusText[issue]:running?'进行中':skipped?'已跳过':finished?'已完成':members.length+' 个模块')+'</span><span class="chev">⌄</span></summary>'+names+'</details>';
  }).join('');
  const percent = Math.round(resolved / steps.length * 100);
  $('monitorState').textContent = statusText[state] || '待命';
  $('monitorState').className = 'pill ' + (state==='idle'?'':'on');
  $('monitor').innerHTML = '<div class="flow"><div class="flowTop"><div class="phaseTabs"><button data-phase="scan" aria-pressed="'+(!verifying)+'">挖掘管线</button><button data-phase="verify" aria-pressed="'+Boolean(verifying)+'" '+(!current?'disabled':'')+'>验证管线</button></div><span class="flowCount">'+resolved+' / '+steps.length+'</span></div>'+
    '<div class="progressTrack" role="progressbar" aria-label="模块进度" aria-valuemin="0" aria-valuemax="100" aria-valuenow="'+percent+'"><span style="width:'+percent+'%"></span></div>'+groupRows+'</div>';
  $('monitor').querySelectorAll('[data-phase]').forEach(button => button.onclick = () => {
    phase = button.dataset.phase; openGroup = null; drawMonitor();
  });
  $('monitor').querySelectorAll('[data-group]').forEach(row => {
    row.querySelector('summary').onclick = e => {
      e.preventDefault();
      openGroup = row.open ? null : Number(row.dataset.group);
      $('monitor').querySelectorAll('[data-group]').forEach(item => { item.open = Number(item.dataset.group) === openGroup; });
    };
  });
  $('monitorFoot').textContent = !current ? '管线预览 · 展开阶段可查看智能体' : active ? '当前模块 · '+active.name : state==='failed'?current.error:state==='done'?'执行完成 · '+current.name:state==='running'?'正在启动执行器':'等待验证请求';
}

function locationOf(f) {
  const loc = f.location || {};
  return loc.file ? loc.file+(loc.line_start?':'+loc.line_start:'') : (loc.http_method || '')+' '+(loc.endpoint || '未提供端点');
}
function badge(type, label) {
  return '<span class="badge '+esc(type)+'">'+esc(label)+'</span>';
}
function field(title, value) {
  return '<div class="fact"><small>'+title+'</small><span>'+esc(value ?? '—')+'</span></div>';
}
function reviewData() {
  const archive = view==='archive';
  const kind = archive ? archiveKind : current?.kind;
  return {kind, records: archive ? SAMPLES[kind].findings : findings, checks: archive ? SAMPLES[kind].verdicts : verdicts};
}
function renderResults() {
  const {kind, records, checks} = reviewData();
  const archive = view === 'archive', isVerify = resultTab === 'verdicts';
  const complete = archive || current?.status === 'done';
  const verified = archive || current?.verification === 'done';
  $('findingTab').setAttribute('aria-pressed', String(!isVerify));
  $('verifyTab').setAttribute('aria-pressed', String(isVerify));
  $('findingCount').textContent = records.length;
  $('verifyCount').textContent = checks.length;
  const base = archive ? 'samples/'+kind : '/api/jobs/'+current?.id;
  const report = base+(archive?'/report.html':'/report');
  const verifyReport = base+(archive?'/verification.txt':'/verify-report');
  $('actions').innerHTML = (complete ? '<a class="mini" target="_blank" rel="noopener" href="'+report+'">'+icon('file')+'完整挖掘报告 ↗</a>' : '') +
    (verified && isVerify ? '<a class="mini" target="_blank" rel="noopener" href="'+verifyReport+'">验证报告 ↗</a>' : '') +
    (!archive && complete && records.length ? '<button id="verifyAction" class="mini verifyBtn" '+(busy()?'disabled':'')+'>'+icon('shield')+(verified?'重新验证':'验证漏洞')+'</button>' : '');
  if ($('verifyAction')) $('verifyAction').onclick = verifyPrompt;
  if (!records.length || (isVerify && !checks.length)) {
    const status = isVerify ? current?.verification : current?.status;
    const title = status==='failed'?'执行失败':status==='done'?(isVerify?'没有可验证的 POC':'本次分析未发现符合条件的漏洞'):(isVerify?'等待验证结果':'等待挖掘结果');
    const note = status==='failed'?current.error:status==='done'?'可打开本次运行的完整报告。':isVerify?'完成挖掘后可运行 POC 验证。':'提交任务后，这里会显示引擎生成的报告。';
    $('results').innerHTML = empty(title,note)+
      (!current && !archive ? '<div class="quickCases">'+Object.entries(cases).map(([k,c])=>'<button data-case="'+k+'">'+icon(c.icon)+c.title+' ↗</button>').join('')+'</div>' : '');
    $('results').querySelectorAll('[data-case]').forEach(b=>b.onclick=()=>openCase(b.dataset.case));
    return;
  }
  const options = ['all',...Object.keys(severityText).filter(k=>records.some(f=>f.severity===k))];
  $('results').innerHTML = '<div class="evidenceToolbar"><label class="searchBox">'+icon('search')+'<input id="findingSearch" type="search" aria-label="搜索漏洞" placeholder="搜索漏洞、CWE 或位置" value="'+esc(query)+'"></label>'+
    '<div class="riskFilters" role="group" aria-label="严重度筛选">'+options.map(k=>'<button data-risk="'+k+'" aria-pressed="'+(severity===k)+'">'+
      (k==='all'?'全部':severityText[k])+' <b>'+(k==='all'?records.length:records.filter(f=>f.severity===k).length)+'</b></button>').join('')+'</div></div>'+
    '<div class="evidenceSplit"><div id="findingList" class="findingList" aria-label="漏洞列表"></div><section id="inspector" class="inspector" aria-label="漏洞详情"></section></div>'+
    '<div class="recordFoot">'+icon('file')+' '+(archive?'固定样例 · '+esc(kindName(kind)):'本次运行 · '+esc(current.id))+'</div>';
  $('findingSearch').oninput = e => { query=e.target.value; drawList(); };
  $('results').querySelectorAll('[data-risk]').forEach(b=>b.onclick=()=>{
    severity=b.dataset.risk;
    $('results').querySelectorAll('[data-risk]').forEach(item=>item.setAttribute('aria-pressed',String(item===b)));
    drawList();
  });
  drawList();
}
function drawList() {
  const {records,checks} = reviewData();
  const term = query.trim().toLowerCase();
  const eligible = resultTab==='verdicts' ? records.filter(f=>checks.some(r=>r.finding_id===f.id)) : records;
  const filtered = eligible.filter(f=>(severity==='all'||f.severity===severity) &&
    [f.title,f.id,f.cwe,locationOf(f),f.location?.endpoint].join(' ').toLowerCase().includes(term));
  const selected = filtered.find(f=>f.id===selectedId) || filtered[0];
  selectedId = selected?.id || '';
  $('findingList').innerHTML = '<div class="listCaption"><small>FINDINGS</small><span>'+filtered.length+' / '+eligible.length+'</span></div>'+
    filtered.map(f=>{
      const verdict = checks.find(r=>r.finding_id===f.id);
      const label = resultTab==='verdicts' && verdict ? badge(verdict.verdict,verdictText[verdict.verdict]) : badge(f.severity,severityText[f.severity]);
      return '<button class="findingRow" data-finding="'+esc(f.id)+'" aria-pressed="'+(f.id===selectedId)+'"><span>'+label+'<small>'+esc(f.cwe)+'</small></span><strong>'+esc(f.title.replace(/（CWE-\d+）$/,''))+'</strong><code>'+esc(locationOf(f))+'</code></button>';
    }).join('');
  if(!selected){
    $('inspector').innerHTML=empty('没有匹配的漏洞','可更换关键词或清除筛选。')+'<button id="clearFilters" class="outlineBtn">清除筛选</button>';
    $('clearFilters').onclick=()=>{query='';severity='all';renderResults();$('findingSearch')?.focus();};
    return;
  }
  $('findingList').querySelectorAll('[data-finding]').forEach(button=>button.onclick=()=>{
    selectedId=button.dataset.finding; scriptName=''; drawList();
    $('findingList').querySelector('[aria-pressed="true"]')?.focus({preventScroll:true});
  });
  drawInspector(selected, checks.find(r=>r.finding_id===selected.id));
}
function drawInspector(f, verdict) {
  const verifying = resultTab==='verdicts';
  const scripts = Object.entries(f.poc?.scripts || {});
  const activeScript = scripts.find(([name])=>name===scriptName) || scripts.find(([name])=>name.endsWith('.http')) || scripts[0];
  let content;
  if(verifying && verdict){
    content='<div class="verdictLine">'+badge(verdict.verdict,verdictText[verdict.verdict])+'<b>POC 验证结论</b></div>'+
      '<p class="evidenceText">'+esc(verdict.reason)+'</p><div class="facts">'+field('基线 HTTP',verdict.baseline?.status)+field('探测 HTTP',verdict.attack?.status)+'</div>'+field('验证靶场',verdict.target_url);
  }else if(section==='artifacts'){
    content=activeScript?'<div class="artifactTools"><label>工件 <select id="artifactSelect" aria-label="选择 POC 文件">'+scripts.map(([name])=>'<option '+(name===activeScript[0]?'selected':'')+'>'+esc(name)+'</option>').join('')+'</select></label><button class="mini" id="copyPoc">复制内容</button></div>'+
      '<pre tabindex="0" class="codeView"><code>'+esc(activeScript[1])+'</code></pre>':empty('没有 POC 工件','此条记录只包含分析证据。');
  }else{
    content='<div class="facts">'+field('源码位置 / 端点',locationOf(f))+field('请求入口',[f.location?.http_method,f.location?.endpoint].filter(Boolean).join(' '))+'</div>'+
      '<h4>发现依据</h4><p class="evidenceText">'+esc(f.description)+'</p>'+
      (f.poc?.impact?'<h4>潜在影响</h4><p class="evidenceText">'+esc(f.poc.impact)+'</p>':'');
  }
  $('inspector').innerHTML='<div class="inspectionMeta">'+badge(f.severity,severityText[f.severity])+'<code>'+esc(f.id)+'</code></div>'+
    '<h3>'+esc(f.title)+'</h3>'+(!verifying?'<div class="inspectionTabs"><button data-section="overview" aria-pressed="'+(section==='overview')+'">证据概览</button><button data-section="artifacts" aria-pressed="'+(section==='artifacts')+'">POC 工件 · '+scripts.length+'</button></div>':'')+content;
  $('inspector').querySelectorAll('[data-section]').forEach(b=>b.onclick=()=>{
    section=b.dataset.section;drawInspector(f,verdict);$('inspector').querySelector('[aria-pressed="true"]')?.focus({preventScroll:true});
  });
  if($('artifactSelect'))$('artifactSelect').onchange=e=>{scriptName=e.target.value;drawInspector(f,verdict);$('artifactSelect').focus();};
  if($('copyPoc'))$('copyPoc').onclick=async()=>{
    try{await navigator.clipboard.writeText(activeScript[1]);toast('POC 内容已复制');}
    catch{const range=document.createRange();range.selectNodeContents(document.querySelector('.codeView code'));const selection=window.getSelection();selection.removeAllRanges();selection.addRange(range);toast('已选中工件内容，可按 Ctrl+C 或 ⌘C 复制');}
  };
}

glyphs.search = '<circle cx="10" cy="10" r="6"/><path d="m15 15 5 5"/>';
$('url').addEventListener('input',()=>{if(!current)drawMonitor();});
init();
