/* कोडनीती AI: hand-built browser UI, dependency-free, with safe text-only Markdown parsing. */
(() => {
  'use strict';
  const $ = selector => document.querySelector(selector);
  const $$ = selector => Array.from(document.querySelectorAll(selector));
  const TOOLS = {
    'verify-repair':['Verify & Auto-Repair','Detect AST & Bandit issues, synthesize targeted AI patch, and re-scan to prove resolution.','Verify & Repair Code','single'],
    'audit-project':['Project Audit (ZIP)','Scan an entire Python project archive (.zip) for multi-file AST risks and Bandit security issues.','Audit ZIP Project','zip'],
    optimize:['Optimise code','Identify improvements in performance, clarity and correctness.','Analyse code','single'],
    complexity:['Complexity analysis','Estimate Big-O behaviour and algorithmic trade-offs.','Analyse complexity','single'],
    debug:['Debug assistant','Identify possible root causes and propose regression tests.','Debug code','single'],
    security:['Security audit','Scan Python using Bandit. Static results require review.','Scan source','single'],
    testcases:['Generate tests','Propose edge cases, assertions and useful unit tests.','Generate tests','single'],
    generate:['Code generator','Turn a detailed request into an initial working implementation.','Generate code','prompt'],
    compare:['Compare code','Review a deterministic, line-by-line diff between revisions.','Compare versions','compare'],
    beautify:['Python formatter','Format Python predictably using Ruff without executing it.','Format code','single']
  };
  const EXAMPLES = {
    'verify-repair':'import subprocess\napi_key = "prod_secret_token_12345"\n\ndef execute_command(user_dir):\n    try:\n        assert len(user_dir) > 0\n        subprocess.run("ls " + user_dir, shell=True)\n    except:\n        print("Execution failed")\n',
    optimize:'def has_duplicate(nums):\n    for i in range(len(nums)):\n        for j in range(i + 1, len(nums)):\n            if nums[i] == nums[j]:\n                return True\n    return False',
    complexity:'def count_pairs(nums):\n    count = 0\n    for x in nums:\n        for y in nums:\n            if x + y == 10:\n                count += 1\n    return count',
    debug:'def average(numbers):\n    total = 0\n    for i in range(len(numbers) + 1):\n        total += numbers[i]\n    return total / len(numbers)',
    security:'import subprocess\n\ndef show_files(path):\n    subprocess.run("ls " + path, shell=True)',
    testcases:'def is_palindrome(text: str) -> bool:\n    normalized = text.lower().replace(" ", "")\n    return normalized == normalized[::-1]',
    generate:'Write a Python function that checks if two strings are anagrams, ignoring case and spaces. Include type hints and pytest cases.',
    compare:['def square(x):\n    return x * 2','def square(x):\n    return x * x'],
    beautify:'def greet(name:str)->str:\n  print("Hello",name)\n  return "hello " +name'
  };
  let tool='verify-repair',user=null,mode='login',running=false,result='',toastHandle,drawerKind='history',selectedZipFile=null;
  const code=$('#codeInput'),prompt=$('#promptInputText'),before=$('#beforeInput'),after=$('#afterInput');
  const zipInput=$('#zipFileInput'),zipDropzone=$('#zipDropzone'),zipInfo=$('#zipFileInfo'),browseZipBtn=$('#browseZipBtn');
  const modifiedHeaders={'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'};
  function toast(message){const el=$('#toast');el.textContent=message;el.classList.add('visible');clearTimeout(toastHandle);toastHandle=setTimeout(()=>el.classList.remove('visible'),3700);}
  async function api(path,options={}){
    const res=await fetch(path,{credentials:'same-origin',...options,headers:{...(options.method && options.method!=='GET'?modifiedHeaders:{}),...(options.headers||{})}});
    const raw=await res.text();let data;
    try{data=JSON.parse(raw);}catch{throw new Error('The server returned an unexpected response.');}
    if(!res.ok){const detail=data.detail;const msg=Array.isArray(detail)?detail.map(x=>x.msg).join(', '):detail;const error=new Error(msg||`Request failed (${res.status})`);error.status=res.status;throw error;}
    return data;
  }
  const post=(path,payload)=>api(path,{method:'POST',body:JSON.stringify(payload)});
  function updateCount(){const value=code.value;const lines=value.split('\n');$('#lineGutter').textContent=lines.map((_,i)=>i+1).join('\n');$('#editorCount').textContent=`${lines.length} ${lines.length===1?'line':'lines'} · ${value.length} characters`;}
  function setStatus(text,variant=''){$('#resultStatus').textContent=text;$('#resultStatus').className=`status-tag ${variant}`;}
  function clearResult(){result='';$('#resultMeta').textContent='Awaiting your first run';setStatus('READY');$('#copyBtn').disabled=true;$('#downloadBtn').disabled=true;$('#outputArea').replaceChildren();const empty=document.createElement('div');empty.className='empty-report';const icon=document.createElement('span');icon.className='empty-symbol';icon.textContent='⌁';const heading=document.createElement('h3');heading.textContent='A clearer view of your code.';const detail=document.createElement('p');detail.textContent='Select a tool, paste a snippet and run an analysis. Your report will appear here.';const keyboard=document.createElement('span');keyboard.className='keyboard-hint';keyboard.textContent='Ctrl / ⌘ + Enter to run';empty.append(icon,heading,detail,keyboard);$('#outputArea').append(empty);}
  function setTool(next){if(!TOOLS[next])return;tool=next;const [title,detail,action,type]=TOOLS[next];$$('[data-tool]').forEach(b=>b.classList.toggle('active',b.dataset.tool===next));$('#toolHeading').textContent=title;$('#toolDescription').textContent=detail;$('#runLabel').textContent=action;$('#singleInput').classList.toggle('hidden',type!=='single');$('#promptInput').classList.toggle('hidden',type!=='prompt');$('#compareInput').classList.toggle('hidden',type!=='compare');$('#zipInput').classList.toggle('hidden',type!=='zip');const pythonOnly=['security','beautify','verify-repair','audit-project'].includes(tool);$('#language').disabled=pythonOnly;if(pythonOnly)$('#language').value='python';const extension={python:'py',javascript:'js',typescript:'ts',java:'java',cpp:'cpp',c:'c',csharp:'cs',go:'go',rust:'rs',sql:'sql',html:'html',css:'css'}[$('#language').value]||'txt';$('#fileLabel').textContent=type==='prompt'?'request.md':type==='zip'?(selectedZipFile?selectedZipFile.name:'project.zip'):`snippet.${extension}`;clearResult();$('#sidebar').classList.remove('open');}
  function loadSample(){if(tool==='audit-project'){toast('Please choose a .zip file or drag & drop one into the upload zone.');return;}const sample=EXAMPLES[tool];if(Array.isArray(sample)){before.value=sample[0];after.value=sample[1];}else if(TOOLS[tool][3]==='prompt'){prompt.value=sample;}else{code.value=sample;}updateCount();toast('Example loaded. Ready to run.');}
  function payload(){const language=$('#language').value,save_history=$('#saveHistory').checked,type=TOOLS[tool][3];if(type==='prompt'){if(!prompt.value.trim())throw new Error('Describe your requested implementation.');return {prompt:prompt.value,language,save_history};}if(type==='compare'){if(!before.value.trim()||!after.value.trim())throw new Error('Enter both code versions.');return {code1:before.value,code2:after.value,language,save_history};}if(!code.value.trim())throw new Error('Paste source code or load an example.');return {code:code.value,language,save_history};}
  function inline(target,text){const rx=/(`[^`\n]+`|\*\*[^*\n]+\*\*)/g;let match,at=0;while((match=rx.exec(text))){if(match.index>at)target.append(document.createTextNode(text.slice(at,match.index)));const bold=match[0].startsWith('*');const element=document.createElement(bold?'strong':'code');element.textContent=match[0].slice(bold?2:1,bold?-2:-1);target.append(element);at=match.index+match[0].length;}if(at<text.length)target.append(document.createTextNode(text.slice(at)));}
  function render(text){
    const root=$('#outputArea');root.replaceChildren();const report=document.createElement('div');report.className='report';const lines=text.replace(/\r\n/g,'\n').split('\n');let i=0;
    while(i<lines.length){
      let line=lines[i];
      if(!line.trim()){i++;continue;}
      if(line.trim().startsWith('```')){
        const parts=[];i++;while(i<lines.length&&!lines[i].trim().startsWith('```'))parts.push(lines[i++]);i++;
        const pre=document.createElement('pre'),c=document.createElement('code');c.textContent=parts.join('\n');pre.append(c);report.append(pre);continue;
      }
      if(line.trim().startsWith('|')&&line.includes('|')){
        const tblLines=[];
        while(i<lines.length&&lines[i].trim().startsWith('|')&&lines[i].includes('|')){tblLines.push(lines[i].trim());i++;}
        if(tblLines.length>=2){
          const isSep=/^\|?(\s*:?-+:?\s*\|)+\s*:?-+:?\s*\|?$/.test(tblLines[1]);
          const table=document.createElement('table');let start=0;
          if(isSep){
            const thead=document.createElement('thead'),tr=document.createElement('tr');
            tblLines[0].replace(/^\||\|$/g,'').split('|').forEach(c=>{const th=document.createElement('th');inline(th,c.trim());tr.append(th);});
            thead.append(tr);table.append(thead);start=2;
          }
          const tbody=document.createElement('tbody');
          for(let r=start;r<tblLines.length;r++){
            const tr=document.createElement('tr');
            tblLines[r].replace(/^\||\|$/g,'').split('|').forEach(c=>{const td=document.createElement('td');inline(td,c.trim());tr.append(td);});
            tbody.append(tr);
          }
          table.append(tbody);report.append(table);continue;
        }
      }
      if(line.trim().startsWith('>')){
        const qLines=[];while(i<lines.length&&lines[i].trim().startsWith('>')){qLines.push(lines[i].trim().replace(/^>\s?/,''));i++;}
        const bq=document.createElement('blockquote'),qRaw=qLines.join('\n');
        if(/\[!(CAUTION|WARNING)\]/i.test(qRaw))bq.className='callout-caution';
        const cleanQ=qRaw.replace(/\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]/gi,'').trim();
        const qp=document.createElement('p');inline(qp,cleanQ);bq.append(qp);report.append(bq);continue;
      }
      const heading=line.match(/^(#{1,4})\s+(.+)$/);
      if(heading){const h=document.createElement(`h${Math.min(4,heading[1].length+1)}`);inline(h,heading[2]);report.append(h);i++;continue;}
      if(/^\s*([-*]|\d+\.)\s/.test(line)){
        const ordered=/^\s*\d+\./.test(line),list=document.createElement(ordered?'ol':'ul');
        while(i<lines.length&&/^\s*([-*]|\d+\.)\s/.test(lines[i])){const li=document.createElement('li');inline(li,lines[i++].replace(/^\s*([-*]|\d+\.)\s*/,''));list.append(li);}
        report.append(list);continue;
      }
      const para=document.createElement('p'),paragraph=[];
      while(i<lines.length&&lines[i].trim()&&!/^\s*(#{1,4}\s|[-*]\s|\d+\.\s|```|\||>)/.test(lines[i]))paragraph.push(lines[i++]);
      if(!paragraph.length){paragraph.push(line);i++;}inline(para,paragraph.join(' '));report.append(para);
    }
    root.append(report);root.scrollTop=0;
  }
  async function run(){
    if(running)return;if(!user){openAuth('login');return;}
    if(tool==='audit-project'){
      if(!selectedZipFile){toast('Please choose a .zip file to audit.');return;}
      running=true;$('#runBtn').disabled=true;setStatus('RUNNING','working');$('#outputArea').replaceChildren();
      const loading=document.createElement('div');loading.className='loading-box';
      const spinner=document.createElement('div');spinner.className='spinner';
      loading.append(spinner,document.createTextNode('Inspecting and auditing project archive…'));$('#outputArea').append(loading);
      try{
        const formData=new FormData();formData.append('file',selectedZipFile);
        const res=await fetch('/api/audit-project',{method:'POST',credentials:'same-origin',headers:{'X-Requested-With':'XMLHttpRequest'},body:formData});
        const raw=await res.text();let data;
        try{data=JSON.parse(raw);}catch{throw new Error('The server returned an unexpected response.');}
        if(!res.ok){const msg=Array.isArray(data.detail)?data.detail.map(x=>x.msg).join(', '):data.detail;const err=new Error(msg||`Request failed (${res.status})`);err.status=res.status;throw err;}
        result=data.result;render(result);setStatus('COMPLETE','success');
        $('#resultMeta').textContent=`${data.engine.toUpperCase()} · ${data.duration_ms} ms`;
        $('#copyBtn').disabled=false;$('#downloadBtn').disabled=false;if(data.disclaimer)toast(data.disclaimer);refreshMetrics(false);
      }catch(e){
        setStatus('ERROR','error');$('#outputArea').replaceChildren();
        const box=document.createElement('div');box.className='error-box';box.textContent=e.message;
        $('#outputArea').append(box);$('#resultMeta').textContent='Audit not completed';if(e.status===401)openAuth('login');
      }finally{running=false;$('#runBtn').disabled=false;}
      return;
    }
    let data;try{data=payload();}catch(e){toast(e.message);return;}
    running=true;$('#runBtn').disabled=true;setStatus('RUNNING','working');$('#outputArea').replaceChildren();
    const loading=document.createElement('div');loading.className='loading-box';
    const spinner=document.createElement('div');spinner.className='spinner';
    loading.append(spinner,document.createTextNode('Analysing your input…'));$('#outputArea').append(loading);
    try{
      const output=await post(`/api/${tool}`,data);result=output.result;render(result);
      setStatus(output.cached?'CACHED':'COMPLETE','success');
      $('#resultMeta').textContent=`${output.engine.toUpperCase()} · ${output.duration_ms} ms${output.saved?' · Saved':''}`;
      $('#copyBtn').disabled=false;$('#downloadBtn').disabled=false;if(output.disclaimer)toast(output.disclaimer);refreshMetrics(false);
    }catch(e){
      setStatus('ERROR','error');$('#outputArea').replaceChildren();
      const box=document.createElement('div');box.className='error-box';box.textContent=e.message;
      $('#outputArea').append(box);$('#resultMeta').textContent='Analysis not completed';if(e.status===401)openAuth('login');
    }finally{running=false;$('#runBtn').disabled=false;}
  }
  async function refreshService(){try{const s=await api('/api/status');$('#engineStatus').textContent=s.ai_available?`Gemini · ${s.model}`:'Local tools ready';$('#apiState').textContent=s.ai_available?'AI engine configured':'AI key not configured';}catch{$('#engineStatus').textContent='Service unavailable';$('#apiState').textContent='Service unavailable';}}
  async function refreshMetrics(show=false){if(!user)return;try{const data=await api('/api/stats');$('#historyCount').textContent=data.saved_analyses;if(show){drawerKind='metrics';drawerTitle('Performance metrics');const root=$('#drawerContent');root.replaceChildren();const grid=document.createElement('div');grid.className='metric-grid';const items=[['Analyses completed',data.requests_total],['Cache hit rate',`${data.cache_hit_rate_percent}%`],['P95 latency',data.p95_latency_ms===null?'—':`${data.p95_latency_ms} ms`],['Saved reports',data.saved_analyses],['Avg. cold request',data.average_cold_ms===null?'—':`${data.average_cold_ms} ms`],['Avg. cached request',data.average_cached_ms===null?'—':`${data.average_cached_ms} ms`],['AI requests left (UTC)',data.ai_remaining_today],['Measured samples',data.sample_size]];for(const [name,value] of items){const box=document.createElement('div');box.className='metric';const number=document.createElement('strong');number.textContent=value;const label=document.createElement('span');label.textContent=name;box.append(number,label);grid.append(box);}root.append(grid);const note=document.createElement('p');note.className='drawer-paragraph';note.textContent='Metrics use up to the last 500 completed requests from your account. They contain timings and tool names, not your source code. Cached and cold averages can differ by task mix; this is an observational metric, not a controlled benchmark.';root.append(note);$('#clearHistoryBtn').classList.add('hidden');openDrawer();}}
    catch(e){if(show)toast(e.message);}}
  function drawerTitle(name){$('#drawerHeading').textContent=name;$('#clearHistoryBtn').classList.add('hidden');}
  function openDrawer(){$('#drawer').classList.add('open');$('#drawer').setAttribute('aria-hidden','false');$('#scrim').classList.remove('hidden');$('#drawerClose').focus();}
  function closeDrawer(){$('#drawer').classList.remove('open');$('#drawer').setAttribute('aria-hidden','true');$('#scrim').classList.add('hidden');}
  function makeText(tag,text,cls=''){const e=document.createElement(tag);e.textContent=text;if(cls)e.className=cls;return e;}
  async function showHistory(){if(!user){openAuth('login');return;}drawerKind='history';drawerTitle('Saved analyses');const root=$('#drawerContent');root.replaceChildren(makeText('p','Loading…','drawer-paragraph'));openDrawer();try{const entries=await api('/api/history?limit=40');root.replaceChildren();if(!entries.length){root.append(makeText('p','No saved analyses yet. Turn on “Save to my history” before running a tool.','drawer-paragraph'));return;}for(const item of entries){const card=document.createElement('article');card.className='history-item';const header=document.createElement('header');header.append(makeText('span',TOOLS[item.tool]?.[0]||item.tool),makeText('span',new Date(item.created_at).toLocaleDateString()));card.append(header,makeText('h3',(item.prompt||item.code||'Untitled').replace(/\s+/g,' ').slice(0,100)),makeText('p',`${item.language.toUpperCase()} · ${item.engine}`));const actions=document.createElement('div');actions.className='history-actions';const load=makeText('button','Open report');load.addEventListener('click',()=>{setTool(item.tool);$('#language').value=item.language;code.value=item.code;before.value=item.code;after.value=item.code2;prompt.value=item.prompt;updateCount();result=item.result;render(item.result);setStatus('SAVED','success');$('#resultMeta').textContent=`${item.engine} · Restored from history`;$('#copyBtn').disabled=false;$('#downloadBtn').disabled=false;closeDrawer();});const del=makeText('button','Delete');del.addEventListener('click',async()=>{if(!confirm('Delete this saved report?'))return;try{await api(`/api/history/${item.id}`,{method:'DELETE'});card.remove();refreshMetrics(false);}catch(e){toast(e.message);}});actions.append(load,del);card.append(actions);root.append(card);}$('#clearHistoryBtn').classList.remove('hidden');}catch(e){root.replaceChildren(makeText('p',e.message,'drawer-paragraph'));}}
  function showAbout(){drawerKind='about';drawerTitle('About the project');const root=$('#drawerContent');root.replaceChildren();const intro=makeText('p','कोडनीती AI — AI Powered Code Intelligence Platform for Automated Optimization, Complexity Analysis & Security Auditing.','drawer-paragraph');root.append(intro,makeText('p','Final Year Major Project · Department of Electronics & Computer Engineering, CSMSS Chh. Shahu College of Engineering, Chhatrapati Sambhajinagar.','drawer-paragraph'),makeText('p','PROJECT TEAM','section-caption'));
    const members=[['Dhuppe Harshad Madhav','EC4145 · 23025331844046'],['Shinde Saurabh Bhagaji','EC4121 · 23025331844021'],['Kale Pradeep Dyaneshwar','EC4168 · 24025331844502']];const list=document.createElement('div');list.className='team-list';for(const [name,roll] of members){const card=document.createElement('div');card.className='team-member';card.append(makeText('strong',name),makeText('span',roll));list.append(card);}root.append(list,makeText('p','PROJECT GUIDE','section-caption'),makeText('p','Prof. J. N. Mohite','drawer-paragraph'),makeText('p','TECHNICAL STACK','section-caption'),makeText('p','Python · FastAPI · SQLite · Google Gemini · Ruff · Bandit · Vanilla JavaScript · Pytest. AI recommendations are not a substitute for testing or human security review.','drawer-paragraph'));openDrawer();}
  function showAccount(){drawerKind='account';drawerTitle('My account');const root=$('#drawerContent');root.replaceChildren();root.append(makeText('p',user?.display_name||'','drawer-paragraph'),makeText('p',user?.email||'','drawer-paragraph'));const logout=makeText('button','Sign out','danger-button');logout.addEventListener('click',async()=>{await api('/api/auth/logout',{method:'POST',body:'{}'});user=null;closeDrawer();openAuth('login');});const erase=makeText('button','Delete my account and all data','danger-button');erase.style.marginLeft='9px';erase.addEventListener('click',async()=>{if(!confirm('Permanently delete your account, history, caches and metrics? This cannot be undone.'))return;await api('/api/auth/account',{method:'DELETE'});user=null;closeDrawer();openAuth('register');toast('Account deleted.');});root.append(logout,erase,makeText('p','Sign out revokes the current session. Account deletion permanently erases your data from this project’s database.','drawer-paragraph'));openDrawer();}
  function openAuth(type='login'){mode=type;$('#authOverlay').classList.remove('hidden');$('#authError').classList.add('hidden');updateAuthMode();}
  function updateAuthMode(){const creating=mode==='register';$('#authHeading').textContent=creating?'Create your account':'Sign in to continue';$('#nameWrap').classList.toggle('hidden',!creating);$('#authName').required=creating;$('#authPassword').autocomplete=creating?'new-password':'current-password';$('#authSubmit').replaceChildren(document.createTextNode(creating?'Create account ':'Sign in '),makeText('span','→'));$('#loginTab').classList.toggle('active',!creating);$('#registerTab').classList.toggle('active',creating);$('#loginTab').setAttribute('aria-selected',!creating);$('#registerTab').setAttribute('aria-selected',creating);}
  function afterLogin(next){user=next;$('#authOverlay').classList.add('hidden');$('#avatar').textContent=user.display_name.trim()[0]?.toUpperCase()||'U';$('#accountLabel').textContent=user.display_name.split(' ')[0];refreshMetrics(false);toast(`Welcome, ${user.display_name.split(' ')[0]}.`);}
  async function hydrateAuth(){try{const account=await api('/api/auth/me');$('#registerTab').classList.toggle('hidden',!account.signup_enabled);if(account.user){afterLogin(account.user);}else openAuth('login');}catch{openAuth('login');}}
  $('#authForm').addEventListener('submit',async event=>{event.preventDefault();const submit=$('#authSubmit');submit.disabled=true;$('#authError').classList.add('hidden');try{const payload={email:$('#authEmail').value,password:$('#authPassword').value};if(mode==='register')payload.display_name=$('#authName').value;const data=await post(mode==='register'?'/api/auth/register':'/api/auth/login',payload);$('#authForm').reset();afterLogin(data.user);}catch(e){$('#authError').textContent=e.message;$('#authError').classList.remove('hidden');}finally{submit.disabled=false;}});
  $('#loginTab').addEventListener('click',()=>{mode='login';updateAuthMode();});$('#registerTab').addEventListener('click',()=>{mode='register';updateAuthMode();});
  $$('[data-tool]').forEach(el=>el.addEventListener('click',()=>setTool(el.dataset.tool)));
  $('#language').addEventListener('change',()=>setTool(tool));$('#sampleBtn').addEventListener('click',loadSample);$('#runBtn').addEventListener('click',run);$('#clearBtn').addEventListener('click',()=>{code.value='';before.value='';after.value='';prompt.value='';updateCount();clearResult();});code.addEventListener('input',updateCount);code.addEventListener('scroll',()=>{$('#lineGutter').scrollTop=code.scrollTop;});
  [code,before,after].forEach(el=>el.addEventListener('keydown',ev=>{if(ev.key==='Tab'){ev.preventDefault();el.setRangeText('    ',el.selectionStart,el.selectionEnd,'end');updateCount();}}));
  document.addEventListener('keydown',ev=>{if((ev.ctrlKey||ev.metaKey)&&ev.key==='Enter'){ev.preventDefault();if($('#authOverlay').classList.contains('hidden'))run();}if(ev.key==='Escape')closeDrawer();});
  $('#copyBtn').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(result);toast('Report copied.');}catch{toast('Clipboard unavailable. Use Export.');}});
  $('#downloadBtn').addEventListener('click',()=>{if(!result)return;const data=new Blob([`# कोडनीती AI · ${TOOLS[tool][0]}\n\n${result}\n`],{type:'text/markdown;charset=utf-8'});const url=URL.createObjectURL(data);const a=document.createElement('a');a.href=url;a.download=`kodniti-${tool}-${new Date().toISOString().slice(0,10)}.md`;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  $('#historyBtn').addEventListener('click',showHistory);$('#insightsBtn').addEventListener('click',()=>refreshMetrics(true));$('#aboutBtn').addEventListener('click',showAbout);$('#footerAbout').addEventListener('click',showAbout);$('#accountBtn').addEventListener('click',()=>user?showAccount():openAuth('login'));
  $('#drawerClose').addEventListener('click',closeDrawer);$('#scrim').addEventListener('click',()=>{closeDrawer();$('#sidebar').classList.remove('open');});$('#menuBtn').addEventListener('click',()=>{closeDrawer();$('#sidebar').classList.toggle('open');});
  $('#clearHistoryBtn').addEventListener('click',async()=>{if(!confirm('Delete all saved analyses and their caches?'))return;try{await api('/api/history',{method:'DELETE'});showHistory();refreshMetrics(false);toast('History and cache cleared.');}catch(e){toast(e.message);}});
  function handleZipSelection(f){
    if(!f.name.toLowerCase().endsWith('.zip')){toast('Please choose a valid .zip file.');return;}
    if(f.size>5*1024*1024){toast('Archive exceeds 5 MB upload limit.');return;}
    selectedZipFile=f;
    zipInfo.textContent=`Selected: ${f.name} (${(f.size/1024).toFixed(1)} KB)`;
    zipInfo.classList.remove('hidden');
    $('#fileLabel').textContent=f.name;
    toast(`Archive "${f.name}" ready to audit.`);
  }
  if(browseZipBtn&&zipInput&&zipDropzone){
    browseZipBtn.addEventListener('click',()=>zipInput.click());
    zipDropzone.addEventListener('click',e=>{if(e.target!==browseZipBtn)zipInput.click();});
    zipDropzone.addEventListener('dragover',e=>{e.preventDefault();zipDropzone.classList.add('dragover');});
    ['dragleave','dragend'].forEach(ev=>zipDropzone.addEventListener(ev,()=>zipDropzone.classList.remove('dragover')));
    zipDropzone.addEventListener('drop',e=>{
      e.preventDefault();zipDropzone.classList.remove('dragover');
      if(e.dataTransfer.files&&e.dataTransfer.files.length)handleZipSelection(e.dataTransfer.files[0]);
    });
    zipInput.addEventListener('change',()=>{
      if(zipInput.files&&zipInput.files.length)handleZipSelection(zipInput.files[0]);
    });
  }
  setTool('verify-repair');updateCount();refreshService();hydrateAuth();
})();
