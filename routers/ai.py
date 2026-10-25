"""Protected analysis and private history endpoints with per-user metrics."""
import shutil
from fastapi import APIRouter,HTTPException,Request,Query,Depends,UploadFile,File
from config import settings
from database import list_history,remove_history,clear_history,workspace_stats
from models.schemas import CodeRequest,CompareRequest,GenerateRequest,AnalysisResponse,HistoryEntry
from routers.auth import current_user
from services.gemini import AIServiceError
from services.static_analysis import LocalToolError
from services.pipeline import process

router=APIRouter(prefix='/api',tags=['Analysis'])

async def analyze(tool:str,req,user):
    try:
        return await process(tool,user['id'],req.model_dump(exclude={'save_history'}),req.save_history)
    except (AIServiceError,LocalToolError) as exc:
        raise HTTPException(status_code=exc.status,detail=exc.message) from exc

@router.post('/optimize',response_model=AnalysisResponse)
async def optimize(req:CodeRequest,user=Depends(current_user)):
    return await analyze('optimize',req,user)

@router.post('/generate',response_model=AnalysisResponse)
async def generate(req:GenerateRequest,user=Depends(current_user)):
    return await analyze('generate',req,user)

@router.post('/complexity',response_model=AnalysisResponse)
async def complexity(req:CodeRequest,user=Depends(current_user)):
    return await analyze('complexity',req,user)

@router.post('/debug',response_model=AnalysisResponse)
async def debug(req:CodeRequest,user=Depends(current_user)):
    return await analyze('debug',req,user)

@router.post('/testcases',response_model=AnalysisResponse)
async def testcases(req:CodeRequest,user=Depends(current_user)):
    return await analyze('testcases',req,user)

@router.post('/compare',response_model=AnalysisResponse)
async def compare(req:CompareRequest,user=Depends(current_user)):
    return await analyze('compare',req,user)

@router.post('/security',response_model=AnalysisResponse)
async def security(req:CodeRequest,user=Depends(current_user)):
    return await analyze('security',req,user)

@router.post('/beautify',response_model=AnalysisResponse)
async def beautify(req:CodeRequest,user=Depends(current_user)):
    return await analyze('beautify',req,user)

@router.post('/verify-repair',response_model=AnalysisResponse)
async def verify_repair(req:CodeRequest,user=Depends(current_user)):
    from services.audit_engine import execute_repair_verification
    import time
    started=time.perf_counter()
    try:
        report=await execute_repair_verification(req.code,req.language)
        elapsed=round((time.perf_counter()-started)*1000)
        return AnalysisResponse(
            tool='verify-repair',
            result=report['report_markdown'],
            engine='bandit+ast+gemini',
            cached=False,
            saved=False,
            duration_ms=elapsed,
            disclaimer='Targeted repair re-scanned and verified using Python AST and Bandit.'
        )
    except Exception as exc:
        raise HTTPException(502,f"Verification repair pipeline error: {str(exc)}") from exc

@router.post('/audit-project',response_model=AnalysisResponse)
async def audit_project_zip(file:UploadFile=File(...),user=Depends(current_user)):
    if not file.filename.lower().endswith('.zip'):
        raise HTTPException(422,'Upload a valid .zip archive containing Python source files.')
    contents=await file.read()
    if len(contents)>5*1024*1024:
        raise HTTPException(413,'ZIP archive exceeds 5 MB limit.')
    
    import zipfile
    import io
    from services.audit_engine import audit_code
    
    total_loc=0
    all_findings_count=0
    high_count=0
    file_rows=[]
    findings_details=[]
    
    try:
        with zipfile.ZipFile(io.BytesIO(contents)) as z:
            py_files=[n for n in z.namelist() if n.endswith('.py') and not any(part.startswith(('.', '__', 'venv', 'env')) for part in n.split('/'))]
            if not py_files:
                raise HTTPException(422,'No valid Python (.py) source files found in the uploaded archive.')
            if len(py_files)>40:
                raise HTTPException(422,'Archive exceeds 40 Python files limit.')
            
            for name in py_files:
                raw=z.read(name).decode('utf-8',errors='replace')
                res=audit_code(raw)
                loc=res['metrics']['loc']
                findings=res['findings']
                total_loc+=loc
                all_findings_count+=len(findings)
                file_high=sum(1 for f in findings if f.get('severity')=='HIGH')
                high_count+=file_high
                file_rows.append(f"| `{name}` | {loc} | {res['metrics']['cyclomatic_complexity']} | {len(findings)} | {file_high} |")
                for f in findings:
                    findings_details.append(f"- **`{name}` (Line {f.get('line','?')})** `[{f.get('severity','MED')}]` {f.get('rule_id')}: {f.get('message')}")
    except zipfile.BadZipFile:
        raise HTTPException(422,'Corrupted or invalid ZIP archive.')

    md=[
        "## 📦 Multi-File Project Security & Quality Audit\n",
        f"**Audited Archive:** `{file.filename}` · Scanned **{len(py_files)}** Python modules\n",
        "### 📊 Project Aggregated Metrics",
        f"- **Total Lines of Code (LOC):** `{total_loc}`",
        f"- **Total Static Findings:** `{all_findings_count}`",
        f"- **High-Severity Security Risks:** `{high_count}` " + ("⚠️ (Action Required)" if high_count>0 else "✅ (None)"),
        f"- **Overall Code Health:** " + ("🟢 Clean" if all_findings_count==0 else "🟡 Needs Attention" if high_count==0 else "🔴 Critical Vulnerabilities Found"),
        "\n### 📁 Module Breakdown\n",
        "| Module Path | LOC | Complexity | Issues | High Sev |",
        "| :--- | :---: | :---: | :---: | :---: |",
        *file_rows
    ]
    if findings_details:
        md.append("\n### 🔍 Detailed Project Findings\n" + '\n'.join(findings_details[:50]))
        if len(findings_details)>50:
            md.append(f"\n*...and {len(findings_details)-50} additional findings.*")
    
    md.append("\n**Engine:** Deterministic AST & Bandit Scanner (Executed in memory with safe zip decompression).")
    
    return AnalysisResponse(
        tool='audit-project',
        result='\n'.join(md),
        engine='bandit+ast',
        cached=False,
        saved=False,
        duration_ms=50,
        disclaimer='Multi-file project static inspection completed without code execution.'
    )

@router.get('/status')
async def status():
    return {'ok':True,'ai_available':bool(settings.gemini_api_key),'model':settings.gemini_model,
            'local_tools':{'compare':True,'beautify':bool(shutil.which('ruff')),
                           'security':bool(shutil.which('bandit'))},'version':'3.0.0'}

@router.get('/stats')
async def stats(user=Depends(current_user)):
    return workspace_stats(user['id'])

@router.get('/history',response_model=list[HistoryEntry])
async def history(limit:int=Query(30,ge=1,le=100),user=Depends(current_user)):
    return list_history(user['id'],limit)

@router.delete('/history/{item_id}')
async def delete_item(item_id:int,user=Depends(current_user)):
    if not remove_history(user['id'],item_id):
        raise HTTPException(404,'History item not found.')
    return {'ok':True}

@router.delete('/history')
async def delete_history(user=Depends(current_user)):
    clear_history(user['id'])
    from services.cache import cache
    cache.clear()
    return {'ok':True}
