"""Protected analysis and private history endpoints with per-user metrics."""
import shutil
from fastapi import APIRouter,HTTPException,Request,Query,Depends,UploadFile,File,Form
from config import settings
from database import list_history,remove_history,clear_history,workspace_stats,save_history
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
    from database import take_ai_quota
    from services.audit_engine import execute_repair_verification
    import time

    # Enforce daily AI quota limit on repair verification requests
    allowed, _ = take_ai_quota(user['id'])
    if not allowed:
        raise HTTPException(status_code=429, detail='Daily AI request quota reached. Try again tomorrow (UTC).')

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
        raise HTTPException(502,"Automated repair verification failed. Please try again.") from exc

@router.post('/audit-project',response_model=AnalysisResponse)
async def audit_project_zip(file:UploadFile=File(...),persist_history:bool=Form(False,alias='save_history'),user=Depends(current_user)):
    import time
    started=time.perf_counter()
    if not file.filename.lower().endswith('.zip'):
        raise HTTPException(422,'Upload a valid .zip archive containing Python source files.')
    contents=await file.read()
    if len(contents)>5*1024*1024:
        raise HTTPException(413,'ZIP archive exceeds 5 MB compressed upload limit.')
    
    import zipfile
    import io
    from services.audit_engine import audit_code
    
    total_loc=0
    all_findings_count=0
    high_count=0
    med_count=0
    low_count=0
    total_complexity=0
    modules=[]
    findings_details=[]
    
    MAX_UNCOMPRESSED_TOTAL = 15 * 1024 * 1024  # 15 MB total expanded limit (Zip bomb defense)
    MAX_UNCOMPRESSED_FILE = 1 * 1024 * 1024    # 1 MB per file limit
    MAX_PY_FILES = 30
    running_uncompressed_bytes = 0

    try:
        with zipfile.ZipFile(io.BytesIO(contents)) as z:
            candidate_infos = []
            for info in z.infolist():
                name = info.filename.replace('\\', '/')
                # Path traversal defense
                if name.startswith('/') or '..' in name:
                    raise HTTPException(422, 'Insecure path traversal detected in ZIP archive.')
                parts = name.split('/')
                if name.endswith('.py') and not any(part.startswith(('.', '__', 'venv', 'env', 'node_modules', 'dist', 'build')) for part in parts):
                    if info.file_size > MAX_UNCOMPRESSED_FILE:
                        raise HTTPException(413, f"File '{name}' exceeds 1 MB uncompressed file limit.")
                    running_uncompressed_bytes += info.file_size
                    if running_uncompressed_bytes > MAX_UNCOMPRESSED_TOTAL:
                        raise HTTPException(413, 'ZIP archive exceeds 15 MB uncompressed size limit (Zip Bomb protection).')
                    candidate_infos.append(info)

            if not candidate_infos:
                raise HTTPException(422,'No valid Python (.py) source files found in the uploaded archive.')
            if len(candidate_infos) > MAX_PY_FILES:
                raise HTTPException(422, f'Archive exceeds {MAX_PY_FILES} Python files limit.')
            
            for info in candidate_infos:
                normalized_path = info.filename.replace('\\', '/')
                raw = z.read(info.filename).decode('utf-8', errors='replace')
                res = audit_code(raw)
                loc = res['metrics']['loc']
                cplx = res['metrics']['cyclomatic_complexity']
                findings = res['findings']
                
                file_high = sum(1 for f in findings if f.get('severity') == 'HIGH')
                file_med = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
                file_low = sum(1 for f in findings if f.get('severity') == 'LOW')
                
                total_loc += loc
                total_complexity += cplx
                all_findings_count += len(findings)
                high_count += file_high
                med_count += file_med
                low_count += file_low
                
                modules.append({
                    'path': normalized_path,
                    'loc': loc,
                    'complexity': cplx,
                    'findings_count': len(findings),
                    'high_count': file_high,
                    'findings': findings
                })
    except zipfile.BadZipFile:
        raise HTTPException(422,'Corrupted or invalid ZIP archive.')

    # Sort modules: Highest risk first
    modules.sort(key=lambda m: (m['high_count'], m['findings_count'], m['complexity']), reverse=True)

    file_rows = []
    for m in modules:
        file_rows.append(f"| `{m['path']}` | {m['loc']} | {m['complexity']} | {m['findings_count']} | {m['high_count']} |")
        for f in m['findings']:
            findings_details.append(
                f"- **`{m['path']}` (Line {f.get('line', '?')})** `[{f.get('severity', 'MED')}]` {f.get('rule_id')}: {f.get('message')}"
            )

    avg_complexity = round(total_complexity / max(1, len(modules)), 1)
    if high_count >= 5:
        grade = "🔴 Grade F (Critical Security Risks)"
        health_status = "Severe vulnerabilities present. Immediate remediation required."
    elif high_count >= 1:
        grade = "🟠 Grade D (Security Risks Identified)"
        health_status = "High-severity vulnerabilities detected. Fix before deployment."
    elif all_findings_count > 10 or avg_complexity > 8:
        grade = "🟡 Grade C (Moderate Technical Debt)"
        health_status = "High branch complexity or multiple code smells present."
    elif all_findings_count > 0:
        grade = "🟢 Grade B (Good Maintainability)"
        health_status = "Clean security profile with minor code smells."
    else:
        grade = "🏆 Grade A+ (Exceptional Quality)"
        health_status = "Zero static issues or security violations detected."

    roadmap = []
    if high_count > 0:
        vulnerable_files = [m['path'] for m in modules if m['high_count'] > 0]
        roadmap.append(f"1. **Critical Security Patching:** Remediate high-severity issues in `{', '.join(vulnerable_files[:3])}` using the **Verify & Auto-Repair** tool.")
    if avg_complexity > 6:
        complex_files = [m['path'] for m in modules if m['complexity'] > 8]
        if complex_files:
            roadmap.append(f"2. **Algorithmic Refactoring:** Decompose high-complexity functions in `{', '.join(complex_files[:3])}` to reduce cyclomatic depth.")
    roadmap.append("3. **Continuous Verification:** Re-upload project ZIP after fixes to verify that the health grade advances toward Grade A+.")

    elapsed = max(1, round((time.perf_counter()-started)*1000))

    md = [
        "## 📦 Multi-File Project Security & Quality Audit\n",
        f"**Audited Archive:** `{file.filename}` · Scanned **{len(candidate_infos)}** Python modules\n",
        "### 📊 Project Aggregated Metrics",
        f"- **Project Health Grade:** **{grade}**",
        f"- **Total Lines of Code (LOC):** `{total_loc}` across `{len(modules)}` modules",
        f"- **Average Cyclomatic Complexity:** `{avg_complexity}` per module",
        f"- **Security Findings Breakdown:** `{high_count}` High ⚠️ · `{med_count}` Medium · `{low_count}` Low",
        f"- **Executive Assessment:** {health_status}",
        "\n### 📁 Module Breakdown (Sorted by Priority)\n",
        "| Module Path | LOC | Complexity | Issues | High Sev |",
        "| :--- | :---: | :---: | :---: | :---: |",
        *file_rows,
        "\n### 🎯 Recommended Remediation Roadmap\n",
        *roadmap
    ]
    if findings_details:
        md.append("\n### 🔍 Detailed Project Findings\n" + '\n'.join(findings_details[:50]))
        if len(findings_details) > 50:
            md.append(f"\n*...and {len(findings_details)-50} additional findings.*")
    
    md.append("\n**Engine:** Deterministic AST & Bandit Scanner (Executed in memory with safe zip decompression).")
    
    result_text = '\n'.join(md)
    if persist_history:
        save_history(user['id'], 'audit-project', 'python', file.filename, '', '', result_text, 'bandit+ast')

    return AnalysisResponse(
        tool='audit-project',
        result=result_text,
        engine='bandit+ast',
        cached=False,
        saved=persist_history,
        duration_ms=elapsed,
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
