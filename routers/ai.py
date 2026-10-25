"""Protected analysis and private history endpoints with per-user metrics."""
import shutil
from fastapi import APIRouter,HTTPException,Request,Query,Depends
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
