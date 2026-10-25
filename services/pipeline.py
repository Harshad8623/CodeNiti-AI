"""Cached hybrid tool pipeline. Stores submitted source only after explicit opt-in."""
import asyncio
import time
from config import settings,PROMPT_VERSION
from database import fingerprint,cache_get,cache_put,save_history,record_metric,take_ai_quota
from services.cache import cache
from services.gemini import call_gemini,AIServiceError
from services.static_analysis import compare,beautify,security
from models.schemas import AnalysisResponse

LOCAL={'compare':('diff',compare),'beautify':('ruff',beautify),'security':('bandit',security)}
DISCLAIMERS={
    'complexity':'Complexity is an AI estimate, not a formal proof.',
    'optimize':'Recommendations were not executed or independently verified.',
    'generate':'Generated code was not executed. Review and test it.',
    'debug':'Potential bugs need confirmation through testing.',
    'testcases':'Proposed tests were not run.',
    'security':'Bandit checks are limited and do not establish complete security.',
    'compare':'A textual diff cannot prove program equivalence.',
    'beautify':'Source was formatted without execution.',
}

async def process(tool:str,user_id:int,payload:dict,save:bool)->AnalysisResponse:
    started=time.perf_counter()
    language=payload.get('language','python')
    code=payload.get('code',payload.get('code1',''))
    code2=payload.get('code2','')
    prompt=payload.get('prompt','')
    engine=LOCAL[tool][0] if tool in LOCAL else 'gemini'
    key=fingerprint(user_id,{'tool':tool,'payload':payload,'engine':engine,
                             'model':settings.gemini_model if engine=='gemini' else 'local-v2',
                             'prompt_version':PROMPT_VERSION})
    found=None
    if save:
        found=cache.get(key)
        if found is None:
            found=cache_get(key,user_id)
            if found is not None:
                cache.set(key,found)
    cached=found is not None
    if cached:
        result,engine=found['result'],found['engine']
    else:
        if tool in LOCAL:
            action=LOCAL[tool][1]
            result=await asyncio.to_thread(action,code,code2,language) if tool=='compare' else await asyncio.to_thread(action,code,language)
        else:
            # A cache hit does not spend AI tokens and must not consume the daily AI budget.
            allowed, _ = take_ai_quota(user_id)
            if not allowed:
                raise AIServiceError(429, 'Daily AI request quota reached. Try again tomorrow (UTC).')
            result=await call_gemini(tool,payload)
        if save:
            data={'result':result,'engine':engine}
            cache.set(key,data)
            cache_put(key,user_id,result,engine)
    if save:
        save_history(user_id,tool,language,code,code2,prompt,result,engine)
    elapsed=(time.perf_counter()-started)*1000
    record_metric(user_id,tool,engine,cached,elapsed)
    return AnalysisResponse(tool=tool,result=result,engine=engine,cached=cached,saved=save,
                            duration_ms=round(elapsed),disclaimer=DISCLAIMERS.get(tool,''))
