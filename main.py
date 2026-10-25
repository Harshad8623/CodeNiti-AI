"""कोडनीती AI — final-year major project, E&CE, CSMSS Chh. Shahu College of Engineering."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from config import ROOT,settings
from database import init_db
from middleware.rate_limiter import RateLimiterMiddleware
from routers.ai import router as analysis_router
from routers.auth import router as auth_router
from services.auth import COOKIE,session_user

@asynccontextmanager
async def lifespan(app:FastAPI):
    init_db()
    yield

app=FastAPI(title='कोडनीती AI',description='AI-powered code intelligence for optimization, complexity and security',
            version='3.0.0',lifespan=lifespan)

class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self,request:Request,call_next):
        request.state.user=session_user(request.cookies.get(COOKIE,''))
        if request.url.path.startswith('/api/') and request.method in {'POST','PATCH','PUT','DELETE'}:
            # Custom header is required on JSON mutations: stops HTML form CSRF without a CORS grant.
            if request.headers.get('X-Requested-With')!='XMLHttpRequest':
                return JSONResponse({'detail':'Missing same-site request header.'},status_code=403)
            origin=request.headers.get('origin')
            if origin:
                from urllib.parse import urlsplit
                if urlsplit(origin).netloc.lower()!=request.headers.get('host','').lower():
                    return JSONResponse({'detail':'Cross-origin request rejected.'},status_code=403)
        response=await call_next(request)
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Content-Security-Policy']=(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'")
        response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
        if request.url.path.startswith('/api/'):
            response.headers['Cache-Control']='no-store'
        return response

app.add_middleware(RateLimiterMiddleware)
app.add_middleware(SecurityMiddleware)
app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')
app.include_router(auth_router)
app.include_router(analysis_router)
templates=Jinja2Templates(directory=ROOT/'templates')

@app.get('/',response_class=HTMLResponse,include_in_schema=False)
async def home(request:Request):
    return templates.TemplateResponse(request=request,name='index.html')

@app.get('/health',tags=['Operations'])
async def health():
    return {'status':'healthy','version':'3.0.0'}

if __name__=='__main__':
    import uvicorn
    uvicorn.run('main:app',host='127.0.0.1',port=settings.port)
