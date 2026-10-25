"""Bounded, single-worker rate limiter for analysis and stricter account attempts."""
from collections import OrderedDict,deque
import asyncio
import time
from starlette.responses import JSONResponse
from config import settings

class RateLimiterMiddleware:
    def __init__(self,app):
        self.app=app
        self.hits=OrderedDict()
        self.lock=asyncio.Lock()

    async def __call__(self,scope,receive,send):
        if (scope['type']!='http' or scope['method']!='POST'
                or not scope['path'].startswith('/api/')
                or scope['path']=='/api/auth/logout'):
            return await self.app(scope,receive,send)
        address=scope.get('client')
        ip=address[0] if address else 'unknown'
        auth=scope['path'] in {'/api/auth/login','/api/auth/register'}
        window=900 if auth else 60
        limit=8 if auth else settings.rate_limit
        current_user=scope.get('state',{}).get('user')
        # Rate-limit authenticated analysis by account, not by Railway's shared proxy IP.
        identity=f'ip:{ip}' if auth or not current_user else f'user:{current_user["id"]}'
        key=f'{identity}:{"auth" if auth else "api"}'
        now=time.monotonic()
        async with self.lock:
            bucket=self.hits.setdefault(key,deque())
            while bucket and now-bucket[0]>=window:
                bucket.popleft()
            if len(bucket)>=limit:
                delay=max(1,int(window-(now-bucket[0])+1))
                response=JSONResponse({'detail':'Request limit reached. Try again later.'},
                                      status_code=429,headers={'Retry-After':str(delay)})
            else:
                bucket.append(now)
                self.hits.move_to_end(key)
                while len(self.hits)>2000:
                    self.hits.popitem(last=False)
                response=None
        if response:
            return await response(scope,receive,send)
        return await self.app(scope,receive,send)
