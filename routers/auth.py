"""Account routes. Only the authenticated user can read, delete or export personal history."""
import re
import asyncio
from fastapi import APIRouter, HTTPException, Request, Response, Depends
from pydantic import BaseModel, Field, field_validator
from config import settings
from database import clear_account
from services.auth import COOKIE, SESSION_DAYS, authenticate, create_session, create_user, revoke_session

router = APIRouter(prefix='/api/auth',tags=['Accounts'])


class Credentials(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=10,max_length=128)
    @field_validator('email')
    @classmethod
    def email_format(cls,v):
        value = v.strip().lower()
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',value):
            raise ValueError('Enter a valid email address.')
        return value


class Registration(Credentials):
    display_name: str = Field(min_length=2,max_length=70)
    @field_validator('display_name')
    @classmethod
    def name_format(cls,v):
        value = v.strip()
        if len(value)<2 or '<' in value or '>' in value:
            raise ValueError('Enter a valid display name.')
        return value


def current_user(request:Request):
    if request.state.user is None:
        raise HTTPException(status_code=401,detail='Sign in to continue.')
    return request.state.user


def user_response(user):
    return {'id':user['id'],'display_name':user['display_name'],'email':user['email']}


def set_auth_cookie(response:Response,token:str):
    response.set_cookie(COOKIE,token,httponly=True,samesite='lax',
                        secure=settings.app_env=='production',max_age=86400*SESSION_DAYS,path='/')


@router.get('/me')
async def me(request:Request):
    return {'user': user_response(request.state.user) if request.state.user else None,
            'signup_enabled':settings.signup_enabled}


@router.post('/register',status_code=201)
async def register(body:Registration, request:Request,response:Response):
    if not settings.signup_enabled:
        raise HTTPException(status_code=403,detail='New account registration is disabled.')
    user_id=await asyncio.to_thread(create_user,body.display_name,body.email,body.password)
    if user_id is None:
        raise HTTPException(status_code=409,detail='An account with this email already exists.')
    if request.cookies.get(COOKIE):
        revoke_session(request.cookies[COOKIE])
    token=await asyncio.to_thread(create_session,user_id)
    set_auth_cookie(response,token)
    return {'user':{'id':user_id,'display_name':body.display_name,'email':body.email}}


@router.post('/login')
async def login(body:Credentials,request:Request,response:Response):
    user=await asyncio.to_thread(authenticate,body.email,body.password)
    if user is None:
        raise HTTPException(status_code=401,detail='Invalid email or password.')
    if request.cookies.get(COOKIE):
        revoke_session(request.cookies[COOKIE])
    set_auth_cookie(response,await asyncio.to_thread(create_session,user['id']))
    return {'user':user_response(user)}


@router.post('/logout')
async def logout(request:Request,response:Response):
    revoke_session(request.cookies.get(COOKIE,''))
    response.delete_cookie(COOKIE,path='/',samesite='lax',secure=settings.app_env=='production')
    return {'ok':True}


@router.delete('/account')
async def delete_account(request:Request,response:Response,user=Depends(current_user)):
    clear_account(user['id'])
    # Discard in-process reports after deletion; persistent entries cascade in SQLite.
    from services.cache import cache
    cache.clear()
    response.delete_cookie(COOKIE,path='/',samesite='lax',secure=settings.app_env=='production')
    return {'ok':True}
