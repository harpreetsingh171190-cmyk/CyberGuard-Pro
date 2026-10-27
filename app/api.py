import os
from fastapi import FastAPI, Depends, Header, HTTPException, Query, Request
from app.security import SecurityHeadersMiddleware, rate_limit
from pydantic import BaseModel, Field
from app.core import authorize, score_urls, active_version, history, activate
app=FastAPI(title='CyberGuard API',version='5.0.0',docs_url=None if os.getenv('CYBERGUARD_ENV')=='production' else '/docs')
app.add_middleware(SecurityHeadersMiddleware)
class ScanRequest(BaseModel):
    urls:list[str]=Field(min_length=1,max_length=500)

def auth(authorization:str|None=Header(default=None)):
    token=authorization[7:] if authorization and authorization.startswith('Bearer ') else None
    if not authorize(token):raise HTTPException(401,'Unauthorized')

@app.get('/ready')
def ready():
    try:
        from app.core import load_model
        load_model()
        return {'ready':True}
    except (FileNotFoundError, ValueError):
        raise HTTPException(503, 'No active approved model')

@app.get('/health')
def health():return {'status':'ok'}
@app.get('/model',dependencies=[Depends(auth)])
def model():
    try:return {'active_version':active_version()}
    except FileNotFoundError:return {'active_version':None}
@app.post('/scan',dependencies=[Depends(auth),Depends(rate_limit)])
def scan(req:ScanRequest):
    try:return {'results':score_urls(req.urls)}
    except (ValueError,FileNotFoundError) as e:raise HTTPException(422,str(e))
@app.get('/audit',dependencies=[Depends(auth)])
def audit_log(limit:int=Query(default=100,ge=1,le=500)):return {'events':history(limit)}
@app.post('/admin/activate/{version}',dependencies=[Depends(auth),Depends(rate_limit)])
def activate_model(version:str):
    if os.getenv('CYBERGUARD_ALLOW_ADMIN_API')!='true':raise HTTPException(403,'Admin API disabled')
    try:activate(version);return {'active_version':version}
    except ValueError as e:raise HTTPException(422,str(e))
