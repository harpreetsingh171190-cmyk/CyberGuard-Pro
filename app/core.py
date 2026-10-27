import os, json, hashlib, hmac, sqlite3, time
from pathlib import Path
from datetime import datetime, timezone
from functools import lru_cache
from threading import Lock
from urllib.parse import urlparse
from collections import Counter
import math, re

ROOT=Path(__file__).resolve().parents[1]
MODEL_DIR=Path(os.getenv('CYBERGUARD_MODEL_DIR',str(ROOT/'models'))).resolve()
DB=Path(os.getenv('CYBERGUARD_DB',str(ROOT/'cyberguard.sqlite3')))
_LOCK=Lock()

def audit(action, detail=''):
    DB.parent.mkdir(parents=True,exist_ok=True)
    with _LOCK, sqlite3.connect(DB,timeout=10) as con:
        con.execute('CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, action TEXT, detail TEXT)')
        con.execute('INSERT INTO audit(ts,action,detail) VALUES(?,?,?)',(datetime.now(timezone.utc).isoformat(),action,str(detail)[:300]))

def history(limit=100):
    with sqlite3.connect(DB,timeout=10) as con:
        con.execute('CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, action TEXT, detail TEXT)')
        return [{'time':r[0],'action':r[1],'detail':r[2]} for r in con.execute('SELECT ts,action,detail FROM audit ORDER BY id DESC LIMIT ?', (min(max(limit,1),500),))]

def authorize(token):
    expected=os.getenv('CYBERGUARD_API_TOKEN','')
    return bool(expected) and bool(token) and hmac.compare_digest(expected,token)

def safe_url(url):
    from cyberguard_threat_intel import inspect_target
    inspect_target(url)
    return url

def entropy(s):
    return -sum((v/len(s))*math.log2(v/len(s)) for v in Counter(s).values()) if s else 0.

# Feature extractor is sourced from the existing notebook; the notebook exports this module's feature schema.
@lru_cache(maxsize=2)
def load_model(version=None):
    import joblib
    name=version or active_version()
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',name) or name.startswith('.'):
        raise ValueError('Invalid model version')
    path=(MODEL_DIR/name/'model.joblib').resolve()
    if not path.is_relative_to(MODEL_DIR) or not path.exists():
        raise FileNotFoundError('No approved model artifact. See README model registration.')
    # Joblib is pickle based: only administrators should register trusted local artifacts.
    payload=joblib.load(path)
    if not isinstance(payload,dict) or not {'model','features'} <= payload.keys():
        raise ValueError('Invalid model bundle')
    return payload

def active_version():
    p=MODEL_DIR/'active.json'
    if not p.exists():
        raise FileNotFoundError('No active model; register a trusted notebook artifact first')
    return json.loads(p.read_text())['version']

def register(source,version):
    import joblib
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',version):raise ValueError('Invalid version')
    source=Path(source).resolve()
    if not source.is_file():raise FileNotFoundError(source)
    target=MODEL_DIR/version
    if target.exists():raise FileExistsError('Version already exists')
    payload=joblib.load(source) # trusted admin-only artifact
    if not isinstance(payload,dict) or not {'model','features'}<=payload.keys():raise ValueError('Bad model bundle')
    target.mkdir(parents=True)
    shutil_path=target/'model.joblib'
    import shutil
    shutil.copyfile(source,shutil_path)
    (target/'manifest.json').write_text(json.dumps({'version':version,'sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'registered_utc':datetime.now(timezone.utc).isoformat()},indent=2))
    audit('model_registered',version)

def activate(version):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',version) or not (MODEL_DIR/version/'model.joblib').is_file():raise ValueError('Unknown version')
    MODEL_DIR.mkdir(parents=True,exist_ok=True)
    temp=MODEL_DIR/'active.json.tmp'
    temp.write_text(json.dumps({'version':version}))
    temp.replace(MODEL_DIR/'active.json')
    load_model.cache_clear()
    audit('model_activated',version)

def score_urls(urls):
    import pandas as pd
    from app.features import extract_features
    if len(urls)>500:raise ValueError('Maximum 500 URLs per request')
    if not urls:return []
    urls=[safe_url(x) for x in urls]
    bundle=load_model()
    features=pd.DataFrame([extract_features(u) for u in urls])[bundle['features']]
    scores=bundle['model'].predict_proba(features)[:,1]
    result=[{'url':u,'risk_score':round(float(p),5),'risk_band':('critical' if p>=.8 else 'high' if p>=.5 else 'moderate' if p>=.2 else 'low')} for u,p in zip(urls,scores)]
    audit('scan',f'count={len(result)}') # no raw URLs in audit log
    return result
