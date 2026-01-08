from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Depends
import asyncio
import os
import logging
import sys
import re
import requests
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from .crud import create_property, list_properties, import_invoice, log_activity, add_inventory, create_user, grant_property_access, revoke_property_access, get_user_properties, get_property_users, user_can_access_property
from sqlmodel import select
from .database import get_session
from .models import User
from .database import init_db
from . import ai
from . import auth
from . import resman

def configure_logging():
    level_name = os.getenv('LOG_LEVEL', 'INFO').upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(level=level, format='%(asctime)s %(levelname)s %(name)s %(message)s')

# initialize logging as early as possible
configure_logging()
logger = logging.getLogger("backend")

import pandas as pd
from datetime import datetime
import io

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

# Load index.html for serving at root
import pathlib
INDEX_PATH = pathlib.Path(__file__).parent.parent / "index.html"
try:
    with open(INDEX_PATH, 'r', encoding='utf-8') as f:
        INDEX_CONTENT = f.read()
    logger.info(f"Successfully loaded index.html from {INDEX_PATH}")
except Exception as e:
    logger.error(f"Failed to load index.html from {INDEX_PATH}: {e}")
    INDEX_CONTENT = "<h1>Balancing Bolts</h1><p>Unable to load index.html</p>"

# Background resman poller task handle
resman_task: asyncio.Task | None = None

async def _resman_worker(interval_seconds: int):
    while True:
        try:
            await asyncio.to_thread(resman.pull_once)
        except Exception:
            logger.exception("Exception in ResMan worker")
        await asyncio.sleep(interval_seconds)


@app.on_event("startup")
async def _startup_resman_poller():
    global resman_task
    try:
        interval = int(os.getenv('RESMAN_POLL_INTERVAL', '3600'))
    except Exception:
        interval = 3600
    # only start if RESMAN_INVOICES_URL is configured
    try:
        if os.getenv('RESMAN_INVOICES_URL'):
            resman_task = asyncio.create_task(_resman_worker(interval))
    except Exception:
        logger.exception("Failed to start ResMan poller during startup")


@app.on_event("startup")
async def _configure_on_startup():
    try:
        logger.info("Starting application, RESMAN_POLL_INTERVAL=%s", os.getenv('RESMAN_POLL_INTERVAL'))
        # install a global exception hook so unhandled exceptions are logged
        def _excepthook(exc_type, exc, tb):
            logger.exception('Uncaught exception', exc_info=(exc_type, exc, tb))
        sys.excepthook = _excepthook
    except Exception:
        logger.exception("Error in startup configuration")
    # ensure 9 property slots exist (create placeholders if none)
    try:
        with get_session() as s:
            props = s.exec(select(type(list_properties()).__args__[0] if hasattr(list_properties(), '__args__') else "property")).all()
    except Exception:
        # fallback: use the crud list_properties
        try:
            props = list_properties()
        except Exception:
            props = []
    try:
        # if there are fewer than 9 properties, create placeholders
        if len(props) < 9:
            for i in range(1, 10):
                name = f"Property {i}"
                # avoid duplicates
                existing = [p for p in props if getattr(p, 'name', '') == name]
                if existing:
                    continue
                try:
                    create_property(name=name, address='')
                except Exception:
                    pass
    except Exception:
        logger.exception('Error seeding default properties')


@app.on_event("shutdown")
async def _shutdown_resman_poller():
    global resman_task
    if resman_task:
        resman_task.cancel()
        try:
            await resman_task
        except asyncio.CancelledError:
            pass

@app.get('/api/properties')
def get_properties():
    return [p.dict() for p in list_properties()]

@app.post('/api/properties')
def post_property(name: str = Form(...), address: str = Form(None), user=Depends(auth.require_role('admin'))):
    """Create a property (admin-only)."""
    p = create_property(name=name, address=address)
    return p
@app.delete('/api/properties/{property_id}')
def delete_property(property_id: int, user=Depends(auth.require_role('admin'))):
    """Delete a property (admin-only)."""
    from .crud import delete_property as delete_prop_crud
    try:
        delete_prop_crud(property_id)
        return {'status': 'ok', 'deleted_property_id': property_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# Auth endpoints


# ResMan OAuth helpers (open redirect to start flow)
@app.get('/')
def root():
    """Serve index.html at root path."""
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=INDEX_CONTENT)


# ResMan OAuth helpers (open redirect to start flow)
@app.get('/api/auth/resman/login')
def resman_login():
    return {"authorize_url": auth.resman_authorize_url()}

@app.get('/api/auth/resman/callback')
def resman_callback(code: str = None):
    if not code:
        raise HTTPException(status_code=400, detail='code required')
    try:
        token = auth.exchange_code_for_token(code)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "ok", "token_id": token.id}

@app.post('/api/import-invoices')
async def import_invoices(file: UploadFile = File(...), property_id: int = Form(...), user=Depends(auth.get_current_user)):
    # Accept CSV with columns: vendor,date,total,description
    content = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(content))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'CSV parse error: {e}')
    created = []
    for _, row in df.iterrows():
        date = None
        try:
            date = pd.to_datetime(row.get('date'))
            date = date.to_pydatetime()
        except:
            date = datetime.utcnow()
        total = float(row.get('total') or 0)
        vendor = row.get('vendor') or ''
        raw = str(row.to_dict())
        inv = import_invoice(property_id=int(property_id), vendor=vendor, date=date, total=total, raw_text=raw)
        # store embedding for invoice text
        try:
            ai.store_embedding('invoice', inv.id, raw)
        except Exception:
            pass
        created.append({'id': inv.id, 'total': inv.total, 'vendor': inv.vendor})
    return {'imported': len(created), 'items': created}

@app.post('/api/ai/query')
async def ai_query(payload: dict):
    q = payload.get('query')
    if not q:
        raise HTTPException(status_code=400, detail='query required')
    try:
        ans = ai.answer_query(q)
    except Exception as e:
        ans = str(e)
    return {'answer': ans}


# Report endpoints
@app.get('/api/reports/monthly')
def report_monthly(year: int, month: int, property_id: int = None, user=Depends(auth.get_current_user)):
    from .crud import monthly_spend
    try:
        total = monthly_spend(property_id, int(year), int(month))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"year": int(year), "month": int(month), "property_id": property_id, "total": total}


@app.get('/api/reports/yearly')
def report_yearly(year: int, property_id: int = None, user=Depends(auth.get_current_user)):
    from .crud import yearly_spend
    try:
        total = yearly_spend(property_id, int(year))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"year": int(year), "property_id": property_id, "total": total}


def _extract_title(html: str):
    try:
        mt = re.search(r'<meta[^>]+property=["\"]og:title["\"][^>]+content=["\"]([^"\"]+)["\"]', html, re.IGNORECASE)
        if mt:
            return mt.group(1).strip()
        tt = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if tt:
            return tt.group(1).strip()
    except Exception:
        return None
    return None

def _extract_prices(html: str):
    # Find currency-like patterns, filter, and return sorted unique top 10
    nums = re.findall(r'\$\s?([0-9][0-9,]*(?:\.\d{2})?)', html)
    vals = []
    for n in nums:
        try:
            vals.append(float(n.replace(',', '')))
        except Exception:
            continue
    uniq = sorted(list({v for v in vals if v > 0}))
    return uniq[:10]

@app.post('/api/quotes/fetch')
def fetch_quote(payload: dict, user=Depends(auth.require_role('manager'))):
    """Fetch a quote from a supplier URL (lightweight scraper)."""
    url = (payload or {}).get('url')
    if not url:
        raise HTTPException(status_code=400, detail='url required')
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'fetch failed: {e}')
    html = resp.text or ''
    title = _extract_title(html)
    prices = _extract_prices(html)
    return {
        "status": "ok",
        "source_url": url,
        "page_title": title,
        "prices_detected": prices,
        "note": "Lightweight parsing; refine selectors as needed."
    }

@app.post('/api/inventory')
async def api_add_inventory(property_id: int = Form(...), name: str = Form(...), description: str = Form(None), quantity: int = Form(1), cost: float = Form(0.0), assigned_to: int = Form(None), user=Depends(auth.get_current_user)):
    item = add_inventory(property_id=int(property_id), name=name, desc=description, qty=int(quantity), cost=float(cost), assigned_to=assigned_to)
    return item


@app.get('/api/inventory')
def api_list_inventory(page: int = 1, per_page: int = 20, property_id: int = None, user=Depends(auth.get_current_user)):
    from .crud import list_inventory
    items, total = list_inventory(page=int(page), per_page=int(per_page), property_id=property_id)
    return {"items": [i.dict() for i in items], "total": total, "page": int(page), "per_page": int(per_page)}


# Auth endpoints
@app.post('/api/auth/signup')
def signup(name: str = Form(...), email: str = Form(...), password: str = Form(...), role: str = Form('maintenance')):
    # create user (stores hashed password)
    u = create_user(name=name, email=email, role=role, password=password)
    token = auth.create_access_token({"sub": u.email})
    return {"access_token": token, "token_type": "bearer", "user": u}


@app.post('/api/auth/login')
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = auth.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail='Invalid credentials')
    access_token = auth.create_access_token({"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post('/api/resman/pull')
def trigger_resman_pull(user=Depends(auth.require_role('manager'))):
    # trigger a single pull from ResMan
    from . import resman
    res = resman.pull_once()
    return res


@app.post('/api/admin/assign-property')
def admin_assign_property(payload: dict, user=Depends(auth.require_role('admin'))):
    """Assign a property to a user. payload: {email: str, property_id: int}"""
    email = payload.get('email')
    prop_id = payload.get('property_id')
    if not email or prop_id is None:
        raise HTTPException(status_code=400, detail='email and property_id required')
    from .database import get_session
    from .models import User
    with get_session() as s:
        q = select(User).where(User.email == email).order_by(User.id.desc())
        u = s.exec(q).first()
        if not u:
            raise HTTPException(status_code=404, detail='user not found')
        u.current_property_id = int(prop_id)
        s.add(u)
        s.commit()
        s.refresh(u)
        return {'status': 'ok', 'user': u}


@app.get('/api/admin/users')
def admin_list_users(user=Depends(auth.require_role('admin'))):
    """Return list of users for admin UIs (includes current_property_id)."""
    with get_session() as s:
        q = select(User).order_by(User.id.desc())
        rows = s.exec(q).all()
        out = []
        for r in rows:
            out.append({'id': r.id, 'name': r.name, 'email': r.email, 'role': r.role, 'current_property_id': r.current_property_id})
        return out


@app.get('/api/auth/me')
async def get_current_user_info(user: User = Depends(auth.get_current_user)):
    """Return current logged-in user info including property assignment."""
    return {'id': user.id, 'name': user.name, 'email': user.email, 'role': user.role, 'current_property_id': user.current_property_id}


# Admin endpoints to control background poller
@app.post('/api/resman/poller/enable')
def enable_poller(user=Depends(auth.require_role('manager'))):
    global resman_task
    if resman_task and not resman_task.done():
        return {"status": "already_running"}
    interval = int(os.getenv('RESMAN_POLL_INTERVAL', '3600'))
    try:
        resman_task = asyncio.create_task(_resman_worker(interval))
        logger.info("ResMan poller enabled by user")
    except RuntimeError:
        # no running loop (e.g., in tests); mark enabled but do not start task
        resman_task = None
        logger.info("ResMan poller enabled but no running event loop (test environment)")
    return {"status": "enabled"}


@app.post('/api/resman/poller/disable')
def disable_poller(user=Depends(auth.require_role('manager'))):
    global resman_task
    if not resman_task:
        return {"status": "already_disabled"}
    resman_task.cancel()
    resman_task = None
    logger.info("ResMan poller disabled by user")
    return {"status": "disabled"}


@app.get('/api/resman/poller/status')
def poller_status(user=Depends(auth.require_role('manager'))):
    running = bool(resman_task and not resman_task.done())
    return {"running": running}


# User Property Access Management Endpoints

@app.get('/api/users/{user_id}/properties')
def get_user_property_access(user_id: int, current_user=Depends(auth.get_current_user)):
    """Get all properties a user has access to"""
    # Only admins or the user themselves can view this
    if current_user.role != 'admin' and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    return get_user_properties(user_id)


@app.get('/api/properties/{property_id}/users')
def get_property_user_access(property_id: int, user=Depends(auth.require_role('admin'))):
    """Get all users with access to a property (admin only)"""
    return get_property_users(property_id)


@app.post('/api/users/{user_id}/properties/{property_id}/grant')
def grant_access(
    user_id: int,
    property_id: int,
    can_view: bool = Form(True),
    can_edit: bool = Form(False),
    can_delete: bool = Form(False),
    current_user=Depends(auth.require_role('admin'))
):
    """Grant a user access to a property with specific permissions (admin only)"""
    access = grant_property_access(user_id, property_id, can_view, can_edit, can_delete)
    return {"status": "success", "access": {
        "user_id": access.user_id,
        "property_id": access.property_id,
        "can_view": access.can_view,
        "can_edit": access.can_edit,
        "can_delete": access.can_delete
    }}


@app.post('/api/users/{user_id}/properties/{property_id}/revoke')
def revoke_access(
    user_id: int,
    property_id: int,
    current_user=Depends(auth.require_role('admin'))
):
    """Revoke a user's access to a property (admin only)"""
    revoke_property_access(user_id, property_id)
    return {"status": "success"}


@app.get('/api/users')
def list_all_users(current_user=Depends(auth.require_role('admin'))):
    """List all users (admin only)"""
    with get_session() as s:
        users = s.exec(select(User)).all()
        return [{"id": u.id, "name": u.name, "email": u.email, "role": u.role} for u in users]


@app.post('/api/users/{user_id}/role')
def update_user_role(
    user_id: int,
    role: str = Form(...),
    current_user=Depends(auth.require_role('admin'))
):
    """Update a user's role (admin only)"""
    valid_roles = ['admin', 'manager', 'maintenance', 'leasing']
    if role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}")

    with get_session() as s:
        user = s.exec(select(User).where(User.id == user_id)).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.role = role
        s.add(user)
        s.commit()
        s.refresh(user)

        return {"status": "success", "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role}}
