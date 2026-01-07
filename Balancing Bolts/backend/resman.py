import os
import requests
import pandas as pd
from .database import get_session
from .models import ResmanToken
from .crud import import_invoice
import os
import requests
import pandas as pd
import logging
from .database import get_session
from .models import ResmanToken
from .crud import import_invoice
from sqlmodel import select
from datetime import datetime

logger = logging.getLogger("resman")


def _fetch_with_token(url, token):
    headers = {'Authorization': f'Bearer {token}'}
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp


def pull_once():
    """Pull invoices from ResMan for all stored tokens.

    Returns a dict with counts and errors for reporting/logging.
    """
    invoices_url = os.getenv('RESMAN_INVOICES_URL')
    if not invoices_url:
        raise RuntimeError('RESMAN_INVOICES_URL not configured')
    result = {"pulled": 0, "errors": []}
    with get_session() as s:
        toks = s.exec(select(ResmanToken)).all()
        for t in toks:
            try:
                resp = _fetch_with_token(invoices_url, t.access_token)
            except Exception as e:
                logger.exception("ResMan fetch failed for token id=%s", getattr(t, 'id', None))
                result['errors'].append(str(e))
                continue
            ct = resp.headers.get('content-type', '')
            try:
                # prefer content-type; fallback to URL extension
                if 'csv' in ct:
                    import io as _io
                    df = pd.read_csv(_io.StringIO(resp.text))
                    for _, row in df.iterrows():
                        vendor = row.get('vendor') or ''
                        try:
                            date = pd.to_datetime(row.get('date')).to_pydatetime()
                        except Exception:
                            date = datetime.utcnow()
                        total = float(row.get('total') or 0)
                        raw = str(row.to_dict())
                        prop = int(row.get('property_id')) if row.get('property_id') else 0
                        import_invoice(property_id=prop or 0, vendor=vendor, date=date, total=total, raw_text=raw)
                        result['pulled'] += 1
                elif 'json' in ct:
                    data = resp.json()
                    for rec in data:
                        vendor = rec.get('vendor') or ''
                        try:
                            date = pd.to_datetime(rec.get('date')).to_pydatetime()
                        except Exception:
                            date = datetime.utcnow()
                        total = float(rec.get('total') or 0)
                        raw = str(rec)
                        prop = rec.get('property_id') or 0
                        import_invoice(property_id=int(prop), vendor=vendor, date=date, total=total, raw_text=raw)
                        result['pulled'] += 1
                elif invoices_url.lower().endswith('.csv'):
                    import io as _io
                    df = pd.read_csv(_io.StringIO(resp.text))
                    for _, row in df.iterrows():
                        vendor = row.get('vendor') or ''
                        try:
                            date = pd.to_datetime(row.get('date')).to_pydatetime()
                        except Exception:
                            date = datetime.utcnow()
                        total = float(row.get('total') or 0)
                        raw = str(row.to_dict())
                        prop = int(row.get('property_id')) if row.get('property_id') else 0
                        import_invoice(property_id=prop or 0, vendor=vendor, date=date, total=total, raw_text=raw)
                        result['pulled'] += 1
                else:
                    data = resp.json()
                    for rec in data:
                        vendor = rec.get('vendor') or ''
                        try:
                            date = pd.to_datetime(rec.get('date')).to_pydatetime()
                        except Exception:
                            date = datetime.utcnow()
                        total = float(rec.get('total') or 0)
                        raw = str(rec)
                        prop = rec.get('property_id') or 0
                        import_invoice(property_id=int(prop), vendor=vendor, date=date, total=total, raw_text=raw)
                        result['pulled'] += 1
            except Exception as e:
                logger.exception("Error processing ResMan response for token id=%s", getattr(t, 'id', None))
                result['errors'].append(str(e))
    logger.info("ResMan pull completed: pulled=%s, errors=%s", result['pulled'], len(result['errors']))
    return result
