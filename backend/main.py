from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Depends
import asyncio
import os
import logging
import sys

# Version: 2.1.0 - Force restart to apply super admin migration
import re
import requests
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from pydantic import BaseModel, Field, validator, constr
from typing import Optional
from .crud import create_property, list_properties, import_invoice, log_activity, add_inventory, create_user, grant_property_access, revoke_property_access, get_user_properties, get_property_users, user_can_access_property
from sqlmodel import select
from .database import get_session, engine
from .models import User, VendorCredential, QuoteRequest, Quote, QuoteStatus, Property, Invoice, Organization
from .database import init_db
from . import ai
from . import auth
from . import resman
from . import vendor_quotes
from . import auto_quote

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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Email notification function
def send_admin_notification_email(admin_email: str, admin_name: str, new_user_name: str, new_user_email: str, organization_name: str):
    """Send email notification to admin when new user joins their organization"""
    try:
        # Email configuration from environment variables
        smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        smtp_username = os.getenv('SMTP_USERNAME')
        smtp_password = os.getenv('SMTP_PASSWORD')
        from_email = os.getenv('SMTP_FROM_EMAIL', smtp_username)

        if not smtp_username or not smtp_password:
            logger.warning("SMTP credentials not configured, skipping email notification")
            return

        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'New User Joined {organization_name} - Balancing Bolts'
        msg['From'] = from_email
        msg['To'] = admin_email

        # HTML email body
        html = f"""
        <html>
          <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
              <h2 style="color: #2563eb; border-bottom: 2px solid #2563eb; padding-bottom: 10px;">
                🔔 New User Registration
              </h2>

              <p>Hello {admin_name},</p>

              <p>A new user has signed up to join <strong>{organization_name}</strong> on Balancing Bolts.</p>

              <div style="background: #f3f4f6; padding: 15px; border-radius: 6px; margin: 20px 0;">
                <h3 style="margin-top: 0; color: #1f2937;">User Details:</h3>
                <p style="margin: 5px 0;"><strong>Name:</strong> {new_user_name}</p>
                <p style="margin: 5px 0;"><strong>Email:</strong> {new_user_email}</p>
                <p style="margin: 5px 0;"><strong>Organization:</strong> {organization_name}</p>
              </div>

              <p>The user account has been created successfully and they can now log in to the system.</p>

              <p style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 14px;">
                This is an automated notification from Balancing Bolts.<br>
                <a href="https://balancing-bolts-production.up.railway.app" style="color: #2563eb;">Log in to manage users</a>
              </p>
            </div>
          </body>
        </html>
        """

        # Plain text version
        text = f"""
        New User Registration - Balancing Bolts

        Hello {admin_name},

        A new user has signed up to join {organization_name} on Balancing Bolts.

        User Details:
        - Name: {new_user_name}
        - Email: {new_user_email}
        - Organization: {organization_name}

        The user account has been created successfully and they can now log in to the system.

        Log in to manage users: https://balancing-bolts-production.up.railway.app
        """

        # Attach both HTML and plain text versions
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)

        # Send email
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)

        logger.info(f"Sent admin notification email to {admin_email}")
    except Exception as e:
        logger.error(f"Failed to send email to {admin_email}: {e}")
        raise

app = FastAPI()

# ============================================
# SECURITY CONFIGURATION
# ============================================

# Rate Limiting Setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# CORS Configuration - Strict (only allow your Railway domain)
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://balancing-bolts-production.up.railway.app,http://localhost:8000,http://127.0.0.1:8000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=3600,
)

# Request Size Limit Middleware
MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB limit

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in ["POST", "PUT", "PATCH"]:
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > MAX_REQUEST_SIZE:
                return Response(
                    content="Request too large. Maximum size is 10MB.",
                    status_code=413
                )
        return await call_next(request)

app.add_middleware(RequestSizeLimitMiddleware)

# Input Validation Models
class SafeString(BaseModel):
    """Validates and sanitizes string input"""
    value: constr(max_length=500, strip_whitespace=True)

    @validator('value')
    def sanitize_input(cls, v):
        # Remove potential XSS characters
        if v:
            v = re.sub(r'[<>]', '', v)
        return v

def sanitize_input(text: str, max_length: int = 500) -> str:
    """Sanitize user input to prevent XSS and injection attacks"""
    if not text:
        return text
    # Truncate to max length
    text = text[:max_length]
    # Remove script tags and dangerous characters
    text = re.sub(r'<script.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)
    return text.strip()

# ============================================
# END SECURITY CONFIGURATION
# ============================================

init_db()

# Run database migrations automatically on startup
try:
    from sqlalchemy import text
    logger.info("Checking for required database migrations...")

    migrations = [
        "ALTER TABLE quoterequest ADD COLUMN IF NOT EXISTS invoice_id INTEGER;",
        "ALTER TABLE quoterequest ADD COLUMN IF NOT EXISTS is_auto_generated BOOLEAN DEFAULT FALSE;",
        # Add invoice tracking to inventory items (early, before organization stuff)
        'ALTER TABLE inventoryitem ADD COLUMN IF NOT EXISTS invoice_id INTEGER REFERENCES invoice(id);',
        'ALTER TABLE inventoryitem ADD COLUMN IF NOT EXISTS product_id VARCHAR(255);',
        # Organization multi-tenancy migrations
        """CREATE TABLE IF NOT EXISTS organization (
            id SERIAL PRIMARY KEY,
            name VARCHAR NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );""",
        # Create default organization FIRST before adding foreign keys
        "INSERT INTO organization (name, created_at) SELECT 'Default Organization', CURRENT_TIMESTAMP WHERE NOT EXISTS (SELECT 1 FROM organization WHERE id = 1);",
        # Add Balancing Bolts organization
        "INSERT INTO organization (name, created_at) SELECT 'Balancing Bolts', CURRENT_TIMESTAMP WHERE NOT EXISTS (SELECT 1 FROM organization WHERE name = 'Balancing Bolts');",
        # Now add the foreign key columns
        'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organization(id);',
        "ALTER TABLE property ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organization(id);",
        # Super admin column
        'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS is_super_admin BOOLEAN DEFAULT FALSE;',
        # Assign existing users/properties to default organization (now organization exists)
        'UPDATE "user" SET organization_id = 1 WHERE organization_id IS NULL;',
        "UPDATE property SET organization_id = 1 WHERE organization_id IS NULL;",
        # Set super admin - ONLY for balancingbolts@gmail.com (platform owner) - ALWAYS RUN THIS
        'UPDATE "user" SET is_super_admin = FALSE;',  # First, remove super admin from everyone
        'UPDATE "user" SET is_super_admin = TRUE, role = \'admin\' WHERE LOWER(email) = \'balancingbolts@gmail.com\';',  # Grant super admin and admin role to platform owner
        # Add notes column to property table
        "ALTER TABLE property ADD COLUMN IF NOT EXISTS notes TEXT;",
        # Add unit_number column to inventoryitem table
        "ALTER TABLE inventoryitem ADD COLUMN IF NOT EXISTS unit_number VARCHAR(50);",
        # Create property_unit table for storing units
        """CREATE TABLE IF NOT EXISTS property_unit (
            id SERIAL PRIMARY KEY,
            property_id INTEGER REFERENCES property(id) ON DELETE CASCADE,
            unit_number VARCHAR(50) NOT NULL,
            unit_type VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(property_id, unit_number)
        );""",
    ]

    with engine.connect() as conn:
        for sql in migrations:
            logger.info(f"Running migration: {sql}")
            conn.execute(text(sql))
            conn.commit()

    logger.info("✓ Database migrations completed successfully")
except Exception as e:
    logger.error(f"Migration error (non-fatal): {e}")
    # Don't fail startup if migration fails

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

    # Create demo admin account if it doesn't exist
    try:
        with get_session() as s:
            demo_email = "demo@balancingbolts.com"
            existing_demo = s.exec(select(User).where(User.email == demo_email)).first()
            if not existing_demo:
                logger.info("Creating demo admin account...")
                create_user(
                    name="Demo Admin",
                    email=demo_email,
                    role="admin",
                    password="demo123"
                )
                logger.info("Demo admin account created: demo@balancingbolts.com / demo123")
    except Exception:
        logger.exception('Error creating demo admin account')


@app.on_event("shutdown")
async def _shutdown_resman_poller():
    global resman_task
    if resman_task:
        resman_task.cancel()
        try:
            await resman_task
        except asyncio.CancelledError:
            pass

@app.get('/api/migrate')
def run_migration(current_user=Depends(auth.require_role('admin'))):
    """Run database migrations to add missing columns (admin only)"""
    try:
        from sqlalchemy import text

        migrations = [
            "ALTER TABLE quoterequest ADD COLUMN IF NOT EXISTS invoice_id INTEGER;",
            "ALTER TABLE quoterequest ADD COLUMN IF NOT EXISTS is_auto_generated BOOLEAN DEFAULT FALSE;",
        ]

        with engine.connect() as conn:
            for sql in migrations:
                logger.info(f"Running migration: {sql}")
                conn.execute(text(sql))
                conn.commit()

        return {
            "status": "success",
            "message": "Database migration completed successfully",
            "migrations_run": len(migrations)
        }
    except Exception as e:
        import traceback
        logger.exception("Migration failed")
        return {
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        }

@app.get('/api/health')
def health_check():
    """Health check endpoint to verify database and tables"""
    try:
        # Try to query the database
        with get_session() as s:
            # Try to count quote requests
            quote_requests_count = len(s.exec(select(QuoteRequest)).all())
            quotes_count = len(s.exec(select(Quote)).all())

            return {
                "status": "healthy",
                "database": "connected",
                "quote_requests": quote_requests_count,
                "quotes": quotes_count,
                "tables_working": True
            }
    except Exception as e:
        import traceback
        return {
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        }

@app.get('/api/properties')
def get_properties(current_user=Depends(auth.get_current_user)):
    """Get properties for current user's organization, or all if super admin"""
    if current_user.is_super_admin:
        return [p.dict() for p in list_properties()]  # No org filter for super admin
    return [p.dict() for p in list_properties(organization_id=current_user.organization_id)]

@app.post('/api/properties')
def post_property(name: str = Form(...), address: str = Form(None), user=Depends(auth.require_role('admin'))):
    """Create a property (admin-only) in current user's organization"""
    p = create_property(name=name, address=address, organization_id=user.organization_id)
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


class UpdatePropertyNotesRequest(BaseModel):
    notes: Optional[str] = None


@app.put('/api/properties/{property_id}/notes')
def update_property_notes(property_id: int, request: UpdatePropertyNotesRequest, user=Depends(auth.get_current_user)):
    """Update notes for a property"""
    with get_session() as session:
        prop = session.exec(select(Property).where(Property.id == property_id)).first()
        if not prop:
            raise HTTPException(status_code=404, detail="Property not found")

        # Check access (admin or if user has access to this property)
        if user.role != 'admin' and not user_can_access_property(user.id, property_id):
            raise HTTPException(status_code=403, detail="Not authorized to update this property")

        prop.notes = request.notes
        session.add(prop)
        session.commit()
        session.refresh(prop)
        return {'status': 'ok', 'notes': prop.notes}


@app.post('/api/properties/parse-units')
async def parse_units_file(file: UploadFile = File(...), user=Depends(auth.require_role('admin'))):
    """Parse a unit report (PDF, Excel, or CSV) and extract unit information"""
    try:
        logger.info(f"Parsing units file: {file.filename}")
        # Read file content
        content = await file.read()

        units = []
        property_name = None

        # Check file type
        if file.filename.endswith(('.xlsx', '.xls', '.csv')):
            # Parse Excel or CSV file
            if file.filename.endswith('.csv'):
                df = pd.read_csv(io.BytesIO(content))
                logger.info(f"Parsed CSV with {len(df)} rows")
            else:
                df = pd.read_excel(io.BytesIO(content))
                logger.info(f"Parsed Excel with {len(df)} rows")

            logger.info(f"Initial columns: {df.columns.tolist()}")

            # Try to find property name in header rows
            for i in range(min(5, len(df))):
                row_values = df.iloc[i].astype(str).tolist()
                for val in row_values:
                    if val and len(val) > 3 and not val.replace('.', '').isdigit():
                        # Potential property name
                        if not property_name and 'Unit' not in val and 'Type' not in val:
                            property_name = val.strip()
                            break

            # Find the header row (look for 'Unit' column)
            header_row = None
            for i in range(min(10, len(df))):
                row_values = df.iloc[i].astype(str).tolist()
                if any('unit' in str(v).lower() for v in row_values):
                    header_row = i
                    break

            # If no header row found, assume first row is header
            if header_row is None:
                header_row = 0
                logger.info("No header row found, using first row")

            # Set the header
            df.columns = df.iloc[header_row]
            df = df.iloc[header_row + 1:]
            logger.info(f"Using row {header_row} as header. Columns: {df.columns.tolist()}")

            # Find unit and unit type columns with more flexible matching
            unit_col = None
            type_col = None

            for col in df.columns:
                col_lower = str(col).lower().strip()
                # Match unit column
                if any(term in col_lower for term in ['unit', 'unit #', 'unit number', 'unit_number', 'apt', 'apartment']):
                    if not any(term in col_lower for term in ['type', 'status', 'tenant', 'name', 'balance']):
                        unit_col = col
                        logger.info(f"Found unit column: {col}")
                # Match unit type column
                if any(term in col_lower for term in ['type', 'bedroom', 'bed', 'br', 'unit type', 'unit_type']):
                    type_col = col
                    logger.info(f"Found unit type column: {col}")

            # Extract units
            if unit_col:
                logger.info(f"Extracting units from column '{unit_col}'")
                for idx, row in df.iterrows():
                    unit_num = str(row[unit_col]).strip()
                    unit_type = str(row[type_col]).strip() if type_col and pd.notna(row[type_col]) else 'Unknown'

                    # Skip if not a valid unit number
                    if unit_num and unit_num != 'nan' and unit_num != 'None' and unit_num != '':
                        units.append({
                            'unit_number': unit_num,
                            'unit_type': unit_type
                        })
                logger.info(f"Extracted {len(units)} units")
            else:
                logger.warning("Could not find unit column in file")
                logger.warning(f"Available columns: {df.columns.tolist()}")

        elif file.filename.endswith('.pdf'):
            # Parse PDF file
            import PyPDF2
            logger.info("Parsing PDF file")
            pdf_reader = PyPDF2.PdfReader(io.BytesIO(content))

            # Extract text from first page
            first_page_text = pdf_reader.pages[0].extract_text()
            lines = first_page_text.split('\n')

            # Try to find property name in first few lines
            for line in lines[:10]:
                line = line.strip()
                if line and len(line) > 3 and not line.replace('.', '').isdigit():
                    if 'Unit' not in line and 'Type' not in line and 'Status' not in line:
                        property_name = line
                        break

            # Extract all text
            all_text = ''
            for page in pdf_reader.pages:
                all_text += page.extract_text()

            # Find unit entries using regex
            # Pattern: unit number followed by unit type (e.g., "112 2-2")
            import re
            unit_pattern = r'(\d{2,4})\s+(\d-\d)'
            matches = re.findall(unit_pattern, all_text)

            for unit_num, unit_type in matches:
                units.append({
                    'unit_number': unit_num,
                    'unit_type': unit_type
                })
            logger.info(f"Extracted {len(units)} units from PDF")

        else:
            raise HTTPException(status_code=400, detail="File must be PDF, Excel (.xlsx, .xls), or CSV (.csv)")

        logger.info(f"Successfully parsed file. Property: {property_name}, Units: {len(units)}")
        return {
            'units': units,
            'property_name': property_name,
            'total_units': len(units)
        }

    except Exception as e:
        import traceback
        logger.error(f"Error parsing units file: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=400, detail=f"Error parsing file: {str(e)}")


class CreatePropertyWithUnitsRequest(BaseModel):
    name: str
    address: Optional[str] = None
    notes: Optional[str] = None
    units: list = []


@app.post('/api/properties/create-with-units')
def create_property_with_units(request: CreatePropertyWithUnitsRequest, user=Depends(auth.require_role('admin'))):
    """Create a property with units"""
    try:
        logger.info(f"Creating property '{request.name}' with {len(request.units)} units")

        # Create the property
        property_obj = create_property(
            name=request.name,
            address=request.address,
            notes=request.notes,
            organization_id=user.organization_id
        )
        logger.info(f"Property created with ID {property_obj.id}")

        # Store units
        units_created = 0
        if request.units:
            with get_session() as session:
                from sqlmodel import text

                # Insert units (table should exist from migrations)
                for unit in request.units:
                    try:
                        logger.debug(f"Inserting unit {unit['unit_number']} for property {property_obj.id}")
                        result = session.exec(text("""
                            INSERT INTO property_unit (property_id, unit_number, unit_type)
                            VALUES (:property_id, :unit_number, :unit_type)
                            ON CONFLICT (property_id, unit_number) DO NOTHING
                            RETURNING id
                        """), {
                            'property_id': property_obj.id,
                            'unit_number': unit['unit_number'],
                            'unit_type': unit.get('unit_type', 'Unknown')
                        })
                        if result.fetchone():
                            units_created += 1
                    except Exception as e:
                        logger.error(f"Failed to create unit {unit['unit_number']}: {e}")

                session.commit()
                logger.info(f"Successfully created {units_created} units for property {property_obj.id}")

        return {
            'property': {
                'id': property_obj.id,
                'name': property_obj.name,
                'address': property_obj.address
            },
            'units_created': units_created,
            'total_units_requested': len(request.units)
        }

    except Exception as e:
        import traceback
        logger.error(f"Error creating property with units: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=400, detail=str(e))


@app.get('/api/properties/{property_id}/units')
def get_property_units(property_id: int, user=Depends(auth.get_current_user)):
    """Get all units for a property"""
    with get_session() as session:
        from sqlmodel import text

        # Check if property_unit table exists
        try:
            result = session.execute(
                text("SELECT unit_number, unit_type FROM property_unit WHERE property_id = :prop_id ORDER BY unit_number"),
                {"prop_id": property_id}
            )
            units = [{"unit_number": row[0], "unit_type": row[1]} for row in result]
            return {"units": units, "total": len(units)}
        except Exception as e:
            # Table might not exist yet
            logger.warning(f"Error fetching units: {e}")
            return {"units": [], "total": 0}


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

        # Automatically generate quote requests from invoice and fetch quotes
        try:
            auto_quotes = await auto_quote.generate_quotes_from_invoice(
                invoice_id=inv.id,
                user_id=current_user.id,
                property_id=int(property_id),
                auto_fetch=True  # Automatically fetch quotes from vendors
            )
            logger.info(f"Auto-generated {len(auto_quotes)} quote requests for invoice {inv.id}")
        except Exception as e:
            logger.exception(f"Error auto-generating quotes for invoice {inv.id}: {e}")

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
async def api_add_inventory(
    property_id: int = Form(None),
    unit_number: str = Form(None),
    name: str = Form(...),
    description: str = Form(None),
    quantity: int = Form(1),
    cost: float = Form(0.0),
    assigned_to: int = Form(None),
    invoice_id: int = Form(None),
    product_id: str = Form(None),
    user=Depends(auth.get_current_user)
):
    item = add_inventory(
        property_id=int(property_id) if property_id else None,
        unit_number=unit_number,
        name=name,
        desc=description,
        qty=int(quantity),
        cost=float(cost),
        assigned_to=assigned_to,
        invoice_id=invoice_id,
        product_id=product_id
    )
    return item


@app.get('/api/inventory')
def api_list_inventory(page: int = 1, per_page: int = 20, property_id: int = None, user=Depends(auth.get_current_user)):
    from .crud import list_inventory
    org_id = None if user.is_super_admin else user.organization_id  # Super admin sees all
    items, total = list_inventory(page=int(page), per_page=int(per_page), property_id=property_id, organization_id=org_id)
    return {"items": [i.dict() for i in items], "total": total, "page": int(page), "per_page": int(per_page)}


# Auth endpoints
@app.post('/api/auth/signup')
@limiter.limit("3/hour")  # Max 3 signups per hour per IP
async def signup(
    request: Request,
    first_name: str = Form(None),
    last_name: str = Form(None),
    name: str = Form(None),
    email: str = Form(...),
    password: str = Form(...),
    organization_id: int = Form(None),
    role: str = Form('maintenance'),
    company_name: str = Form(None)
):
    """
    Create a new user account. Sends notification emails to organization admins.
    """
    # Build full name from first_name/last_name if provided, otherwise use name
    if first_name and last_name:
        full_name = f"{first_name.strip()} {last_name.strip()}"
    elif name:
        full_name = name.strip()
    else:
        # Extract name from email as fallback
        full_name = email.split('@')[0]

    # Sanitize inputs
    full_name = sanitize_input(full_name, max_length=100)
    email = sanitize_input(email, max_length=100).lower()
    if company_name:
        company_name = sanitize_input(company_name, max_length=200)

    # Validate email format
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    # Validate password strength
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")

    with get_session() as s:
        # Check if user already exists
        existing = s.exec(select(User).where(User.email == email)).first()
        if existing:
            raise HTTPException(status_code=400, detail="User with this email already exists")

        org_id = None
        org_name = None

        # If organization_id provided (from new signup form)
        if organization_id:
            org = s.exec(select(Organization).where(Organization.id == organization_id)).first()
            if not org:
                raise HTTPException(status_code=400, detail="Invalid organization")
            org_id = org.id
            org_name = org.name
        # If company name provided, create new organization (legacy flow)
        elif company_name:
            org = Organization(name=company_name)
            s.add(org)
            s.commit()
            s.refresh(org)
            org_id = org.id
            org_name = org.name
            role = 'admin'  # First user becomes admin
            logger.info(f"Created new organization: {company_name}")
        else:
            # Assign to default organization
            default_org = s.exec(select(Organization).where(Organization.id == 1)).first()
            if not default_org:
                default_org = Organization(name="Default Organization")
                s.add(default_org)
                s.commit()
                s.refresh(default_org)
            org_id = default_org.id
            org_name = default_org.name

    # Create user
    u = create_user(name=full_name, email=email, role=role, password=password, organization_id=org_id)

    # Send notification emails to all admins in the organization
    try:
        with get_session() as s:
            admins = s.exec(
                select(User).where(
                    User.organization_id == org_id,
                    User.role == 'admin'
                )
            ).all()

            for admin in admins:
                try:
                    send_admin_notification_email(
                        admin_email=admin.email,
                        admin_name=admin.name,
                        new_user_name=full_name,
                        new_user_email=email,
                        organization_name=org_name
                    )
                except Exception as e:
                    logger.error(f"Failed to send notification email to {admin.email}: {e}")

            logger.info(f"New user signup: {full_name} ({email}) joined {org_name}. Notified {len(admins)} admins.")
    except Exception as e:
        logger.error(f"Error sending admin notifications: {e}")

    token = auth.create_access_token({"sub": u.email})
    return {"access_token": token, "token_type": "bearer", "user": u}


@app.post('/api/auth/login')
@limiter.limit("5/minute")  # Max 5 login attempts per minute per IP
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
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
    return {
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'role': user.role,
        'current_property_id': user.current_property_id,
        'organization_id': user.organization_id,
        'is_super_admin': user.is_super_admin
    }


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
    """List all users in current user's organization (admin only), or all if super admin"""
    with get_session() as s:
        if current_user.is_super_admin:
            users = s.exec(select(User)).all()  # No org filter for super admin
        else:
            users = s.exec(select(User).where(User.organization_id == current_user.organization_id)).all()

        # Include organization info for each user
        result = []
        for u in users:
            user_data = {"id": u.id, "name": u.name, "email": u.email, "role": u.role, "organization_id": u.organization_id}

            # Fetch organization name if organization_id exists
            if u.organization_id:
                org = s.exec(select(Organization).where(Organization.id == u.organization_id)).first()
                if org:
                    user_data["organization_name"] = org.name
                else:
                    user_data["organization_name"] = "Unknown Organization"
            else:
                user_data["organization_name"] = "No Organization"

            result.append(user_data)

        return result


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

        # SECURITY: Prevent modification of super admin accounts
        if user.is_super_admin:
            raise HTTPException(status_code=403, detail="Cannot modify super admin accounts")

        # SECURITY: Only allow admins to modify users in their own organization
        if not current_user.is_super_admin and user.organization_id != current_user.organization_id:
            raise HTTPException(status_code=403, detail="Cannot modify users from other organizations")

        user.role = role
        s.add(user)
        s.commit()
        s.refresh(user)

        return {"status": "success", "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role}}


@app.get('/api/organizations/public')
def list_organizations_public():
    """List all organizations (public endpoint for signup)"""
    with get_session() as s:
        orgs = s.exec(select(Organization)).all()
        return [{"id": org.id, "name": org.name} for org in orgs]


@app.get('/api/organizations')
def list_organizations(current_user=Depends(auth.get_current_user)):
    """List all organizations (super admin only)"""
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Only super admins can list all organizations")

    with get_session() as s:
        orgs = s.exec(select(Organization)).all()
        return [{"id": org.id, "name": org.name} for org in orgs]


@app.post('/api/organizations')
def create_organization(
    name: str = Form(...),
    current_user=Depends(auth.get_current_user)
):
    """Create a new organization (super admin only)"""
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Only super admins can create organizations")

    with get_session() as s:
        # Check if organization already exists
        existing = s.exec(select(Organization).where(Organization.name == name)).first()
        if existing:
            raise HTTPException(status_code=400, detail="Organization with this name already exists")

        org = Organization(name=name)
        s.add(org)
        s.commit()
        s.refresh(org)

        return {"status": "success", "organization": {"id": org.id, "name": org.name}}


@app.post('/api/users/{user_id}/organization')
def update_user_organization(
    user_id: int,
    organization_id: str = Form(...),
    current_user=Depends(auth.get_current_user)
):
    """Update a user's organization (super admin only)"""
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Only super admins can change user organizations")

    with get_session() as s:
        user = s.exec(select(User).where(User.id == user_id)).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # SECURITY: Prevent modification of super admin accounts
        if user.is_super_admin:
            raise HTTPException(status_code=403, detail="Cannot modify super admin accounts")

        # Handle empty string or None to clear organization
        if organization_id == '' or organization_id == 'None':
            user.organization_id = None
        else:
            org_id = int(organization_id)
            # Verify organization exists
            org = s.exec(select(Organization).where(Organization.id == org_id)).first()
            if not org:
                raise HTTPException(status_code=404, detail="Organization not found")
            user.organization_id = org_id

        s.add(user)
        s.commit()
        s.refresh(user)

        return {"status": "success", "user": {"id": user.id, "name": user.name, "organization_id": user.organization_id}}


@app.delete('/api/users/{user_id}')
def delete_user(
    user_id: int,
    current_user=Depends(auth.require_role('admin'))
):
    """Delete a user and all their data (admin only)"""
    with get_session() as s:
        user = s.exec(select(User).where(User.id == user_id)).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # SECURITY: Prevent deleting super admin accounts
        if user.is_super_admin:
            raise HTTPException(status_code=403, detail="Cannot delete super admin accounts")

        # Prevent deleting yourself
        if user.id == current_user.id:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")

        # SECURITY: Only allow admins to delete users in their own organization
        if not current_user.is_super_admin and user.organization_id != current_user.organization_id:
            raise HTTPException(status_code=403, detail="Cannot delete users from other organizations")

        # Delete user (cascade will handle related records)
        s.delete(user)
        s.commit()

        return {"status": "success", "message": f"User {user.name} deleted successfully"}


@app.post('/api/users/{user_id}/super-admin')
def grant_super_admin(
    user_id: int,
    grant: bool = Form(...),
    current_user=Depends(auth.get_current_user)
):
    """Grant or revoke super admin status (super admin only)"""
    # SECURITY: Only super admin can modify super admin status
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Only super admin can grant/revoke super admin status")

    with get_session() as s:
        user = s.exec(select(User).where(User.id == user_id)).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Prevent removing your own super admin status
        if user.id == current_user.id and not grant:
            raise HTTPException(status_code=400, detail="Cannot revoke your own super admin status")

        user.is_super_admin = grant
        s.add(user)
        s.commit()
        s.refresh(user)

        action = "granted to" if grant else "revoked from"
        return {
            "status": "success",
            "message": f"Super admin {action} {user.name}",
            "user": {"id": user.id, "name": user.name, "email": user.email, "is_super_admin": user.is_super_admin}
        }


@app.get('/api/check-balancingbolts-status')
def check_balancingbolts_status():
    """Check current status of balancingbolts account"""
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            result = conn.execute(text(
                "SELECT id, name, email, role, is_super_admin, organization_id FROM \"user\" WHERE email ILIKE '%balancingbolts%'"
            ))
            users = [dict(row._mapping) for row in result]
            return {"status": "success", "users": users}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get('/api/fix-balancingbolts-admin')
@app.post('/api/fix-balancingbolts-admin')
def fix_balancingbolts_admin():
    """Emergency endpoint to set balancingbolts@gmail.com as admin - no auth required"""
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            # First check what exists
            check = conn.execute(text(
                "SELECT id, email, role, is_super_admin FROM \"user\" WHERE LOWER(email) = 'balancingbolts@gmail.com'"
            ))
            before = [dict(row._mapping) for row in check]

            # Update
            result = conn.execute(text(
                "UPDATE \"user\" SET role = 'admin', is_super_admin = TRUE WHERE LOWER(email) = 'balancingbolts@gmail.com'"
            ))
            conn.commit()

            # Check after
            check = conn.execute(text(
                "SELECT id, email, role, is_super_admin FROM \"user\" WHERE LOWER(email) = 'balancingbolts@gmail.com'"
            ))
            after = [dict(row._mapping) for row in check]

            return {
                "status": "success",
                "message": "balancingbolts@gmail.com set to admin with super admin status",
                "rows_affected": result.rowcount,
                "before": before,
                "after": after
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ===== VENDOR QUOTE MANAGEMENT =====

@app.post('/api/vendors/credentials')
async def add_vendor_credential(
    vendor_name: str = Form(...),
    vendor_url: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    property_id: int = Form(None),
    current_user=Depends(auth.require_role('manager'))
):
    """Add vendor login credentials (manager/admin only)"""
    encrypted_password = vendor_quotes.encrypt_password(password)

    with get_session() as s:
        # Check if property exists if provided
        if property_id:
            prop = s.exec(select(Property).where(Property.id == property_id)).first()
            if not prop:
                raise HTTPException(status_code=404, detail="Property not found")

        credential = VendorCredential(
            vendor_name=vendor_name,
            vendor_url=vendor_url,
            username=username,
            encrypted_password=encrypted_password,
            user_id=current_user.id,
            property_id=property_id
        )
        s.add(credential)
        s.commit()
        s.refresh(credential)

        return {
            "status": "success",
            "credential": {
                "id": credential.id,
                "vendor_name": credential.vendor_name,
                "vendor_url": credential.vendor_url,
                "username": credential.username,
                "property_id": credential.property_id,
                "created_at": credential.created_at.isoformat()
            }
        }


@app.get('/api/vendors/credentials')
def list_vendor_credentials(current_user=Depends(auth.get_current_user)):
    """List all vendor credentials for the current user"""
    with get_session() as s:
        # Admins and managers see all credentials
        if current_user.role in ['admin', 'manager']:
            credentials = s.exec(select(VendorCredential)).all()
        else:
            # Other users only see credentials they added
            credentials = s.exec(
                select(VendorCredential).where(VendorCredential.user_id == current_user.id)
            ).all()

        return [{
            "id": c.id,
            "vendor_name": c.vendor_name,
            "vendor_url": c.vendor_url,
            "username": c.username,
            "property_id": c.property_id,
            "is_active": c.is_active,
            "last_used": c.last_used.isoformat() if c.last_used else None,
            "created_at": c.created_at.isoformat()
        } for c in credentials]


@app.delete('/api/vendors/credentials/{credential_id}')
def delete_vendor_credential(
    credential_id: int,
    current_user=Depends(auth.require_role('manager'))
):
    """Delete a vendor credential (manager/admin only)"""
    with get_session() as s:
        credential = s.exec(
            select(VendorCredential).where(VendorCredential.id == credential_id)
        ).first()

        if not credential:
            raise HTTPException(status_code=404, detail="Credential not found")

        # Only the creator or admin can delete
        if credential.user_id != current_user.id and current_user.role != 'admin':
            raise HTTPException(status_code=403, detail="Not authorized to delete this credential")

        s.delete(credential)
        s.commit()

        return {"status": "success"}


@app.post('/api/quotes/request')
async def create_quote_request(
    item_description: str = Form(...),
    quantity: int = Form(1),
    property_id: int = Form(None),
    notes: str = Form(None),
    auto_fetch: bool = Form(True),  # Default to auto-fetch
    current_user=Depends(auth.get_current_user)
):
    """Create a new quote request and optionally auto-fetch quotes"""
    with get_session() as s:
        # Validate property if provided
        if property_id:
            prop = s.exec(select(Property).where(Property.id == property_id)).first()
            if not prop:
                raise HTTPException(status_code=404, detail="Property not found")

        quote_request = QuoteRequest(
            property_id=property_id,
            user_id=current_user.id,
            item_description=item_description,
            quantity=quantity,
            notes=notes
        )
        s.add(quote_request)
        s.commit()
        s.refresh(quote_request)

        request_id = quote_request.id

    # Auto-fetch quotes if enabled
    if auto_fetch:
        try:
            await fetch_quotes(request_id, current_user)
            logger.info(f"Auto-fetched quotes for request {request_id}")
        except Exception as e:
            logger.exception(f"Error auto-fetching quotes for request {request_id}: {e}")

    with get_session() as s:
        quote_request = s.exec(
            select(QuoteRequest).where(QuoteRequest.id == request_id)
        ).first()

        # Get quote count
        quotes = s.exec(
            select(Quote).where(Quote.quote_request_id == request_id)
        ).all()

        return {
            "status": "success",
            "quote_request": {
                "id": quote_request.id,
                "item_description": quote_request.item_description,
                "quantity": quote_request.quantity,
                "property_id": quote_request.property_id,
                "status": quote_request.status,
                "created_at": quote_request.created_at.isoformat(),
                "quote_count": len(quotes)
            }
        }


@app.post('/api/quotes/request/{request_id}/fetch')
async def fetch_quotes(
    request_id: int,
    current_user=Depends(auth.get_current_user)
):
    """Fetch quotes from all configured vendors for a quote request"""
    with get_session() as s:
        # Get the quote request
        quote_request = s.exec(
            select(QuoteRequest).where(QuoteRequest.id == request_id)
        ).first()

        if not quote_request:
            raise HTTPException(status_code=404, detail="Quote request not found")

        # Update status to fetching
        quote_request.status = QuoteStatus.fetching
        s.add(quote_request)
        s.commit()

        # Get all active vendor credentials
        credentials = s.exec(
            select(VendorCredential).where(VendorCredential.is_active == True)
        ).all()

        # If no credentials configured, use demo mode with fake credentials
        if not credentials:
            logger.info("No vendor credentials found, using demo mode")
            # Create demo credentials (passwords don't matter in demo mode, so use plain text)
            creds_data = [
                {'vendor_name': 'Home Depot', 'username': 'demo', 'encrypted_password': 'DEMO_MODE'},
                {'vendor_name': 'Lowes', 'username': 'demo', 'encrypted_password': 'DEMO_MODE'},
                {'vendor_name': 'Grainger', 'username': 'demo', 'encrypted_password': 'DEMO_MODE'}
            ]
        else:
            # Prepare credential data for fetching
            creds_data = [{
                'vendor_name': c.vendor_name,
                'username': c.username,
                'encrypted_password': c.encrypted_password
            } for c in credentials]

        try:
            logger.info(f"Fetching quotes for '{quote_request.item_description}' from {len(creds_data)} vendors")

            # Fetch quotes from vendors
            quotes_data = await vendor_quotes.fetch_quotes_from_vendors(
                quote_request.item_description,
                quote_request.quantity,
                creds_data
            )

            logger.info(f"Received {len(quotes_data)} quotes from vendors")

            # Save quotes to database
            for quote_data in quotes_data:
                quote = Quote(
                    quote_request_id=request_id,
                    vendor_name=quote_data.get('vendor_name', 'Unknown'),
                    item_name=quote_data.get('item_name', quote_request.item_description),
                    item_description=quote_data.get('item_description'),
                    unit_price=quote_data.get('unit_price', 0.0),
                    quantity=quote_request.quantity,
                    total_price=quote_data.get('total_price', 0.0),
                    vendor_item_number=quote_data.get('vendor_item_number'),
                    availability=quote_data.get('availability'),
                    vendor_url=quote_data.get('vendor_url'),
                    raw_data=quote_data.get('raw_data')
                )
                s.add(quote)

            # Update request status
            quote_request.status = QuoteStatus.completed
            s.add(quote_request)
            s.commit()

            # Return the quotes
            quotes = s.exec(
                select(Quote).where(Quote.quote_request_id == request_id)
            ).all()

            return {
                "status": "success",
                "quote_count": len(quotes),
                "quotes": [{
                    "id": q.id,
                    "vendor_name": q.vendor_name,
                    "item_name": q.item_name,
                    "unit_price": q.unit_price,
                    "quantity": q.quantity,
                    "total_price": q.total_price,
                    "availability": q.availability,
                    "vendor_url": q.vendor_url
                } for q in quotes]
            }

        except Exception as e:
            quote_request.status = QuoteStatus.failed
            s.add(quote_request)
            s.commit()
            logger.exception(f"Error fetching quotes: {e}")
            raise HTTPException(status_code=500, detail=f"Error fetching quotes: {str(e)}")


@app.get('/api/quotes/request/{request_id}')
def get_quote_request(request_id: int, current_user=Depends(auth.get_current_user)):
    """Get a quote request with all its quotes"""
    with get_session() as s:
        quote_request = s.exec(
            select(QuoteRequest).where(QuoteRequest.id == request_id)
        ).first()

        if not quote_request:
            raise HTTPException(status_code=404, detail="Quote request not found")

        quotes = s.exec(
            select(Quote).where(Quote.quote_request_id == request_id)
        ).all()

        # Get property and user info
        property_name = None
        if quote_request.property_id:
            prop = s.exec(select(Property).where(Property.id == quote_request.property_id)).first()
            if prop:
                property_name = prop.name

        user = s.exec(select(User).where(User.id == quote_request.user_id)).first()
        user_name = user.name if user else "Unknown"

        return {
            "id": quote_request.id,
            "item_description": quote_request.item_description,
            "quantity": quote_request.quantity,
            "property_id": quote_request.property_id,
            "property_name": property_name,
            "user_name": user_name,
            "status": quote_request.status,
            "created_at": quote_request.created_at.isoformat(),
            "notes": quote_request.notes,
            "quotes": [{
                "id": q.id,
                "vendor_name": q.vendor_name,
                "item_name": q.item_name,
                "item_description": q.item_description,
                "unit_price": q.unit_price,
                "quantity": q.quantity,
                "total_price": q.total_price,
                "vendor_item_number": q.vendor_item_number,
                "availability": q.availability,
                "vendor_url": q.vendor_url,
                "fetched_at": q.fetched_at.isoformat()
            } for q in quotes]
        }


@app.get('/api/quotes/requests')
def list_quote_requests(current_user=Depends(auth.get_current_user)):
    """List all quote requests for current user's organization, or all if super admin"""
    try:
        with get_session() as s:
            # Super admin sees everything across all organizations
            if current_user.is_super_admin:
                requests = s.exec(select(QuoteRequest)).all()
            # Admin and managers see all requests in their organization
            elif current_user.role in ['admin', 'manager']:
                # Filter by users in the same organization
                requests = s.exec(
                    select(QuoteRequest)
                    .join(User, QuoteRequest.user_id == User.id)
                    .where(User.organization_id == current_user.organization_id)
                ).all()
            else:
                # Others only see their own
                requests = s.exec(
                    select(QuoteRequest).where(QuoteRequest.user_id == current_user.id)
                ).all()

            logger.info(f"Found {len(requests)} quote requests for user {current_user.id} ({current_user.role})")

            result = []
            for req in requests:
                # Count quotes for this request
                quote_count = s.exec(
                    select(Quote).where(Quote.quote_request_id == req.id)
                ).all()

                result.append({
                    "id": req.id,
                    "item_description": req.item_description,
                    "quantity": req.quantity,
                    "property_id": req.property_id,
                    "status": req.status,
                    "quote_count": len(quote_count),
                    "created_at": req.created_at.isoformat() if req.created_at else None
                })
                logger.info(f"  - Quote request {req.id}: {req.item_description}")

            return result
    except Exception as e:
        logger.exception(f"Error listing quote requests: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/api/quotes/request/{request_id}/email')
def generate_quote_email(request_id: int, current_user=Depends(auth.get_current_user)):
    """Generate email-ready HTML for a quote comparison"""
    with get_session() as s:
        quote_request = s.exec(
            select(QuoteRequest).where(QuoteRequest.id == request_id)
        ).first()

        if not quote_request:
            raise HTTPException(status_code=404, detail="Quote request not found")

        quotes = s.exec(
            select(Quote).where(Quote.quote_request_id == request_id)
        ).all()

        if not quotes:
            raise HTTPException(status_code=400, detail="No quotes available for this request")

        # Get property and user info
        property_name = "N/A"
        if quote_request.property_id:
            prop = s.exec(select(Property).where(Property.id == quote_request.property_id)).first()
            if prop:
                property_name = prop.name

        user = s.exec(select(User).where(User.id == quote_request.user_id)).first()
        user_name = user.name if user else "Unknown"

        # Prepare data for email generation
        request_data = {
            'item_description': quote_request.item_description,
            'quantity': quote_request.quantity,
            'property_name': property_name,
            'user_name': user_name
        }

        quotes_data = [{
            'vendor_name': q.vendor_name,
            'item_name': q.item_name,
            'item_description': q.item_description,
            'unit_price': q.unit_price,
            'quantity': q.quantity,
            'total_price': q.total_price,
            'vendor_item_number': q.vendor_item_number,
            'availability': q.availability,
            'vendor_url': q.vendor_url
        } for q in quotes]

        # Generate email HTML
        email_html = vendor_quotes.generate_email_html(request_data, quotes_data)

        return {"html": email_html}


@app.delete('/api/quotes/request/{request_id}')
def delete_quote_request(request_id: int, current_user=Depends(auth.get_current_user)):
    """Delete an entire quote request and all associated quotes"""
    with get_session() as s:
        # Get the quote request
        quote_request = s.exec(
            select(QuoteRequest).where(QuoteRequest.id == request_id)
        ).first()

        if not quote_request:
            raise HTTPException(status_code=404, detail="Quote request not found")

        # Check permissions - admins/managers can delete any request, others only their own
        if current_user.role not in ['admin', 'manager']:
            if quote_request.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="Not authorized to delete this quote request")

        # Delete all associated quotes first
        quotes = s.exec(
            select(Quote).where(Quote.quote_request_id == request_id)
        ).all()

        for quote in quotes:
            s.delete(quote)

        # Delete the quote request
        item_desc = quote_request.item_description
        s.delete(quote_request)
        s.commit()

        logger.info(f"User {current_user.id} deleted quote request {request_id} ({item_desc})")

        return {
            "status": "success",
            "message": f"Quote request '{item_desc}' deleted successfully"
        }


@app.delete('/api/quotes/{quote_id}')
def delete_quote(quote_id: int, current_user=Depends(auth.get_current_user)):
    """Delete an individual vendor quote"""
    with get_session() as s:
        # Get the quote
        quote = s.exec(
            select(Quote).where(Quote.id == quote_id)
        ).first()

        if not quote:
            raise HTTPException(status_code=404, detail="Quote not found")

        # Get the associated quote request to check permissions
        quote_request = s.exec(
            select(QuoteRequest).where(QuoteRequest.id == quote.quote_request_id)
        ).first()

        # Check permissions - admins/managers can delete any quote, others only their own
        if current_user.role not in ['admin', 'manager']:
            if not quote_request or quote_request.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="Not authorized to delete this quote")

        # Delete the quote
        s.delete(quote)
        s.commit()

        logger.info(f"User {current_user.id} deleted quote {quote_id} ({quote.vendor_name})")

        return {
            "status": "success",
            "message": f"Quote from {quote.vendor_name} deleted successfully"
        }


@app.get('/api/invoices/{invoice_id}/quotes')
def get_invoice_quotes(invoice_id: int, current_user=Depends(auth.get_current_user)):
    """Get all quote requests automatically generated from an invoice"""
    try:
        quotes_data = auto_quote.get_invoice_quotes(invoice_id)
        return {
            "invoice_id": invoice_id,
            "quote_requests": quotes_data
        }
    except Exception as e:
        logger.exception(f"Error getting invoice quotes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/api/invoices/{invoice_id}/quotes/generate')
async def generate_invoice_quotes(
    invoice_id: int,
    auto_fetch: bool = False,
    current_user=Depends(auth.get_current_user)
):
    """Manually trigger quote generation for an invoice"""
    with get_session() as s:
        invoice = s.exec(select(Invoice).where(Invoice.id == invoice_id)).first()
        if not invoice:
            raise HTTPException(status_code=404, detail="Invoice not found")

        try:
            created_quotes = await auto_quote.generate_quotes_from_invoice(
                invoice_id=invoice_id,
                user_id=current_user.id,
                property_id=invoice.property_id,
                auto_fetch=auto_fetch
            )

            return {
                "status": "success",
                "generated_quotes": len(created_quotes),
                "quote_requests": [{
                    "id": qr.id,
                    "item_description": qr.item_description,
                    "quantity": qr.quantity,
                    "status": qr.status
                } for qr in created_quotes]
            }
        except Exception as e:
            logger.exception(f"Error generating quotes for invoice {invoice_id}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to generate quotes: {str(e)}")
