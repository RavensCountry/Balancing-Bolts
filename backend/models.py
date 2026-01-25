from typing import Optional
from sqlmodel import SQLModel, Field, Relationship
from enum import Enum
from datetime import datetime

class Role(str, Enum):
    admin = "admin"
    manager = "manager"
    maintenance = "maintenance"
    leasing = "leasing"

class Organization(SQLModel, table=True):
    """Represents a company/organization for multi-tenancy"""
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str
    role: Role = Field(default=Role.maintenance)
    hashed_password: Optional[str] = None
    current_property_id: Optional[int] = Field(default=None, foreign_key="property.id")
    organization_id: Optional[int] = Field(default=None, foreign_key="organization.id")
    is_super_admin: bool = Field(default=False)  # Platform owner, sees all organizations

class Property(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    address: Optional[str] = None
    notes: Optional[str] = None
    organization_id: Optional[int] = Field(default=None, foreign_key="organization.id")

class UserPropertyAccess(SQLModel, table=True):
    """Junction table for many-to-many relationship between users and properties"""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    property_id: int = Field(foreign_key="property.id")
    can_view: bool = Field(default=True)
    can_edit: bool = Field(default=False)
    can_delete: bool = Field(default=False)

class InventoryItem(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    property_id: Optional[int] = Field(default=None, foreign_key="property.id")
    unit_number: Optional[str] = None  # Unit number within the property
    name: str
    description: Optional[str] = None
    quantity: int = 1
    cost: float = 0.0
    assigned_to_user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    invoice_id: Optional[int] = Field(default=None, foreign_key="invoice.id")  # Link to invoice
    product_id: Optional[str] = None  # Product/SKU number from invoice/vendor

class Invoice(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    property_id: Optional[int] = Field(default=None, foreign_key="property.id")
    vendor: Optional[str] = None
    date: Optional[datetime] = None
    total: float = 0.0
    raw_text: Optional[str] = None

class ActivityLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    action: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    details: Optional[str] = None

class Embedding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    source_type: str  # 'invoice'|'item' etc
    source_id: int
    vector: Optional[str] = None  # JSON string of embedding vector
    text: Optional[str] = None

class ResmanToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    tenant: Optional[str] = None

class VendorCredential(SQLModel, table=True):
    """Stores encrypted vendor website login credentials for automated quote pulling"""
    id: Optional[int] = Field(default=None, primary_key=True)
    vendor_name: str  # e.g., "Home Depot", "Lowe's", "Grainger"
    vendor_url: str
    username: str
    encrypted_password: str  # Encrypted for security
    user_id: int = Field(foreign_key="user.id")  # Who added this credential
    property_id: Optional[int] = Field(default=None, foreign_key="property.id")  # Optional property association
    is_active: bool = Field(default=True)
    last_used: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class QuoteStatus(str, Enum):
    pending = "pending"
    fetching = "fetching"
    completed = "completed"
    failed = "failed"
    emailed = "emailed"

class QuoteRequest(SQLModel, table=True):
    """Tracks quote requests across multiple vendors"""
    id: Optional[int] = Field(default=None, primary_key=True)
    property_id: Optional[int] = Field(default=None, foreign_key="property.id")
    user_id: int = Field(foreign_key="user.id")  # Who requested the quote
    item_description: str  # What they're requesting a quote for
    quantity: int = Field(default=1)
    status: QuoteStatus = Field(default=QuoteStatus.pending)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    notes: Optional[str] = None
    invoice_id: Optional[int] = Field(default=None, foreign_key="invoice.id")  # Link to invoice if auto-generated
    is_auto_generated: bool = Field(default=False)  # Flag for auto-generated quotes

class Quote(SQLModel, table=True):
    """Individual quotes from vendors"""
    id: Optional[int] = Field(default=None, primary_key=True)
    quote_request_id: int = Field(foreign_key="quoterequest.id")
    vendor_name: str
    item_name: str
    item_description: Optional[str] = None
    unit_price: float
    quantity: int
    total_price: float
    vendor_item_number: Optional[str] = None
    availability: Optional[str] = None  # "In Stock", "2-3 days", etc.
    vendor_url: Optional[str] = None  # Link to product page
    fetched_at: datetime = Field(default_factory=datetime.utcnow)
    raw_data: Optional[str] = None  # JSON string of raw vendor response
