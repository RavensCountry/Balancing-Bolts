from typing import Optional
from sqlmodel import SQLModel, Field, Relationship
from enum import Enum
from datetime import datetime

class Role(str, Enum):
    admin = "admin"
    manager = "manager"
    maintenance = "maintenance"
    leasing = "leasing"

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str
    role: Role = Field(default=Role.maintenance)
    hashed_password: Optional[str] = None
    current_property_id: Optional[int] = Field(default=None, foreign_key="property.id")

class Property(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    address: Optional[str] = None

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
    name: str
    description: Optional[str] = None
    quantity: int = 1
    cost: float = 0.0
    assigned_to_user_id: Optional[int] = Field(default=None, foreign_key="user.id")

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
