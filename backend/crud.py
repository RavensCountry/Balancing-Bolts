from .database import get_session, init_db
from .models import User, Property, InventoryItem, Invoice, ActivityLog, Embedding, UserPropertyAccess, Organization
from passlib.context import CryptContext
from typing import List, Optional
from sqlmodel import select
from datetime import datetime

init_db()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# fallback hasher for environments without bcrypt available
fallback_ctx = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def create_user(name: str, email: str, role: str, property_id: Optional[int] = None, password: Optional[str] = None, organization_id: Optional[int] = None) -> User:
    with get_session() as s:
        hashed = None
        if password:
            # prefer a portable pbkdf2_sha256 hash so verification works
            try:
                hashed = fallback_ctx.hash(password)
            except Exception:
                try:
                    hashed = pwd_context.hash(password)
                except Exception:
                    import hashlib
                    hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()
        u = User(name=name, email=email, role=role, current_property_id=property_id, hashed_password=hashed, organization_id=organization_id)
        s.add(u)
        s.commit()
        s.refresh(u)
        return u

def list_properties(organization_id: Optional[int] = None) -> List[Property]:
    with get_session() as s:
        if organization_id:
            return s.exec(select(Property).where(Property.organization_id == organization_id)).all()
        return s.exec(select(Property)).all()

def create_property(name: str, address: Optional[str] = None, organization_id: Optional[int] = None) -> Property:
    with get_session() as s:
        p = Property(name=name, address=address, organization_id=organization_id)
        s.add(p)
        s.commit()
        s.refresh(p)
        return p
def delete_property(property_id: int):
    """Delete a property by ID."""
    with get_session() as s:
        p = s.exec(select(Property).where(Property.id == property_id)).first()
        if not p:
            raise ValueError(f"Property {property_id} not found")
        s.delete(p)
        s.commit()
        return p

def add_inventory(property_id: int, name: str, desc: Optional[str], qty: int, cost: float, assigned_to: Optional[int]=None) -> InventoryItem:
    with get_session() as s:
        item = InventoryItem(property_id=property_id, name=name, description=desc, quantity=qty, cost=cost, assigned_to_user_id=assigned_to)
        s.add(item)
        s.commit()
        s.refresh(item)
        return item


def list_inventory(page: int = 1, per_page: int = 20, property_id: Optional[int] = None):
    """Return (items, total_count) for inventory with optional property filter."""
    with get_session() as s:
        q = select(InventoryItem)
        if property_id:
            q = q.where(InventoryItem.property_id == property_id)
        all_items = s.exec(q).all()
        total = len(all_items)
        # simple in-memory pagination
        start = max(0, (page - 1) * per_page)
        end = start + per_page
        page_items = all_items[start:end]
        return page_items, total

def import_invoice(property_id: int, vendor: str, date: datetime, total: float, raw_text: str) -> Invoice:
    with get_session() as s:
        inv = Invoice(property_id=property_id, vendor=vendor, date=date, total=total, raw_text=raw_text)
        s.add(inv)
        s.commit()
        s.refresh(inv)
        return inv

def log_activity(user_id: Optional[int], action: str, details: Optional[str]=None) -> ActivityLog:
    with get_session() as s:
        a = ActivityLog(user_id=user_id, action=action, details=details)
        s.add(a)
        s.commit()
        s.refresh(a)
        return a

def monthly_spend(property_id: Optional[int], year: int, month: int) -> float:
    from datetime import datetime, timedelta
    with get_session() as s:
        q = select(Invoice)
        if property_id:
            q = q.where(Invoice.property_id == property_id)
        q = q.where(Invoice.date >= datetime(year, month, 1))
        # naive end of month
        next_month = month % 12 + 1
        end_year = year + (1 if next_month == 1 else 0)
        q = q.where(Invoice.date < datetime(end_year, next_month, 1))
        invs = s.exec(q).all()
        return sum(i.total for i in invs)

def yearly_spend(property_id: Optional[int], year: int) -> float:
    from datetime import datetime
    with get_session() as s:
        q = select(Invoice)
        if property_id:
            q = q.where(Invoice.property_id == property_id)
        q = q.where(Invoice.date >= datetime(year, 1, 1))
        q = q.where(Invoice.date < datetime(year+1, 1, 1))
        invs = s.exec(q).all()
        return sum(i.total for i in invs)

def grant_property_access(user_id: int, property_id: int, can_view: bool = True, can_edit: bool = False, can_delete: bool = False) -> UserPropertyAccess:
    """Grant a user access to a property with specific permissions."""
    with get_session() as s:
        # Check if access already exists
        existing = s.exec(
            select(UserPropertyAccess)
            .where(UserPropertyAccess.user_id == user_id)
            .where(UserPropertyAccess.property_id == property_id)
        ).first()

        if existing:
            # Update existing access
            existing.can_view = can_view
            existing.can_edit = can_edit
            existing.can_delete = can_delete
            s.add(existing)
            s.commit()
            s.refresh(existing)
            return existing

        # Create new access
        access = UserPropertyAccess(
            user_id=user_id,
            property_id=property_id,
            can_view=can_view,
            can_edit=can_edit,
            can_delete=can_delete
        )
        s.add(access)
        s.commit()
        s.refresh(access)
        return access

def revoke_property_access(user_id: int, property_id: int):
    """Revoke a user's access to a property."""
    with get_session() as s:
        access = s.exec(
            select(UserPropertyAccess)
            .where(UserPropertyAccess.user_id == user_id)
            .where(UserPropertyAccess.property_id == property_id)
        ).first()

        if access:
            s.delete(access)
            s.commit()

def get_user_properties(user_id: int) -> List[dict]:
    """Get all properties a user has access to with their permissions."""
    with get_session() as s:
        accesses = s.exec(
            select(UserPropertyAccess)
            .where(UserPropertyAccess.user_id == user_id)
        ).all()

        result = []
        for access in accesses:
            prop = s.exec(select(Property).where(Property.id == access.property_id)).first()
            if prop:
                result.append({
                    "id": prop.id,
                    "name": prop.name,
                    "address": prop.address,
                    "can_view": access.can_view,
                    "can_edit": access.can_edit,
                    "can_delete": access.can_delete
                })
        return result

def get_property_users(property_id: int) -> List[dict]:
    """Get all users with access to a property."""
    with get_session() as s:
        accesses = s.exec(
            select(UserPropertyAccess)
            .where(UserPropertyAccess.property_id == property_id)
        ).all()

        result = []
        for access in accesses:
            user = s.exec(select(User).where(User.id == access.user_id)).first()
            if user:
                result.append({
                    "id": user.id,
                    "name": user.name,
                    "email": user.email,
                    "role": user.role,
                    "can_view": access.can_view,
                    "can_edit": access.can_edit,
                    "can_delete": access.can_delete
                })
        return result

def user_can_access_property(user_id: int, property_id: int, permission: str = "view") -> bool:
    """Check if a user has specific permission to access a property."""
    with get_session() as s:
        # Admins can access everything
        user = s.exec(select(User).where(User.id == user_id)).first()
        if user and user.role == "admin":
            return True

        # Check specific access
        access = s.exec(
            select(UserPropertyAccess)
            .where(UserPropertyAccess.user_id == user_id)
            .where(UserPropertyAccess.property_id == property_id)
        ).first()

        if not access:
            return False

        if permission == "view":
            return access.can_view
        elif permission == "edit":
            return access.can_edit
        elif permission == "delete":
            return access.can_delete

        return False
