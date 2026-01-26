from .database import get_session, init_db
from .models import User, Property, InventoryItem, Invoice, ActivityLog, Embedding, UserPropertyAccess, Organization
from passlib.context import CryptContext
from typing import List, Optional
from sqlmodel import select
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

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
        from sqlalchemy import inspect, text

        # Check if notes column exists
        try:
            inspector = inspect(s.get_bind())
            columns = [col['name'] for col in inspector.get_columns('property')]
            has_notes_column = 'notes' in columns
        except Exception:
            has_notes_column = True  # Assume it exists if we can't check

        if not has_notes_column:
            # If notes column doesn't exist, query without it
            query = text("SELECT id, name, address, organization_id FROM property" +
                        (" WHERE organization_id = :org_id" if organization_id else ""))
            if organization_id:
                result = s.execute(query, {"org_id": organization_id})
            else:
                result = s.execute(query)

            # Convert to Property objects manually
            properties = []
            for row in result:
                prop = Property(id=row[0], name=row[1], address=row[2], organization_id=row[3])
                properties.append(prop)
            return properties
        else:
            # Normal query with notes column
            if organization_id:
                return s.exec(select(Property).where(Property.organization_id == organization_id)).all()
            return s.exec(select(Property)).all()

def create_property(name: str, address: Optional[str] = None, notes: Optional[str] = None, organization_id: Optional[int] = None) -> Property:
    with get_session() as s:
        from sqlalchemy import inspect, text

        # Check if notes column exists
        inspector = inspect(s.get_bind())
        columns = [col['name'] for col in inspector.get_columns('property')]
        has_notes_column = 'notes' in columns

        # Create property with or without notes based on column existence
        if has_notes_column:
            p = Property(name=name, address=address, notes=notes, organization_id=organization_id)
            s.add(p)
            s.commit()
            s.refresh(p)
            return p
        else:
            logger.warning("Notes column does not exist yet, creating property without notes using raw SQL")
            # Use raw SQL to insert and return the property
            result = s.execute(
                text("INSERT INTO property (name, address, organization_id) VALUES (:name, :address, :org_id) RETURNING id, name, address, organization_id"),
                {"name": name, "address": address, "org_id": organization_id}
            )
            row = result.fetchone()
            s.commit()
            # Return a Property object
            return Property(id=row[0], name=row[1], address=row[2], organization_id=row[3])
def delete_property(property_id: int):
    """Delete a property by ID."""
    with get_session() as s:
        from sqlalchemy import inspect, text

        # Check if notes column exists
        try:
            inspector = inspect(s.get_bind())
            columns = [col['name'] for col in inspector.get_columns('property')]
            has_notes_column = 'notes' in columns
        except Exception:
            has_notes_column = True

        if not has_notes_column:
            # Use raw SQL to delete
            result = s.execute(text("DELETE FROM property WHERE id = :prop_id RETURNING id, name, address, organization_id"),
                             {"prop_id": property_id})
            row = result.fetchone()
            s.commit()
            if not row:
                raise ValueError(f"Property {property_id} not found")
            # Return a Property object
            return Property(id=row[0], name=row[1], address=row[2], organization_id=row[3])
        else:
            # Normal ORM delete
            p = s.exec(select(Property).where(Property.id == property_id)).first()
            if not p:
                raise ValueError(f"Property {property_id} not found")
            s.delete(p)
            s.commit()
            return p

def add_inventory(property_id: int, name: str, desc: Optional[str], qty: int, cost: float, assigned_to: Optional[int]=None, invoice_id: Optional[int]=None, product_id: Optional[str]=None, unit_number: Optional[str]=None) -> InventoryItem:
    with get_session() as s:
        from sqlalchemy import inspect, text

        # Check if unit_number column exists
        inspector = inspect(s.get_bind())
        columns = [col['name'] for col in inspector.get_columns('inventoryitem')]
        has_unit_number = 'unit_number' in columns

        if has_unit_number:
            # Normal ORM insert with unit_number
            item = InventoryItem(
                property_id=property_id,
                unit_number=unit_number,
                name=name,
                description=desc,
                quantity=qty,
                cost=cost,
                assigned_to_user_id=assigned_to,
                invoice_id=invoice_id,
                product_id=product_id
            )
            s.add(item)
            s.commit()
            s.refresh(item)
            return item
        else:
            # Use raw SQL without unit_number
            logger.warning("unit_number column does not exist yet, creating inventory without unit_number using raw SQL")
            result = s.execute(
                text("""INSERT INTO inventoryitem
                        (property_id, name, description, quantity, cost, assigned_to_user_id, invoice_id, product_id)
                        VALUES (:property_id, :name, :description, :quantity, :cost, :assigned_to, :invoice_id, :product_id)
                        RETURNING id, property_id, name, description, quantity, cost, assigned_to_user_id, invoice_id, product_id"""),
                {
                    "property_id": property_id,
                    "name": name,
                    "description": desc,
                    "quantity": qty,
                    "cost": cost,
                    "assigned_to": assigned_to,
                    "invoice_id": invoice_id,
                    "product_id": product_id
                }
            )
            row = result.fetchone()
            s.commit()
            return InventoryItem(
                id=row[0],
                property_id=row[1],
                name=row[2],
                description=row[3],
                quantity=row[4],
                cost=row[5],
                assigned_to_user_id=row[6],
                invoice_id=row[7],
                product_id=row[8]
            )


def list_inventory(page: int = 1, per_page: int = 20, property_id: Optional[int] = None, organization_id: Optional[int] = None):
    """Return (items, total_count) for inventory with optional property and organization filter."""
    with get_session() as s:
        from sqlalchemy import inspect, text

        # Check if unit_number column exists
        try:
            inspector = inspect(s.get_bind())
            columns = [col['name'] for col in inspector.get_columns('inventoryitem')]
            has_unit_number = 'unit_number' in columns
        except Exception:
            has_unit_number = True

        if not has_unit_number:
            # Use raw SQL without unit_number column
            query = "SELECT id, property_id, name, description, quantity, cost, assigned_to_user_id, invoice_id, product_id FROM inventoryitem"
            params = {}

            if property_id:
                query += " WHERE property_id = :property_id"
                params['property_id'] = property_id
            elif organization_id:
                query += " WHERE property_id IN (SELECT id FROM property WHERE organization_id = :org_id)"
                params['org_id'] = organization_id

            result = s.execute(text(query), params)
            all_items = []
            for row in result:
                item = InventoryItem(
                    id=row[0],
                    property_id=row[1],
                    name=row[2],
                    description=row[3],
                    quantity=row[4],
                    cost=row[5],
                    assigned_to_user_id=row[6],
                    invoice_id=row[7],
                    product_id=row[8]
                )
                all_items.append(item)
        else:
            # Normal ORM query with unit_number
            q = select(InventoryItem)
            if property_id:
                q = q.where(InventoryItem.property_id == property_id)
            elif organization_id:
                # Filter by properties that belong to the organization
                q = q.join(Property).where(Property.organization_id == organization_id)
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
