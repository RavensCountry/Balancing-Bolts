#!/usr/bin/env python3
"""
Script to create a test employee user with limited property access.
This demonstrates the multi-company property access system.
"""
import sys
sys.path.insert(0, '.')

from backend.crud import create_user, grant_property_access, list_properties
from backend.database import get_session
from backend.models import User
from sqlmodel import select

def create_employee():
    """Create a test employee with access to specific properties."""

    # Employee credentials
    email = "employee@balancingbolts.com"
    password = "employee123"
    name = "Test Employee"
    role = "maintenance"

    # Check if employee already exists
    with get_session() as session:
        existing = session.exec(select(User).where(User.email == email)).first()
        if existing:
            print(f"\n[OK] Employee user already exists!")
            print(f"  Email: {email}")
            print(f"  Password: {password}")
            print(f"  Role: {role}")
            employee_id = existing.id
        else:
            # Create the employee user
            user = create_user(
                name=name,
                email=email,
                role=role,
                password=password
            )
            employee_id = user.id
            print(f"\n[OK] Employee user created successfully!")
            print(f"  Email: {email}")
            print(f"  Password: {password}")
            print(f"  Role: {role}")

    # Get all properties
    properties = list_properties()

    if not properties:
        print("\n[WARNING] No properties found in the system.")
        print("  Please create some properties first using the admin account.")
        return

    print(f"\n[OK] Found {len(properties)} properties in the system")

    # Grant access to the first 2 properties (or fewer if less exist)
    num_to_grant = min(2, len(properties))

    for i in range(num_to_grant):
        prop = properties[i]
        # First property: view and edit access
        # Second property: view only access
        can_edit = (i == 0)

        grant_property_access(
            user_id=employee_id,
            property_id=prop.id,
            can_view=True,
            can_edit=can_edit,
            can_delete=False
        )

        permissions = "view, edit" if can_edit else "view only"
        print(f"  [OK] Granted access to '{prop.name}' ({permissions})")

    if len(properties) > num_to_grant:
        print(f"\n  Note: Employee does NOT have access to {len(properties) - num_to_grant} other properties")
        for i in range(num_to_grant, len(properties)):
            print(f"    - {properties[i].name} (no access)")

    print(f"\n{'='*60}")
    print("TEST CREDENTIALS")
    print(f"{'='*60}")
    print(f"Admin Account (full access to all properties):")
    print(f"  Email: admin@balancingbolts.com")
    print(f"  Password: admin123")
    print()
    print(f"Employee Account (limited property access):")
    print(f"  Email: {email}")
    print(f"  Password: {password}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    create_employee()
