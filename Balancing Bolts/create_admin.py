#!/usr/bin/env python3
"""Create an admin user for Balancing Bolts"""

import sys
sys.path.insert(0, '.')

from backend.crud import create_user
from backend.database import get_session
from backend.models import User
from sqlmodel import select

def create_admin():
    email = "admin@balancingbolts.com"
    password = "admin123"

    # Check if admin already exists
    with get_session() as session:
        existing = session.exec(select(User).where(User.email == email)).first()
        if existing:
            print(f"Admin user already exists!")
            print(f"Email: {email}")
            print(f"Password: admin123")
            return

    # Create admin user
    user = create_user(
        name="Admin User",
        email=email,
        role="admin",
        password=password
    )

    print("Admin user created successfully!")
    print(f"Email: {email}")
    print(f"Password: {password}")
    print(f"\nYou can now login at http://127.0.0.1:8001")

if __name__ == "__main__":
    create_admin()
