import pytest


@pytest.fixture(autouse=True)
def reset_test_state():
    """
    Reset rate limiter and clean test user data before each test
    to ensure a consistent starting state.
    """
    # Reset rate limiter storage
    from backend.main import limiter
    storage = getattr(limiter, '_storage', None)
    if storage is not None:
        if hasattr(storage, 'storage'):
            storage.storage.clear()
        if hasattr(storage, 'expirations'):
            storage.expirations.clear()
        if hasattr(storage, 'events'):
            storage.events.clear()

    # Clean up user/property/inventory/activity data from previous test runs
    from sqlalchemy import text
    from backend.database import engine
    from backend.models import SQLModel
    SQLModel.metadata.create_all(engine)

    with engine.connect() as conn:
        conn.execute(text('DELETE FROM activitylog'))
        conn.execute(text('DELETE FROM quote'))
        conn.execute(text('DELETE FROM quoterequest'))
        conn.execute(text('DELETE FROM userpropertyaccess'))
        conn.execute(text('DELETE FROM inventoryitem'))
        conn.execute(text('DELETE FROM invoice'))
        conn.execute(text('DELETE FROM property'))
        conn.execute(
            text("DELETE FROM \"user\" WHERE email NOT IN ('balancingbolts@gmail.com', 'demo@balancingbolts.com')")
        )
        conn.commit()

    yield
