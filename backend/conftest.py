import sys
import os

# When pytest runs from the backend/ directory, the project root is not in sys.path.
# Add the project root so that 'from backend.main import app' resolves correctly.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
