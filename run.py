import sys
import os

# Add backend directory to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app import create_app

app = create_app()

if __name__ == "__main__":
    print("🚀 Starting Domain Security Scanner on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
