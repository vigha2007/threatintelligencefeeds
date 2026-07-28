import os
import sys

# Import app from the ML/api package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ML")))
from api.app import app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)