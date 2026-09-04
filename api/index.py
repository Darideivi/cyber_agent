# pyright: reportMissingImports=false

# Vercel's Python runtime looks for a WSGI `app` object under api/.
# The real Flask app lives in gui/app.py, which already adds the repo
# root to sys.path so its sibling module imports keep working here.
from gui.app import app
