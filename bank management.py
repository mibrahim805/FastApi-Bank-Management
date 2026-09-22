"""Convenience launcher for the FastAPI ATM application.

Run this file directly with:

    python3 "bank management.py"

The application itself lives in app.py.
"""

import uvicorn


if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)


