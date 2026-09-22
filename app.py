from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import DateTime, ForeignKey, Integer, String, create_engine, inspect, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = f"sqlite:///{BASE_DIR / 'atm.db'}"
logger = logging.getLogger("atm_banking")
load_dotenv(BASE_DIR / ".env")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    account_number: Mapped[str] = mapped_column(String(12), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(100))
    username: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    phone_number: Mapped[str | None] = mapped_column(String(20), nullable=True)
    pin_salt: Mapped[str] = mapped_column(String(32))
    pin_hash: Mapped[str] = mapped_column(String(128))
    balance_cents: Mapped[int] = mapped_column(Integer, default=0)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    transactions: Mapped[list["Transaction"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    amount_cents: Mapped[int] = mapped_column(Integer)
    balance_after_cents: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped[User] = relationship(back_populates="transactions")


Base.metadata.create_all(engine)


def ensure_schema() -> None:
    """Add columns needed by newer versions to an existing learning-project DB."""
    user_columns = {column["name"] for column in inspect(engine).get_columns("users")}
    if "phone_number" not in user_columns:
        with engine.begin() as connection:
            connection.exec_driver_sql("ALTER TABLE users ADD COLUMN phone_number VARCHAR(20)")


ensure_schema()

app = FastAPI(title="ATM Banking App")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("ATM_SECRET_KEY", "change-this-development-secret"),
    max_age=60 * 30,
    same_site="lax",
    https_only=False,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def money(cents: int) -> str:
    return f"Rs. {Decimal(cents) / Decimal(100):,.2f}"


templates.env.filters["money"] = money


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DB = Annotated[Session, Depends(get_db)]


def hash_pin(pin: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", pin.encode("utf-8"), salt.encode("utf-8"), 120_000
    ).hex()
    return salt, digest


def valid_pin(pin: str, user: User) -> bool:
    _, candidate = hash_pin(pin, user.pin_salt)
    return hmac.compare_digest(candidate, user.pin_hash)


def generate_account_number(db: Session) -> str:
    while True:
        account_number = "PK" + "".join(secrets.choice("0123456789") for _ in range(10))
        if db.scalar(select(User).where(User.account_number == account_number)) is None:
            return account_number


def parse_amount(raw_amount: str) -> int:
    try:
        amount = Decimal(raw_amount.strip().replace(",", ""))
        cents = int((amount * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    except (InvalidOperation, ValueError):
        raise ValueError("Enter a valid amount.")
    if cents <= 0:
        raise ValueError("Amount must be greater than zero.")
    if cents > 100_000_000_00:
        raise ValueError("Amount is too large.")
    return cents


def normalize_phone(raw_phone: str) -> str:
    phone = re.sub(r"[\s()\-]", "", raw_phone.strip())
    if phone.startswith("00"):
        phone = "+" + phone[2:]
    if not re.fullmatch(r"\+[1-9]\d{7,14}", phone):
        raise ValueError("Enter a valid phone number in international format, for example +923001234567.")
    return phone


def mask_phone(phone: str) -> str:
    return f"{phone[:4]}••••{phone[-3:]}"


def send_otp(phone: str, otp: str) -> bool:
    """Send an OTP through TextBee, or use visible/logged development mode."""
    textbee_api_key = os.getenv("TEXTBEE_API_KEY")
    if textbee_api_key:
        request_body = json.dumps({
            "recipients": [phone],
            "message": f"Your ATM Banking verification code is {otp}. It expires in 5 minutes.",
        }).encode("utf-8")
        request = urllib.request.Request(
            "https://api.textbee.dev/api/v1/gateway/send-sms",
            data=request_body,
            headers={
                "Content-Type": "application/json",
                "x-api-key": textbee_api_key,
                "User-Agent": "ATM-Banking/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError("TextBee returned an unsuccessful response.")
            return True
        except urllib.error.HTTPError as exc:
            response_body = exc.read().decode("utf-8", errors="replace")
            logger.error("TextBee HTTP %s response: %s", exc.code, response_body)
            if exc.code == 401:
                message = "TextBee rejected the API key. Generate a new API key in the TextBee dashboard."
            elif exc.code == 403:
                message = "TextBee denied SMS sending. Check your email verification, plan, and API key sending permissions."
            elif exc.code == 429:
                message = "TextBee message quota or rate limit reached."
            else:
                message = f"TextBee rejected the SMS request (HTTP {exc.code})."
            raise RuntimeError(message)
        except (urllib.error.URLError, TimeoutError, RuntimeError):
            logger.exception("Could not send OTP through TextBee")
            raise RuntimeError("The verification SMS could not be sent through TextBee.")

    logger.warning("Development OTP for %s: %s", phone, otp)
    return False


def current_user(request: Request, db: Session) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.get(User, user_id)


def page(request: Request, template_name: str, **context):
    context["request"] = request
    context["flash"] = request.session.pop("flash", None)
    return templates.TemplateResponse(template_name, context)


def redirect_with_flash(url: str, request: Request, message: str, kind: str = "error"):
    request.session["flash"] = {"message": message, "kind": kind}
    return RedirectResponse(url, status_code=303)


def require_user(request: Request, db: Session) -> User | RedirectResponse:
    user = current_user(request, db)
    if user is None:
        return redirect_with_flash("/login", request, "Please log in first.")
    return user


@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: DB):
    return RedirectResponse("/dashboard" if current_user(request, db) else "/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return page(request, "login.html")


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, db: DB, username: Annotated[str, Form()], pin: Annotated[str, Form()]):
    username = username.strip().lower()
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        return page(request, "login.html", error="Invalid username or PIN.", username=username)

    now = datetime.utcnow()
    if user.locked_until and user.locked_until > now:
        minutes = max(1, int((user.locked_until - now).total_seconds() / 60))
        return page(request, "login.html", error=f"Account locked. Try again in about {minutes} minute(s).", username=username, show_forgot=True)
    if user.locked_until:
        user.locked_until = None
        user.failed_attempts = 0

    if not re.fullmatch(r"\d{4}", pin) or not valid_pin(pin, user):
        user.failed_attempts += 1
        if user.failed_attempts >= 3:
            user.failed_attempts = 0
            user.locked_until = now + timedelta(minutes=5)
            db.commit()
            return page(request, "login.html", error="Too many failed attempts. Account locked for 5 minutes.", username=username, show_forgot=True)
        db.commit()
        remaining = 3 - user.failed_attempts
        return page(request, "login.html", error=f"Invalid username or PIN. {remaining} attempt(s) remaining.", username=username, show_forgot=True)

    user.failed_attempts = 0
    user.locked_until = None
    db.commit()
    request.session.clear()
    request.session["user_id"] = user.id
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return page(request, "register.html")


@app.get("/forgot-pin", response_class=HTMLResponse)
def forgot_pin_page(request: Request):
    return page(request, "forgot_pin.html")


@app.post("/forgot-pin", response_class=HTMLResponse)
def forgot_pin(
    request: Request,
    db: DB,
    username: Annotated[str, Form()],
    phone_number: Annotated[str, Form()],
):
    username = username.strip().lower()
    form_data = {"username": username, "phone_number": phone_number}
    try:
        phone_number = normalize_phone(phone_number)
    except ValueError as exc:
        return page(request, "forgot_pin.html", error=str(exc), **form_data)

    user = db.scalar(select(User).where(User.username == username))
    if user is None or user.phone_number != phone_number:
        return page(request, "forgot_pin.html", error="The username and phone number could not be verified.", **form_data)

    otp = f"{secrets.randbelow(1_000_000):06d}"
    request.session["pin_reset"] = {
        "user_id": user.id,
        "otp_hash": hashlib.sha256(otp.encode("utf-8")).hexdigest(),
        "expires_at": time.time() + 300,
        "attempts": 0,
        "phone": phone_number,
    }
    try:
        delivered = send_otp(phone_number, otp)
    except RuntimeError as exc:
        request.session.pop("pin_reset", None)
        return page(request, "forgot_pin.html", error=str(exc), **form_data)

    return page(
        request,
        "verify_otp.html",
        phone=mask_phone(phone_number),
        development_otp=None if delivered else otp,
    )


@app.post("/forgot-pin/verify", response_class=HTMLResponse)
def verify_otp(
    request: Request,
    db: DB,
    otp: Annotated[str, Form()],
    new_pin: Annotated[str, Form()],
    confirm_pin: Annotated[str, Form()],
):
    reset = request.session.get("pin_reset")
    if not reset:
        return redirect_with_flash("/forgot-pin", request, "Start the PIN recovery process first.")

    verify_context = {"phone": mask_phone(reset["phone"]), "development_otp": None}
    if time.time() > reset["expires_at"]:
        request.session.pop("pin_reset", None)
        return page(request, "forgot_pin.html", error="That OTP has expired. Request a new one.")
    if not re.fullmatch(r"\d{6}", otp):
        return page(request, "verify_otp.html", error="Enter the 6-digit OTP.", **verify_context)
    if not re.fullmatch(r"\d{4}", new_pin) or new_pin != confirm_pin:
        return page(request, "verify_otp.html", error="New PINs must match and contain exactly 4 digits.", **verify_context)

    candidate_hash = hashlib.sha256(otp.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(candidate_hash, reset["otp_hash"]):
        reset["attempts"] += 1
        if reset["attempts"] >= 5:
            request.session.pop("pin_reset", None)
            return page(request, "forgot_pin.html", error="Too many incorrect OTP attempts. Request a new OTP.")
        request.session["pin_reset"] = reset
        return page(request, "verify_otp.html", error="Incorrect OTP.", **verify_context)

    user = db.get(User, reset["user_id"])
    if user is None:
        request.session.pop("pin_reset", None)
        return page(request, "forgot_pin.html", error="The account could not be found.")
    user.pin_salt, user.pin_hash = hash_pin(new_pin)
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()
    request.session.pop("pin_reset", None)
    return redirect_with_flash("/login", request, "Your PIN was reset successfully. You can now sign in.", "success")


@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    db: DB,
    full_name: Annotated[str, Form()],
    username: Annotated[str, Form()],
    phone_number: Annotated[str, Form()],
    pin: Annotated[str, Form()],
    confirm_pin: Annotated[str, Form()],
):
    full_name = full_name.strip()
    username = username.strip().lower()
    if len(full_name) < 2:
        return page(request, "register.html", error="Enter your full name.", full_name=full_name, username=username)
    if not re.fullmatch(r"[a-z0-9_]{3,40}", username):
        return page(request, "register.html", error="Username must be 3-40 characters: letters, numbers, or underscore.", full_name=full_name, username=username)
    if db.scalar(select(User).where(User.username == username)):
        return page(request, "register.html", error="That username is already in use.", full_name=full_name, username=username)
    try:
        phone_number = normalize_phone(phone_number)
    except ValueError as exc:
        return page(request, "register.html", error=str(exc), full_name=full_name, username=username, phone_number=phone_number)
    if not re.fullmatch(r"\d{4}", pin) or pin != confirm_pin:
        return page(request, "register.html", error="PINs must match and contain exactly 4 digits.", full_name=full_name, username=username)

    salt, pin_hash = hash_pin(pin)
    user = User(
        account_number=generate_account_number(db),
        full_name=full_name,
        username=username,
        phone_number=phone_number,
        pin_salt=salt,
        pin_hash=pin_hash,
        balance_cents=0,
    )
    db.add(user)
    db.commit()
    return redirect_with_flash("/login", request, f"Account {user.account_number} created. You can now log in.", "success")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: DB):
    user_or_redirect = require_user(request, db)
    if isinstance(user_or_redirect, RedirectResponse):
        return user_or_redirect
    user = user_or_redirect
    transactions = db.scalars(
        select(Transaction).where(Transaction.user_id == user.id).order_by(Transaction.created_at.desc()).limit(8)
    ).all()
    return page(request, "dashboard.html", user=user, transactions=transactions)


@app.post("/deposit")
def deposit(request: Request, db: DB, amount: Annotated[str, Form()]):
    user_or_redirect = require_user(request, db)
    if isinstance(user_or_redirect, RedirectResponse):
        return user_or_redirect
    try:
        amount_cents = parse_amount(amount)
    except ValueError as exc:
        return redirect_with_flash("/dashboard", request, str(exc))

    user = user_or_redirect
    user.balance_cents += amount_cents
    db.add(Transaction(user_id=user.id, kind="Deposit", amount_cents=amount_cents, balance_after_cents=user.balance_cents, description="Cash deposit"))
    db.commit()
    return redirect_with_flash("/dashboard", request, f"{money(amount_cents)} deposited successfully.", "success")


@app.post("/withdraw")
def withdraw(request: Request, db: DB, amount: Annotated[str, Form()]):
    user_or_redirect = require_user(request, db)
    if isinstance(user_or_redirect, RedirectResponse):
        return user_or_redirect
    try:
        amount_cents = parse_amount(amount)
    except ValueError as exc:
        return redirect_with_flash("/dashboard", request, str(exc))

    user = user_or_redirect
    if amount_cents > user.balance_cents:
        return redirect_with_flash("/dashboard", request, "Insufficient balance.")
    user.balance_cents -= amount_cents
    db.add(Transaction(user_id=user.id, kind="Withdrawal", amount_cents=amount_cents, balance_after_cents=user.balance_cents, description="Cash withdrawal"))
    db.commit()
    return redirect_with_flash("/dashboard", request, f"{money(amount_cents)} withdrawn successfully.", "success")


@app.get("/transactions", response_class=HTMLResponse)
def transactions(request: Request, db: DB):
    user_or_redirect = require_user(request, db)
    if isinstance(user_or_redirect, RedirectResponse):
        return user_or_redirect
    user = user_or_redirect
    transaction_list = db.scalars(
        select(Transaction).where(Transaction.user_id == user.id).order_by(Transaction.created_at.desc()).limit(100)
    ).all()
    return page(request, "transactions.html", user=user, transactions=transaction_list)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


def seed_demo_users() -> None:
    with SessionLocal() as db:
        existing_users = db.scalars(select(User)).all()
        if existing_users:
            demo_phones = {"ibrahim": "+15555550101", "demo": "+15555550102"}
            changed = False
            for user in existing_users:
                if user.username in demo_phones and not user.phone_number:
                    user.phone_number = demo_phones[user.username]
                    changed = True
            if changed:
                db.commit()
            return
        for full_name, username, phone_number, pin, balance in [
            ("Ibrahim Khan", "ibrahim", "+15555550101", "1345", 100_000),
            ("Demo Customer", "demo", "+15555550102", "2468", 50_000),
        ]:
            salt, pin_hash = hash_pin(pin)
            db.add(User(
                account_number=generate_account_number(db),
                full_name=full_name,
                username=username,
                phone_number=phone_number,
                pin_salt=salt,
                pin_hash=pin_hash,
                balance_cents=balance,
            ))
        db.commit()


seed_demo_users()
