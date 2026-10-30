#!/usr/bin/env python3
"""FlipTrack — multi-user reseller dashboard.

One dashboard for small resellers: what do I owe, what's due, and what
did I actually make? Each seller gets their own account; every record
is scoped to that account, so sellers can never see each other's data.

Stack: Python standard library only. No pip installs, no build step.
Run:  python3 app.py        (listens on $PORT, default 8000)
Data: SQLite file at $FLIPTRACK_DB (default ./fliptrack.db).

Billing: Pro is $15/month via Square. Until SQUARE_ACCESS_TOKEN,
SQUARE_LOCATION_ID, and SQUARE_PLAN_VARIATION_ID are set, checkout
reports billing_not_configured and every account stays on the free
plan. Square posts subscription events to /api/square-webhook, which
flips accounts to Pro (or back to free on cancel). See README.md.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.environ.get(
    "FLIPTRACK_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "fliptrack.db")
)
PORT = int(os.environ.get("PORT", "8000"))
FREE_FLIP_LIMIT = 10
SESSION_DAYS = 30

FLIP_STATUSES = ["won", "paid", "in_transit", "in_hand", "listed", "sold", "shipped", "completed"]
DEADLINE_KINDS = ["ship_by", "reply_by", "pay_by", "return_by", "case", "follow_up", "other"]
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------- database

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            plan TEXT NOT NULL DEFAULT 'free',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS flips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            source TEXT DEFAULT '',
            lot_number TEXT DEFAULT '',
            buy_price_cents INTEGER NOT NULL DEFAULT 0,
            buy_fees_cents INTEGER NOT NULL DEFAULT 0,
            inbound_shipping_cents INTEGER NOT NULL DEFAULT 0,
            sale_price_cents INTEGER NOT NULL DEFAULT 0,
            sale_fees_cents INTEGER NOT NULL DEFAULT 0,
            outbound_shipping_cents INTEGER NOT NULL DEFAULT 0,
            purchase_date TEXT DEFAULT '',
            sale_date TEXT DEFAULT '',
            sale_platform TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'won',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            vendor TEXT DEFAULT '',
            amount_cents INTEGER NOT NULL DEFAULT 0,
            due_date TEXT DEFAULT '',
            invoice_number TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'unpaid',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS deadlines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            platform TEXT DEFAULT '',
            kind TEXT NOT NULL DEFAULT 'other',
            due_date TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            created_at TEXT NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- auth

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()


def new_session(conn, user_id):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat()
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
        (token_hash, user_id, expires),
    )
    conn.commit()
    return token, expires


def user_from_request(handler):
    cookie = handler.headers.get("Cookie", "")
    token = None
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("session="):
            token = part[len("session="):]
            break
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = db()
    row = conn.execute(
        """SELECT u.id, u.email, u.plan FROM sessions s
           JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ? AND s.expires_at > ?""",
        (token_hash, datetime.now(timezone.utc).isoformat()),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def set_session_cookie(handler, token, expires):
    handler.send_header(
        "Set-Cookie",
        f"session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_DAYS * 86400}",
    )


def clear_session_cookie(handler):
    handler.send_header("Set-Cookie", "session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")


# ---------------------------------------------------------------- helpers

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def today_str():
    return date.today().isoformat()


def to_cents(value):
    """Accept dollars as number or string, return integer cents. Raises ValueError."""
    if value is None or value == "":
        return 0
    cents = round(float(value) * 100)
    if cents < 0 or cents > 9007199254740991:
        raise ValueError("amount out of range")
    return cents


def flip_net(f):
    return (
        f["sale_price_cents"]
        - f["buy_price_cents"]
        - f["buy_fees_cents"]
        - f["inbound_shipping_cents"]
        - f["sale_fees_cents"]
        - f["outbound_shipping_cents"]
    )


def row_to_flip(r):
    d = dict(r)
    d["net_cents"] = flip_net(d)
    return d


def require_fields(body, fields):
    missing = [f for f in fields if not str(body.get(f, "")).strip()]
    if missing:
        raise ValueError("missing required field(s): " + ", ".join(missing))


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def owned_row(conn, table, row_id, user_id):
    row = conn.execute(
        f"SELECT * FROM {table} WHERE id = ? AND user_id = ?", (row_id, user_id)
    ).fetchone()
    if row is None:
        raise ApiError(404, "not found")
    return row

# ---------------------------------------------------------------- API logic

def api_signup(body):
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    if not EMAIL_RE.match(email):
        raise ApiError(400, "enter a valid email address")
    if len(password) < 8:
        raise ApiError(400, "password must be at least 8 characters")
    conn = db()
    try:
        if conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            raise ApiError(409, "an account with that email already exists")
        salt = secrets.token_hex(16)
        conn.execute(
            "INSERT INTO users (email, password_hash, salt, plan, created_at) VALUES (?, ?, ?, 'free', ?)",
            (email, hash_password(password, salt), salt, now_iso()),
        )
        conn.commit()
        user_id = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()["id"]
        token, _ = new_session(conn, user_id)
    finally:
        conn.close()
    return {"token": token, "user": {"id": user_id, "email": email, "plan": "free"}}


def api_login(body):
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    conn = db()
    try:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if row is None or not hmac.compare_digest(
            row["password_hash"], hash_password(password, row["salt"])
        ):
            raise ApiError(401, "email or password is incorrect")
        token, _ = new_session(conn, row["id"])
        user = {"id": row["id"], "email": row["email"], "plan": row["plan"]}
    finally:
        conn.close()
    return {"token": token, "user": user}


def api_logout(handler):
    cookie = handler.headers.get("Cookie", "")
    token = None
    for part in cookie.split(";"):
        if part.strip().startswith("session="):
            token = part.strip()[len("session="):]
    if token:
        conn = db()
        conn.execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        )
        conn.commit()
        conn.close()
    return {"ok": True}


def api_dashboard(user):
    conn = db()
    flips = [row_to_flip(r) for r in conn.execute(
        "SELECT * FROM flips WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)
    )]
    invoices = [dict(r) for r in conn.execute(
        "SELECT * FROM invoices WHERE user_id = ? ORDER BY due_date", (user["id"],)
    )]
    deadlines = [dict(r) for r in conn.execute(
        "SELECT * FROM deadlines WHERE user_id = ? ORDER BY due_date", (user["id"],)
    )]
    conn.close()
    today = today_str()
    week = (date.today() + timedelta(days=7)).isoformat()
    owed = sum(i["amount_cents"] for i in invoices if i["status"] == "unpaid")
    open_dl = [d for d in deadlines if d["status"] == "open"]
    overdue = [d for d in open_dl if d["due_date"] and d["due_date"] < today]
    due7 = [d for d in open_dl if d["due_date"] and today <= d["due_date"] <= week]
    sold = [f for f in flips if f["sale_price_cents"] > 0]
    stats = {
        "total_owed_cents": owed,
        "overdue_count": len(overdue),
        "due_next7_count": len(due7),
        "net_profit_cents": sum(f["net_cents"] for f in sold),
        "total_cost_cents": sum(f["buy_price_cents"] + f["buy_fees_cents"] + f["inbound_shipping_cents"] for f in flips),
        "total_sales_cents": sum(f["sale_price_cents"] for f in flips),
        "active_flips": len([f for f in flips if f["status"] != "completed"]),
    }
    return {"user": user, "stats": stats, "flips": flips, "invoices": invoices,
            "deadlines": deadlines, "overdue": overdue, "due_next7": due7}


def api_create_flip(user, body):
    require_fields(body, ["title"])
    status = body.get("status", "won")
    if status not in FLIP_STATUSES:
        raise ApiError(400, "invalid status")
    conn = db()
    try:
        active = conn.execute(
            "SELECT COUNT(*) FROM flips WHERE user_id = ? AND status != 'completed'",
            (user["id"],),
        ).fetchone()[0]
        if user["plan"] == "free" and active >= FREE_FLIP_LIMIT:
            raise ApiError(402, "free plan limit reached (10 active deals) — upgrade to Pro for unlimited")
        cur = conn.execute(
            """INSERT INTO flips (user_id, title, source, lot_number, buy_price_cents,
                 buy_fees_cents, inbound_shipping_cents, sale_price_cents, sale_fees_cents,
                 outbound_shipping_cents, purchase_date, sale_date, sale_platform, status,
                 notes, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user["id"], body["title"].strip(), str(body.get("source", "")),
             str(body.get("lot_number", "")), to_cents(body.get("buy_price")),
             to_cents(body.get("buy_fees")), to_cents(body.get("inbound_shipping")),
             to_cents(body.get("sale_price")), to_cents(body.get("sale_fees")),
             to_cents(body.get("outbound_shipping")), str(body.get("purchase_date", "")),
             str(body.get("sale_date", "")), str(body.get("sale_platform", "")),
             status, str(body.get("notes", "")), now_iso()),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM flips WHERE id = ?", (cur.lastrowid,)).fetchone()
    finally:
        conn.close()
    return row_to_flip(row)


def api_update_flip(user, flip_id, body):
    conn = db()
    try:
        owned_row(conn, "flips", flip_id, user["id"])
        sets, vals = [], []
        for col, key, conv in [
            ("title", "title", str), ("source", "source", str), ("lot_number", "lot_number", str),
            ("buy_price_cents", "buy_price", to_cents), ("buy_fees_cents", "buy_fees", to_cents),
            ("inbound_shipping_cents", "inbound_shipping", to_cents),
            ("sale_price_cents", "sale_price", to_cents), ("sale_fees_cents", "sale_fees", to_cents),
            ("outbound_shipping_cents", "outbound_shipping", to_cents),
            ("purchase_date", "purchase_date", str), ("sale_date", "sale_date", str),
            ("sale_platform", "sale_platform", str), ("notes", "notes", str),
        ]:
            if key in body:
                sets.append(f"{col} = ?")
                vals.append(conv(body[key]))
        if "status" in body:
            if body["status"] not in FLIP_STATUSES:
                raise ApiError(400, "invalid status")
            sets.append("status = ?")
            vals.append(body["status"])
        if not sets:
            raise ApiError(400, "nothing to update")
        vals += [flip_id, user["id"]]
        conn.execute(f"UPDATE flips SET {', '.join(sets)} WHERE id = ? AND user_id = ?", vals)
        conn.commit()
        row = conn.execute("SELECT * FROM flips WHERE id = ?", (flip_id,)).fetchone()
    finally:
        conn.close()
    return row_to_flip(row)


def api_delete_flip(user, flip_id):
    conn = db()
    owned_row(conn, "flips", flip_id, user["id"])
    conn.execute("DELETE FROM flips WHERE id = ? AND user_id = ?", (flip_id, user["id"]))
    conn.commit()
    conn.close()
    return {"ok": True}


def api_create_invoice(user, body):
    require_fields(body, ["title"])
    conn = db()
    cur = conn.execute(
        """INSERT INTO invoices (user_id, title, vendor, amount_cents, due_date,
             invoice_number, notes, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'unpaid', ?)""",
        (user["id"], body["title"].strip(), str(body.get("vendor", "")),
         to_cents(body.get("amount")), str(body.get("due_date", "")),
         str(body.get("invoice_number", "")), str(body.get("notes", "")), now_iso()),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM invoices WHERE id = ?", (cur.lastrowid,)).fetchone()
    conn.close()
    return dict(row)


def api_set_invoice_status(user, invoice_id, status):
    if status not in ("unpaid", "paid"):
        raise ApiError(400, "invalid status")
    conn = db()
    owned_row(conn, "invoices", invoice_id, user["id"])
    conn.execute("UPDATE invoices SET status = ? WHERE id = ? AND user_id = ?",
                 (status, invoice_id, user["id"]))
    conn.commit()
    row = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    conn.close()
    return dict(row)


def api_delete_invoice(user, invoice_id):
    conn = db()
    owned_row(conn, "invoices", invoice_id, user["id"])
    conn.execute("DELETE FROM invoices WHERE id = ? AND user_id = ?", (invoice_id, user["id"]))
    conn.commit()
    conn.close()
    return {"ok": True}


def api_create_deadline(user, body):
    require_fields(body, ["title"])
    kind = body.get("kind", "other")
    if kind not in DEADLINE_KINDS:
        raise ApiError(400, "invalid kind")
    conn = db()
    cur = conn.execute(
        """INSERT INTO deadlines (user_id, title, platform, kind, due_date, notes, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'open', ?)""",
        (user["id"], body["title"].strip(), str(body.get("platform", "")), kind,
         str(body.get("due_date", "")), str(body.get("notes", "")), now_iso()),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM deadlines WHERE id = ?", (cur.lastrowid,)).fetchone()
    conn.close()
    return dict(row)


def api_set_deadline_status(user, deadline_id, status):
    if status not in ("open", "done"):
        raise ApiError(400, "invalid status")
    conn = db()
    owned_row(conn, "deadlines", deadline_id, user["id"])
    conn.execute("UPDATE deadlines SET status = ? WHERE id = ? AND user_id = ?",
                 (status, deadline_id, user["id"]))
    conn.commit()
    row = conn.execute("SELECT * FROM deadlines WHERE id = ?", (deadline_id,)).fetchone()
    conn.close()
    return dict(row)


def api_delete_deadline(user, deadline_id):
    conn = db()
    owned_row(conn, "deadlines", deadline_id, user["id"])
    conn.execute("DELETE FROM deadlines WHERE id = ? AND user_id = ?", (deadline_id, user["id"]))
    conn.commit()
    conn.close()
    return {"ok": True}


# ---------------------------------------------------------------- Square billing
# Pro is $15/month, sold through Square. Flow: the app creates a
# Square-hosted payment link for the $15/month subscription plan
# variation; the buyer subscribes there; Square posts subscription
# events to /api/square-webhook, which flips the matching account to
# Pro (or back to free on cancel). The webhook signature is verified
# on every request; unverified posts are ignored. Until the SQUARE_*
# settings below are set, checkout honestly reports
# billing_not_configured and every account stays free.

SQUARE_BASE_URL = os.environ.get("SQUARE_BASE_URL", "https://connect.squareup.com").rstrip("/")
SQUARE_WEBHOOK_PATH = "/api/square-webhook"


def square_configured():
    return bool(os.environ.get("SQUARE_ACCESS_TOKEN")
                and os.environ.get("SQUARE_LOCATION_ID")
                and os.environ.get("SQUARE_PLAN_VARIATION_ID"))


def square_base_url():
    return os.environ.get("RENDER_EXTERNAL_URL", "http://localhost:8000").rstrip("/")


def square_webhook_url():
    return os.environ.get("SQUARE_WEBHOOK_URL") or (square_base_url() + SQUARE_WEBHOOK_PATH)


def square_api(method, path, token, payload=None):
    req = urllib.request.Request(
        SQUARE_BASE_URL + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise ApiError(502, f"Square API error: {e.read().decode()[:500]}")


def square_create_payment_link(user, post=None):
    """Return a Square-hosted checkout URL for the Pro subscription.
    `post` is an injectable stand-in for the Square API call (tests)."""
    payload = {
        "idempotency_key": uuid.uuid4().hex,
        "quick_pay": {
            "name": "FlipTrack Pro",
            "price_money": {"amount": 1500, "currency": "USD"},
            "location_id": os.environ.get("SQUARE_LOCATION_ID", ""),
        },
        "checkout_options": {
            "subscription_plan_id": os.environ.get("SQUARE_PLAN_VARIATION_ID", ""),
            "redirect_url": square_base_url() + "/",
        },
        "pre_populated_data": {"buyer_email": user["email"]},
    }
    if post is None:
        data = square_api("POST", "/v2/online-checkout/payment-links",
                          os.environ.get("SQUARE_ACCESS_TOKEN", ""), payload)
    else:
        data = post(payload)
    url = (data.get("payment_link") or {}).get("url")
    if not url:
        raise ApiError(502, "Square did not return a checkout URL")
    return {"checkout_url": url}


def verify_square_signature(signature_key, notification_url, raw_body, signature):
    """Square signs webhooks as base64(HMAC-SHA256(key, url + body))."""
    if not signature:
        return False
    digest = hmac.new(signature_key.encode(),
                      (notification_url + raw_body.decode()).encode(),
                      hashlib.sha256).digest()
    return hmac.compare_digest(base64.b64encode(digest).decode(), signature)


def square_customer_email(customer_id, get=None):
    if get is None:
        data = square_api("GET", f"/v2/customers/{customer_id}",
                          os.environ.get("SQUARE_ACCESS_TOKEN", ""))
    else:
        data = get(customer_id)
    return (data.get("customer") or {}).get("email_address")


def set_user_plan_by_email(email, plan):
    conn = db()
    row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if row is None:
        conn.close()
        return False
    conn.execute("UPDATE users SET plan = ? WHERE id = ?", (plan, row["id"]))
    conn.commit()
    conn.close()
    return True


def handle_square_event(event, customer_email=None):
    """Apply one Square subscription event. `customer_email` resolves a
    Square customer id to an email; defaults to a live Square lookup.
    Flipping a plan twice is harmless, so duplicate deliveries are safe.
    Returns True when an account plan was changed."""
    etype = event.get("type", "")
    sub = ((event.get("data") or {}).get("object") or {}).get("subscription") or {}
    if etype not in ("subscription.created", "subscription.updated") or not sub:
        return False
    status = sub.get("status", "")
    if status == "ACTIVE":
        plan = "pro"
    elif status == "CANCELED":
        plan = "free"
    else:
        return False
    email = (customer_email(sub.get("customer_id", "")) if customer_email
             else square_customer_email(sub.get("customer_id", "")))
    if not email:
        return False
    return set_user_plan_by_email(email, plan)


def api_square_webhook(raw_body, signature):
    key = os.environ.get("SQUARE_WEBHOOK_SIGNATURE_KEY", "")
    if not key or not verify_square_signature(key, square_webhook_url(), raw_body, signature):
        raise ApiError(401, "invalid webhook signature")
    try:
        event = json.loads(raw_body.decode())
    except (ValueError, UnicodeDecodeError):
        raise ApiError(400, "invalid JSON body")
    handle_square_event(event)
    return {"ok": True}


def api_billing(user):
    return {"plan": user["plan"], "pro_price_monthly_cents": 1500,
            "square_configured": square_configured()}


def api_checkout(user):
    # Square-hosted checkout for the $15/month Pro subscription plan.
    # Until Square is configured, fail honestly instead of pretending
    # to charge anyone.
    if not square_configured():
        raise ApiError(501, "billing_not_configured")
    return square_create_payment_link(user)

# ---------------------------------------------------------------- HTTP layer

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_json(self, status, payload, token=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if token:
            set_session_cookie(self, token, "")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, body):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            return json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "invalid JSON body")

    def require_user(self):
        user = user_from_request(self)
        if user is None:
            raise ApiError(401, "not signed in")
        return user

    def do_GET(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            if path == "/":
                self.send_html(FRONTEND)
            elif path == "/api/me":
                self.send_json(200, {"user": self.require_user()})
            elif path == "/api/dashboard":
                self.send_json(200, api_dashboard(self.require_user()))
            elif path == "/api/billing":
                self.send_json(200, api_billing(self.require_user()))
            else:
                self.send_json(404, {"error": "not found"})
        except ApiError as e:
            self.send_json(e.status, {"error": e.message})
        except Exception as e:
            self.send_json(500, {"error": f"server error: {e}"})

    def do_POST(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            if path == SQUARE_WEBHOOK_PATH:
                # Webhooks carry no session and must be verified from
                # their raw bytes, so they bypass the JSON/auth handling.
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                self.send_json(200, api_square_webhook(
                    raw, self.headers.get("x-square-hmacsha256-signature", "")))
                return
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                raise ApiError(400, "JSON body required")
            body = self.read_body()
            m = re.match(r"^/api/flips/(\d+)(/delete)?$", path)
            md = re.match(r"^/api/invoices/(\d+)/(pay|unpay|delete)$", path)
            mdd = re.match(r"^/api/deadlines/(\d+)/(done|reopen|delete)$", path)
            if path == "/api/signup":
                result = api_signup(body)
                self.send_json(200, {"user": result["user"]}, token=result["token"])
            elif path == "/api/login":
                result = api_login(body)
                self.send_json(200, {"user": result["user"]}, token=result["token"])
            elif path == "/api/logout":
                result = api_logout(self)
                self.send_response(200)
                clear_session_cookie(self)
                payload = json.dumps(result).encode()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            elif path == "/api/flips":
                self.send_json(200, api_create_flip(self.require_user(), body))
            elif m and m.group(2) == "/delete":
                self.send_json(200, api_delete_flip(self.require_user(), int(m.group(1))))
            elif m:
                self.send_json(200, api_update_flip(self.require_user(), int(m.group(1)), body))
            elif path == "/api/invoices":
                self.send_json(200, api_create_invoice(self.require_user(), body))
            elif md and md.group(2) == "delete":
                self.send_json(200, api_delete_invoice(self.require_user(), int(md.group(1))))
            elif md:
                status = "paid" if md.group(2) == "pay" else "unpaid"
                self.send_json(200, api_set_invoice_status(self.require_user(), int(md.group(1)), status))
            elif path == "/api/deadlines":
                self.send_json(200, api_create_deadline(self.require_user(), body))
            elif mdd and mdd.group(2) == "delete":
                self.send_json(200, api_delete_deadline(self.require_user(), int(mdd.group(1))))
            elif mdd:
                status = "done" if mdd.group(2) == "done" else "open"
                self.send_json(200, api_set_deadline_status(self.require_user(), int(mdd.group(1)), status))
            elif path == "/api/checkout":
                self.send_json(200, api_checkout(self.require_user()))
            else:
                self.send_json(404, {"error": "not found"})
        except ApiError as e:
            self.send_json(e.status, {"error": e.message})
        except Exception as e:
            self.send_json(500, {"error": f"server error: {e}"})


def main():
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"FlipTrack running on http://localhost:{PORT} (db: {DB_PATH})")
    server.serve_forever()

FRONTEND = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FlipTrack — Reseller Dashboard</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #f4f4f2; color: #222; }
  header { background: #1d2733; color: #fff; padding: 14px 16px; display: flex; justify-content: space-between; align-items: center; }
  header b { font-size: 20px; }
  header .who { font-size: 13px; opacity: .85; }
  header button { background: #3a4a5e; color: #fff; border: 0; border-radius: 6px; padding: 6px 10px; }
  main { max-width: 860px; margin: 0 auto; padding: 16px; }
  .strip { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 16px; }
  .card { background: #fff; border-radius: 10px; padding: 14px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .card .label { font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: #666; }
  .card .num { font-size: 26px; font-weight: 700; margin-top: 4px; }
  .card .num.red { color: #c0392b; }
  .card .num.green { color: #1e7d32; }
  .tabs { display: flex; gap: 8px; margin: 4px 0 14px; }
  .tabs button { flex: 1; padding: 10px; border: 0; border-radius: 8px; background: #ddd; font-size: 15px; }
  .tabs button.active { background: #1d2733; color: #fff; }
  .item { background: #fff; border-radius: 10px; padding: 12px 14px; margin-bottom: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .item h3 { margin: 0 0 4px; font-size: 16px; }
  .item .meta { font-size: 13px; color: #555; }
  .item .notes { font-size: 13px; color: #444; margin-top: 6px; white-space: pre-wrap; }
  .item .row { display: flex; gap: 8px; margin-top: 8px; flex-wrap: wrap; align-items: center; }
  .item select, .item button, form input, form select, form textarea { font-size: 14px; padding: 7px 9px; border-radius: 6px; border: 1px solid #ccc; }
  .item button, form button { background: #1d2733; color: #fff; border: 0; }
  .item button.danger { background: #c0392b; }
  .item button.secondary { background: #e8e8e6; color: #222; }
  .overdue { border-left: 5px solid #c0392b; }
  .due-soon { border-left: 5px solid #e67e22; }
  .done { opacity: .6; }
  form { background: #fff; border-radius: 10px; padding: 14px; margin-top: 14px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  form h3 { margin: 0 0 10px; }
  form .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  form .full { grid-column: 1 / -1; }
  form input, form select, form textarea { width: 100%; }
  form button { margin-top: 10px; padding: 10px 16px; }
  .err { background: #fdecea; color: #c0392b; padding: 10px; border-radius: 8px; margin-bottom: 12px; }
  .ok { background: #e6f4ea; color: #1e7d32; padding: 10px; border-radius: 8px; margin-bottom: 12px; }
  .empty { color: #666; font-size: 14px; padding: 8px 0; }
  @media (max-width: 560px) { .strip { grid-template-columns: 1fr 1fr; } form .grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<header><span style="display:flex;align-items:center;gap:10px"><img src="data:image/png;base64,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" style="height:34px;width:34px" alt=""><b>FlipTrack</b></span><span class="who" id="who"></span></header>
<main>
  <div id="msg"></div>

  <section id="authView">
    <div class="card">
      <h2 style="margin-top:0">Track what you owe, what's due, and what you made.</h2>
      <p style="color:#555">One dashboard for resellers: auction invoices, ship-by dates, support replies, and profit per deal.</p>
      <form id="authForm" onsubmit="return doAuth(event)">
        <div class="grid">
          <input class="full" type="email" id="authEmail" placeholder="Email" required>
          <input class="full" type="password" id="authPass" placeholder="Password (8+ characters)" required>
        </div>
        <button type="submit" id="authBtn">Create account</button>
        <button type="button" class="secondary" style="margin-left:8px" onclick="toggleAuth()">I already have an account</button>
      </form>
    </div>
  </section>

  <section id="appView" style="display:none">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <h2 style="margin:8px 0">Dashboard</h2>
      <button onclick="logout()" style="background:#3a4a5e;color:#fff;border:0;border-radius:6px;padding:7px 12px">Log out</button>
    </div>
    <div class="strip" id="strip"></div>
    <div class="card" id="attention" style="margin-bottom:16px"></div>
    <div class="tabs">
      <button id="tabFlips" onclick="showTab('flips')">Deals</button>
      <button id="tabInvoices" onclick="showTab('invoices')">I Owe</button>
      <button id="tabDeadlines" onclick="showTab('deadlines')">Deadlines</button>
    </div>
    <div id="list"></div>
    <div id="addForm"></div>
    <div class="card" style="margin-top:16px" id="billing"></div>
  </section>
</main>
<script>
let DATA = null, TAB = 'flips', AUTH_MODE = 'signup';
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = c => (c < 0 ? '-$' : '$') + Math.abs(c / 100).toFixed(2);
function showMsg(text, ok) { $('msg').innerHTML = text ? `<div class="${ok ? 'ok' : 'err'}">${esc(text)}</div>` : ''; }
async function api(path, method, body) {
  const r = await fetch(path, { method: method || 'GET', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || ('request failed: ' + r.status));
  return d;
}
function toggleAuth() {
  AUTH_MODE = AUTH_MODE === 'signup' ? 'login' : 'signup';
  $('authBtn').textContent = AUTH_MODE === 'signup' ? 'Create account' : 'Log in';
  event.target.textContent = AUTH_MODE === 'signup' ? 'I already have an account' : 'I need an account';
}
async function doAuth(e) {
  e.preventDefault(); showMsg('');
  try {
    const d = await api('/api/' + AUTH_MODE, 'POST', { email: $('authEmail').value, password: $('authPass').value });
    await load();
  } catch (err) { showMsg(err.message); }
  return false;
}
async function logout() { try { await api('/api/logout', 'POST', {}); } catch (e) {} location.reload(); }
async function load() {
  try {
    const me = await api('/api/me');
    $('who').textContent = me.user.email + ' · ' + me.user.plan + ' plan';
    $('authView').style.display = 'none'; $('appView').style.display = 'block';
    DATA = await api('/api/dashboard');
    const b = await api('/api/billing');
    render(b);
  } catch (e) { $('authView').style.display = 'block'; $('appView').style.display = 'none'; }
}
function render(billing) {
  const s = DATA.stats;
  $('strip').innerHTML =
    `<div class="card"><div class="label">You owe</div><div class="num red">${fmt(s.total_owed_cents)}</div></div>` +
    `<div class="card"><div class="label">Overdue</div><div class="num red">${s.overdue_count}</div></div>` +
    `<div class="card"><div class="label">Due in next 7 days</div><div class="num">${s.due_next7_count}</div></div>` +
    `<div class="card"><div class="label">Net profit (sold)</div><div class="num ${s.net_profit_cents >= 0 ? 'green' : 'red'}">${fmt(s.net_profit_cents)}</div></div>`;
  const att = [...DATA.overdue, ...DATA.due_next7.filter(d => !DATA.overdue.includes(d))];
  $('attention').innerHTML = '<h3 style="margin:0 0 8px">Needs attention</h3>' +
    (att.length ? att.map(d => `<div>• ${esc(d.title)} — due ${esc(d.due_date || 'no date')} (${esc(d.platform || '')})</div>`).join('')
      : '<div class="empty">Nothing overdue or due this week. Nice.</div>');
  ['flips', 'invoices', 'deadlines'].forEach(t => $('tab' + t[0].toUpperCase() + t.slice(1)).classList.toggle('active', TAB === t));
  renderList();
  $('billing').innerHTML = `<h3 style="margin:0 0 6px">Billing — ${esc(billing.plan)} plan</h3>
    <div style="font-size:14px;color:#555">Pro is $15/month for unlimited deals and alerts. Free covers up to 10 active deals.</div>
    ${billing.plan === 'free' ? `<button style="margin-top:10px" onclick="upgrade()">Upgrade to Pro</button>` : '<div style="margin-top:8px;color:#1e7d32">You are on Pro. Thank you.</div>'}`;
}
async function upgrade() {
  try { const r = await api('/api/checkout', 'POST', {}); if (r.checkout_url) { window.location.href = r.checkout_url; return; } showMsg('Checkout opened.', true); }
  catch (err) { showMsg(err.message === 'billing_not_configured' ? 'Payments are not connected yet — the seller still needs to connect Square. Your account stays free.' : err.message); }
}
function renderList() {
  if (TAB === 'flips') {
    $('list').innerHTML = DATA.flips.length ? DATA.flips.map(f => `
      <div class="item">
        <h3>${esc(f.title)}</h3>
        <div class="meta">${esc(f.source || '')} ${f.lot_number ? '· lot ' + esc(f.lot_number) : ''} · bought ${esc(f.purchase_date || '?')} · net <b>${fmt(f.net_cents)}</b></div>
        <div class="meta">Buy ${fmt(f.buy_price_cents)} + fees ${fmt(f.buy_fees_cents)} + inbound ${fmt(f.inbound_shipping_cents)} · Sale ${fmt(f.sale_price_cents)} − fees ${fmt(f.sale_fees_cents)} − outbound ${fmt(f.outbound_shipping_cents)}</div>
        ${f.notes ? `<div class="notes">${esc(f.notes)}</div>` : ''}
        <div class="row">
          <select onchange="updateFlip(${f.id}, {status: this.value})">${['won','paid','in_transit','in_hand','listed','sold','shipped','completed'].map(s => `<option ${s === f.status ? 'selected' : ''}>${s}</option>`).join('')}</select>
          <button class="secondary" onclick="editSale(${f.id})">Record sale</button>
          <button class="danger" onclick="delFlip(${f.id})">Delete</button>
        </div>
      </div>`).join('') : '<div class="empty">No deals yet. Add your first one below.</div>';
    $('addForm').innerHTML = `<form onsubmit="return addFlip(event)"><h3>Add a deal</h3><div class="grid">
      <input class="full" id="fTitle" placeholder="Title (e.g. 1963 Red Seal notes)" required>
      <input id="fSource" placeholder="Source (auction house, eBay…)">
      <input id="fLot" placeholder="Lot / order number">
      <input type="number" step="0.01" id="fBuy" placeholder="Buy price ($)">
      <input type="number" step="0.01" id="fBuyFees" placeholder="Buy fees / premium ($)">
      <input type="number" step="0.01" id="fInShip" placeholder="Inbound shipping ($)">
      <input type="date" id="fBuyDate">
      <input class="full" id="fNotes" placeholder="Notes">
    </div><button>Add deal</button></form>`;
  } else if (TAB === 'invoices') {
    $('list').innerHTML = DATA.invoices.length ? DATA.invoices.map(i => `
      <div class="item ${i.status === 'unpaid' && i.due_date && i.due_date < new Date().toISOString().slice(0, 10) ? 'overdue' : ''}">
        <h3>${esc(i.title)}</h3>
        <div class="meta">${esc(i.vendor || '')} ${i.invoice_number ? '· invoice ' + esc(i.invoice_number) : ''} · ${fmt(i.amount_cents)} · due ${esc(i.due_date || 'no date')} · <b>${i.status}</b></div>
        ${i.notes ? `<div class="notes">${esc(i.notes)}</div>` : ''}
        <div class="row">
          ${i.status === 'unpaid' ? `<button onclick="invAction(${i.id}, 'pay')">Mark paid</button>` : `<button class="secondary" onclick="invAction(${i.id}, 'unpay')">Reopen</button>`}
          <button class="danger" onclick="invAction(${i.id}, 'delete')">Delete</button>
        </div>
      </div>`).join('') : '<div class="empty">No invoices. Add one below.</div>';
    $('addForm').innerHTML = `<form onsubmit="return addInvoice(event)"><h3>Add an invoice</h3><div class="grid">
      <input class="full" id="iTitle" placeholder="Title" required>
      <input id="iVendor" placeholder="Vendor / auction house">
      <input type="number" step="0.01" id="iAmount" placeholder="Amount ($)">
      <input type="date" id="iDue">
      <input id="iNum" placeholder="Invoice number">
      <input class="full" id="iNotes" placeholder="Notes">
    </div><button>Add invoice</button></form>`;
  } else {
    const today = new Date().toISOString().slice(0, 10);
    $('list').innerHTML = DATA.deadlines.length ? DATA.deadlines.map(d => `
      <div class="item ${d.status === 'done' ? 'done' : (d.due_date && d.due_date < today ? 'overdue' : '')}">
        <h3>${esc(d.title)}</h3>
        <div class="meta">${esc(d.platform || '')} · ${esc(d.kind)} · due ${esc(d.due_date || 'no date')} · <b>${d.status}</b></div>
        ${d.notes ? `<div class="notes">${esc(d.notes)}</div>` : ''}
        <div class="row">
          ${d.status === 'open' ? `<button onclick="dlAction(${d.id}, 'done')">Mark done</button>` : `<button class="secondary" onclick="dlAction(${d.id}, 'reopen')">Reopen</button>`}
          <button class="danger" onclick="dlAction(${d.id}, 'delete')">Delete</button>
        </div>
      </div>`).join('') : '<div class="empty">No deadlines. Add one below.</div>';
    $('addForm').innerHTML = `<form onsubmit="return addDeadline(event)"><h3>Add a deadline</h3><div class="grid">
      <input class="full" id="dTitle" placeholder="Title" required>
      <input id="dPlatform" placeholder="Platform (eBay, Whatnot…)">
      <select id="dKind"><option>ship_by</option><option>reply_by</option><option>pay_by</option><option>return_by</option><option>case</option><option>follow_up</option><option>other</option></select>
      <input type="date" id="dDue">
      <input class="full" id="dNotes" placeholder="Notes">
    </div><button>Add deadline</button></form>`;
  }
}
function showTab(t) { TAB = t; load(); }
async function refresh() { DATA = await api('/api/dashboard'); const b = await api('/api/billing'); render(b); }
async function addFlip(e) {
  e.preventDefault(); showMsg('');
  try {
    await api('/api/flips', 'POST', { title: $('fTitle').value, source: $('fSource').value, lot_number: $('fLot').value,
      buy_price: $('fBuy').value, buy_fees: $('fBuyFees').value, inbound_shipping: $('fInShip').value,
      purchase_date: $('fBuyDate').value, notes: $('fNotes').value });
    await refresh(); showMsg('Deal added.', true);
  } catch (err) { showMsg(err.message); }
  return false;
}
async function addInvoice(e) {
  e.preventDefault(); showMsg('');
  try {
    await api('/api/invoices', 'POST', { title: $('iTitle').value, vendor: $('iVendor').value, amount: $('iAmount').value,
      due_date: $('iDue').value, invoice_number: $('iNum').value, notes: $('iNotes').value });
    await refresh(); showMsg('Invoice added.', true);
  } catch (err) { showMsg(err.message); }
  return false;
}
async function addDeadline(e) {
  e.preventDefault(); showMsg('');
  try {
    await api('/api/deadlines', 'POST', { title: $('dTitle').value, platform: $('dPlatform').value, kind: $('dKind').value,
      due_date: $('dDue').value, notes: $('dNotes').value });
    await refresh(); showMsg('Deadline added.', true);
  } catch (err) { showMsg(err.message); }
  return false;
}
async function updateFlip(id, patch) { try { await api('/api/flips/' + id, 'POST', patch); await refresh(); } catch (err) { showMsg(err.message); } }
async function editSale(id) {
  const sale = prompt('Sale price ($):'); if (sale === null) return;
  const fees = prompt('Sale fees ($, optional):', '0'); if (fees === null) return;
  const ship = prompt('Outbound shipping ($, optional):', '0'); if (ship === null) return;
  try { await api('/api/flips/' + id, 'POST', { sale_price: sale, sale_fees: fees, outbound_shipping: ship, status: 'sold' }); await refresh(); }
  catch (err) { showMsg(err.message); }
}
async function delFlip(id) { if (!confirm('Delete this deal?')) return; try { await api('/api/flips/' + id + '/delete', 'POST', {}); await refresh(); } catch (err) { showMsg(err.message); } }
async function invAction(id, action) { try { await api('/api/invoices/' + id + '/' + action, 'POST', {}); await refresh(); } catch (err) { showMsg(err.message); } }
async function dlAction(id, action) { try { await api('/api/deadlines/' + id + '/' + action, 'POST', {}); await refresh(); } catch (err) { showMsg(err.message); } }
load();
</script>
</body>
</html>'''

if __name__ == "__main__":
    main()
