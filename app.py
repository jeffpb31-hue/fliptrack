#!/usr/bin/env python3
"""FlipTrack — multi-user reseller dashboard.

One dashboard for small resellers: what do I owe, what's due, and what
did I actually make? Each seller gets their own account; every record
is scoped to that account, so sellers can never see each other's data.

Stack: Python standard library only. No pip installs, no build step.
Run:  python3 app.py        (listens on $PORT, default 8000)
Data: SQLite file at $FLIPTRACK_DB (default ./fliptrack.db).

Billing: Pro is $15/month via Stripe. Until STRIPE_SECRET_KEY and
STRIPE_PRICE_ID are set, checkout reports billing_not_configured and
every account stays on the free plan. See README.md.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import urllib.parse
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


def api_billing(user):
    configured = bool(os.environ.get("STRIPE_SECRET_KEY") and os.environ.get("STRIPE_PRICE_ID"))
    return {"plan": user["plan"], "pro_price_monthly_cents": 1500,
            "stripe_configured": configured}


def api_checkout(user):
    # Real Stripe Checkout goes here once keys are configured (see README).
    # Until then, fail honestly instead of pretending to charge anyone.
    if not (os.environ.get("STRIPE_SECRET_KEY") and os.environ.get("STRIPE_PRICE_ID")):
        raise ApiError(501, "billing_not_configured")
    raise ApiError(501, "stripe checkout not wired in this build — see README.md")

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
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                raise ApiError(400, "JSON body required")
            path = urllib.parse.urlparse(self.path).path
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
<header><b>FlipTrack</b><span class="who" id="who"></span></header>
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
  try { await api('/api/checkout', 'POST', {}); showMsg('Checkout opened.', true); }
  catch (err) { showMsg(err.message === 'billing_not_configured' ? 'Payments are not connected yet — the seller still needs to connect Stripe. Your account stays free.' : err.message); }
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
