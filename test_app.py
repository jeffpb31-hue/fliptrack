#!/usr/bin/env python3
"""End-to-end checks for the FlipTrack multi-user app.

Starts the server on a scratch database, then exercises signup, login,
per-user isolation, dashboard math, and the free-plan limit.
Prints PASS/FAIL per check and exits non-zero on any failure.
"""
import http.cookiejar
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PORT = 8471
BASE = f"http://127.0.0.1:{PORT}"
FAILURES = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f" — {extra}" if extra and not cond else ""))
    if not cond:
        FAILURES.append(name)


class Client:
    def __init__(self):
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def call(self, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            BASE + path, data=data,
            headers={"Content-Type": "application/json"}, method="POST" if body is not None else "GET",
        )
        try:
            with self.opener.open(req) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())


def main():
    tmp = tempfile.mkdtemp()
    env = dict(os.environ, FLIPTRACK_DB=os.path.join(tmp, "test.db"), PORT=str(PORT))
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):
            try:
                a = Client()
                code, _ = a.call("/api/me")
                break
            except Exception:
                time.sleep(0.2)
        else:
            print("FAIL server did not start")
            return 1

        a, b = Client(), Client()
        code, r = a.call("/api/signup", {"email": "alice@example.com", "password": "password123"})
        check("signup A succeeds", code == 200, str(r))
        code, r = a.call("/api/signup", {"email": "alice@example.com", "password": "password123"})
        check("duplicate signup rejected", code == 409, str(r))
        code, r = b.call("/api/signup", {"email": "bob@example.com", "password": "password123"})
        check("signup B succeeds", code == 200, str(r))
        c = Client()
        code, r = c.call("/api/login", {"email": "alice@example.com", "password": "wrongpass"})
        check("wrong password rejected", code == 401, str(r))
        code, r = c.call("/api/me")
        check("unauthenticated dashboard blocked", code == 401, str(r))

        code, flip = a.call("/api/flips", {"title": "Test coins", "source": "Auction House",
                                           "buy_price": 416.05, "purchase_date": "2026-10-03"})
        check("A creates flip", code == 200 and flip["id"], str(flip))
        fid = flip["id"]
        code, flip = a.call(f"/api/flips/{fid}", {"sale_price": 500, "sale_fees": 50,
                                                 "outbound_shipping": 10, "status": "sold"})
        check("net math: 500 - 416.05 - 50 - 10 = 23.95",
              code == 200 and flip["net_cents"] == 2395, str(flip))
        code, inv = a.call("/api/invoices", {"title": "Dali test", "vendor": "Auction Online",
                                             "amount": 353.94, "due_date": "2026-09-30"})
        check("A creates invoice", code == 200 and inv["id"], str(inv))
        iid = inv["id"]
        code, dl = a.call("/api/deadlines", {"title": "Ship test", "platform": "eBay",
                                             "kind": "ship_by", "due_date": "2026-09-29"})
        check("A creates deadline", code == 200 and dl["id"], str(dl))

        code, dash = a.call("/api/dashboard")
        check("A dashboard: owed 353.94", dash["stats"]["total_owed_cents"] == 35394, str(dash["stats"]))
        check("A dashboard: 1 overdue", dash["stats"]["overdue_count"] == 1, str(dash["stats"]))
        check("A dashboard: net profit 23.95", dash["stats"]["net_profit_cents"] == 2395, str(dash["stats"]))

        code, dashb = b.call("/api/dashboard")
        check("B dashboard is empty", code == 200 and not dashb["flips"]
              and not dashb["invoices"] and not dashb["deadlines"], str(dashb["stats"]))
        code, r = b.call(f"/api/invoices/{iid}/pay", {})
        check("B cannot pay A's invoice", code == 404, str(r))
        code, r = b.call(f"/api/flips/{fid}/delete", {})
        check("B cannot delete A's flip", code == 404, str(r))
        code, r = b.call(f"/api/deadlines/{dl['id']}/done", {})
        check("B cannot complete A's deadline", code == 404, str(r))

        # Free-plan limit: A has 1 active flip; 9 more reach 10, the 11th must fail.
        for i in range(9):
            code, _ = a.call("/api/flips", {"title": f"Filler {i}"})
            assert code == 200, f"filler {i} failed: {code}"
        code, r = a.call("/api/flips", {"title": "Over the limit"})
        check("11th active flip blocked on free plan", code == 402, str(r))

        code, r = a.call(f"/api/invoices/{iid}/pay", {})
        check("A pays own invoice", code == 200 and r["status"] == "paid", str(r))
        code, dash = a.call("/api/dashboard")
        check("owed drops to 0 after payment", dash["stats"]["total_owed_cents"] == 0, str(dash["stats"]))
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    print(f"\n{len(FAILURES)} failure(s)" if FAILURES else "\nALL CHECKS PASSED")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
