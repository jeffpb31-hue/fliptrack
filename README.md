# FlipTrack — multi-user reseller dashboard

One dashboard for small resellers: what do I owe, what's due, and what
did I actually make? Sellers sign up, track their own deals, invoices,
and deadlines, and see net profit per deal. Each seller's data is
isolated to their account.

## Run it

```bash
python3 app.py
```

Then open http://localhost:8000. No installs, no build step — Python
3.11+ standard library only. Data lives in `fliptrack.db` (SQLite).

Run the checks:

```bash
python3 test_app.py
```

## Features

- Accounts: signup / login / logout, passwords hashed with PBKDF2.
- Deals ledger: buy price, buy fees/premium, inbound shipping, sale
  price, sale fees, outbound shipping — net profit calculated per deal.
- Invoices: auction-house bills with due dates, mark paid/unpaid.
- Deadlines: ship-by, reply-by, pay-by, return-by, case, follow-up —
  with a Needs Attention section for overdue and due-this-week items.
- Dashboard strip: total owed, overdue count, due in next 7 days,
  net profit on sold deals.
- Plans: free covers up to 10 active deals; Pro is $15/month for
  unlimited deals. The limit is enforced server-side.

## Security notes

- Passwords: PBKDF2-HMAC-SHA256, 200,000 iterations, unique salt.
- Sessions: random tokens stored hashed, HttpOnly cookies, 30-day expiry.
- Every query is parameterized, and every read/update/delete checks
  that the record belongs to the signed-in user (verified by
  `test_app.py`: one user cannot see, pay, complete, or delete
  another user's records).
- Run behind HTTPS in production (Caddy, nginx, or your host's TLS),
  and set the session cookie Secure flag if you terminate TLS in-app.

## Deploy on Render (current path — Railway signups paused Oct 2026)

1. Create a Render account (free to sign up; no signup pause).
2. Push this folder to a GitHub repo, then in Render: New →
   Web Service → Build and deploy from a Git repo, and pick that
   repo. Render reads `render.yaml`, which declares everything:
   Starter instance ($7/month), a 1 GB persistent disk mounted at
   `/data` ($0.25/month), and `FLIPTRACK_DB=/data/fliptrack.db`.
   `PORT` is provided by Render automatically — do not set it.
3. Deploy. Render gives you a public `*.onrender.com` URL with
   free SSL. Pick the paid Starter plan, not the free tier: free
   services sleep after 15 minutes and do not keep data.
4. Later: add a custom domain in Render, and set
   `STRIPE_SECRET_KEY` / `STRIPE_PRICE_ID` when you wire Pro billing.

Note: the live database starts empty — the demo data in the private
prototype does not carry over. Add your open deals once it is live.

## Deploy on Railway (chosen host)

1. Create a Railway account and pick the Hobby plan ($5/month,
   card required).
2. Push this folder to a GitHub repo (it is already a git repo —
   see below), then in Railway: New Project → Deploy from GitHub,
   and pick that repo. Railway detects Python and runs
   `python3 app.py` (see `railway.json` / `Procfile`).
3. Add a volume to the service and set its mount path to `/data`.
   Without this, the SQLite database is wiped on every redeploy.
4. Set the service variable `FLIPTRACK_DB=/data/fliptrack.db`.
   `PORT` is provided by Railway automatically — do not set it.
5. Deploy. Railway health-checks `/` and gives you a public URL.
6. Later: add a custom domain in Railway, and set
   `STRIPE_SECRET_KEY` / `STRIPE_PRICE_ID` when you wire Pro billing.

Note: the live database starts empty — the demo data in the private
prototype does not carry over. Add your open deals once it is live.

## Deploy it (going live)

The app listens on `$PORT` (default 8000) and stores data in
`$FLIPTRACK_DB`. Any host that runs Python works: a VPS, Render,
Railway, Fly.io, etc.

1. Copy this folder to the host. Give the SQLite file a persistent
   disk — on hosts with ephemeral filesystems, attach a volume or the
   database will reset on each deploy.
2. Run `python3 app.py` behind HTTPS.
3. Point your domain at it.

SQLite is fine for the first hundreds of users on one server. When you
outgrow it, move the same schema to Postgres.

## Connect Stripe (Pro billing)

1. Create a $15/month recurring price in Stripe.
2. Set `STRIPE_SECRET_KEY` and `STRIPE_PRICE_ID` in the environment.
3. Wire `api_checkout()` in `app.py` to create a Checkout Session
   (price ID, success/cancel URLs), and add a webhook endpoint that
   flips `users.plan` to `'pro'` on `checkout.session.completed`
   (and back to `'free'` on subscription cancellation).
4. Until those keys are set, checkout honestly reports
   `billing_not_configured` and every account stays free — it never
   pretends to charge anyone.

## Not built yet (future versions)

- Email/SMS deadline alerts (needs a mail provider).
- Automatic import from Gmail, eBay, or Whatnot (currently manual entry).
- Password reset via email (needs a mail provider).
- Team accounts / shared shops.
