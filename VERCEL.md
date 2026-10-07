# Running Pirates billing on Vercel

End result: the dashboard lives at `https://billing.colinowen.online`, GitHub
pushes to `main` deploy automatically, and the MikroTik pulls its changes
from the app once a minute. Nothing connects *in* to the router, so it needs
no public IP, port forward, or VPN.

```
GitHub (main) ──push──▶ Vercel ──▶ Neon Postgres
                          ▲
MikroTik ── every 60s ────┘  POST /api/router/sync  → gets queued commands as a script
                             POST /api/router/ack   → reports which ones worked
```

- **Expiries** run on every router sync, so they apply within a minute.
- **Payments** queue a reconnect, which the router applies on its next sync,
  within about a minute.
- **Reminders** run once a day from the Vercel cron in `vercel.json`.

## 1. Database (Neon)

1. In the Vercel dashboard, open **Storage**, then **Create**, then **Neon**,
   and connect it to the project. This sets `DATABASE_URL` (pooled) and
   `DATABASE_URL_UNPOOLED` for you.
2. Create the tables once from your laptop, using the **unpooled** URL:
   ```powershell
   $env:DATABASE_URL = "<DATABASE_URL_UNPOOLED from Neon>"
   .venv\Scripts\alembic upgrade head
   ```
3. Future migrations run automatically. In GitHub, go to **Settings**, then
   **Secrets and variables**, then **Actions**, and add a `DATABASE_URL`
   secret with the same unpooled URL. `.github/workflows/ci.yml` runs
   `alembic upgrade head` after tests pass on `main`.

## 2. Vercel project

1. **Add New**, then **Project**, then import `owenz4040/pirates`.
   FastAPI is detected from `index.py`.
2. Under **Settings**, then **Environment Variables**, add the following:

   | Variable | Value |
   |---|---|
   | `ADMIN_USERNAME`, `ADMIN_PASSWORD` | your dashboard login |
   | `SESSION_SECRET_KEY` | `python -c "import secrets; print(secrets.token_hex(32))"`. **Required.** Without it you get logged out on every cold start. |
   | `CRON_SECRET` | another random hex string |
   | `PUBLIC_BASE_URL` | `https://billing.colinowen.online` |
   | `PAYSTACK_SECRET_KEY` | from Paystack |
   | `AFRICASTALKING_*`, `RESEND_*` | as in `.env.example` |

3. Redeploy after adding the variables.

## 3. Domain

1. In the project, open **Settings**, then **Domains**, then **Add**, and
   enter `billing.colinowen.online`.
2. Where colinowen.online's DNS is managed, add the record Vercel shows,
   normally `A billing → 76.76.21.21` with the proxy **off** (grey cloud, "DNS only"). Your portfolio on the
   apex domain is untouched. If the apex domain belongs to a different Vercel
   account, Vercel also asks for a `TXT` verification record. Add that too.

## 4. Paystack

Set the webhook URL in the Paystack dashboard to
`https://billing.colinowen.online/paystack/webhook`.

## 5. Router

1. Make sure the router can reach the internet and resolve DNS. Go to
   **IP**, then **DNS**, and check that servers are set. RouterOS 6.45+ works,
   RouterOS 7 is recommended (it takes much bigger batches).
2. In the dashboard, open **Router**, then **Copy script**. In Winbox, open
   **New Terminal** and paste. The Router page should show **Online** within
   a minute.
3. Click **Resync everything** once. It aligns profiles and each customer's
   on/off state with the billing database.
4. Static/IP-pool customers still need the one-time drop rule for the
   `suspended-users` address list:
   `/ip firewall filter add chain=forward src-address-list=suspended-users action=drop place-before=0`
5. The app no longer uses the RouterOS API, so close it to the internet:
   `/ip service set api-ssl disabled=yes` and remove any 8729 port forward.

## Notes

- **Hobby plan:** Vercel's free plan is for non-commercial use. Move to Pro
  once paying customers depend on it.
- **If the router goes offline**, commands wait in the queue and apply when
  it's back. Failed commands are listed on the Router page with a retry
  button.
- **Running locally:** `uvicorn billing.main:app --reload` with a local
  `.env`. To act like the router, POST to `/api/router/sync` with the
  `X-Pirates-Token` header shown in the setup script.
