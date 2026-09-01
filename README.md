# MikroTik PPPoE billing core

Python library for the piece everything else in the billing system depends
on: talking to a MikroTik router over the RouterOS API to suspend/restore
PPPoE users and change their bandwidth. This is step one of the larger
architecture (REST API, billing backend, worker, Android app, admin
dashboard); those layers will call into `mikrotik/` rather than talk to
RouterOS directly.

## What's here

- `mikrotik/client.py` - opens an API-SSL connection to the router from env vars.
- `mikrotik/pppoe.py` - `PPPoEManager`: list/create secrets, suspend (disable +
  kick), restore, and move a user to a different bandwidth profile.
- `mikrotik/bandwidth.py` - `BandwidthProfileManager`: manage PPP profiles used
  as bandwidth tiers (`rate-limit`).
- `scripts/demo.py` - CLI to exercise the above against your real hAP lite.
- `tests/` - unit tests against an in-memory fake router (no hardware needed).

## Router-side setup (hAP lite, one-time)

You said the router will be reachable on a static public IP with a
port-forward. That means the RouterOS API is exposed to the whole internet,
so lock it down before you rely on it:

1. **Create a dedicated, non-admin API user.**
   `/user group add name=api-billing policy=api,read,write,!local,!telnet,!ssh,!ftp,!reboot,!policy,!sensitive,!romon`
   `/user add name=billing-api group=api-billing password=<strong-random-password>`
   Don't reuse your `admin` account - if this password ever leaks, blast
   radius is limited to PPP secrets and profiles, not full router config.

2. **Enable api-ssl, disable plain api.**
   `/ip service set api disabled=yes`
   `/ip service set api-ssl disabled=no port=8729 certificate=<your-cert>`
   If you don't have a real cert yet, RouterOS's self-signed default works
   for now (that's why `MIKROTIK_VERIFY_SSL=false` by default) - traffic is
   still encrypted, you just aren't verifying router identity. Get a real
   cert on the router later and flip that env var to `true`.

3. **Restrict who can even reach port 8729.** Don't rely on the password
   alone since this port faces the internet:
   `/ip firewall address-list add list=billing-backend address=<your backend's public IP>`
   `/ip firewall filter add chain=input protocol=tcp dst-port=8729 src-address-list=billing-backend action=accept place-before=0`
   `/ip firewall filter add chain=input protocol=tcp dst-port=8729 action=drop`
   If your backend doesn't have a static IP, put it behind a VPN
   (WireGuard is built into recent RouterOS) instead of opening 8729 to
   everyone - update the address-list, not the plan, if that's the case.

4. **Port-forward 8729** from your ISP's public IP to the router (skip this
   if the router itself already has the public IP on its WAN interface).

5. **Create your bandwidth tiers as PPP profiles** so `set_profile` has
   something to point users at:
   `/ppp profile add name=5mbps rate-limit=5M/5M`
   `/ppp profile add name=10mbps rate-limit=10M/10M`
   (`rx/tx` = router receives-from-client/sends-to-client, i.e.
   upload/download from the subscriber's point of view.) Or do this from
   Python: `BandwidthProfileManager(api).ensure_profile("10mbps", "10M/10M")`.

## Local setup

```
py -m venv .venv
.venv\Scripts\pip install -r requirements-dev.txt
copy .env.example .env   # then fill in MIKROTIK_HOST / USER / PASSWORD
```

Run the tests (no router required):

```
.venv\Scripts\python -m pytest -q
```

Try it against the real router:

```
.venv\Scripts\python -m scripts.demo list-secrets
.venv\Scripts\python -m scripts.demo ensure-profile 10mbps 10M/10M
.venv\Scripts\python -m scripts.demo set-bandwidth alice 10mbps
.venv\Scripts\python -m scripts.demo suspend alice
.venv\Scripts\python -m scripts.demo restore alice
```

## Design notes / caveats worth knowing before building on top of this

- **Suspending a user drops their live session.** RouterOS only checks
  `disabled` on the *next* dial attempt, so `disable_user()` also removes
  any matching row from `/ppp/active` to force an immediate disconnect -
  otherwise someone already online would stay online until the ISP's
  keepalive/idle timeout, which could be hours.
- **Bandwidth changes also force a reconnect by default** (`set_profile(...,
  force_reconnect=True)`), for the same reason: a profile's `rate-limit`
  only takes effect on the session that's negotiated after the change. Most
  PPPoE clients (including consumer routers) auto-redial within seconds, but
  if you ever see a device that doesn't, that's a client-side setting, not
  something fixable from here.
- **This library has no scheduling logic.** "Cut off after one month" is a
  billing-backend concern (a `subscription_end` column + your worker's cron),
  not something the router tracks. This layer just exposes
  `disable_user`/`enable_user`/`set_profile` for that worker to call.
- Not covered yet, and worth doing before this goes further: retry/backoff
  around the RouterOS connection (single dropped TCP session shouldn't fail
  a billing job), and structured logging of every suspend/restore/bandwidth
  change for support/dispute purposes.
