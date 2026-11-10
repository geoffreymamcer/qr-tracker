# QR Tracker

Turn any link into a QR code, put your logo in the middle, and see how many people scan it.

People sign up with an email and password. A QR code belongs to the account that made it:
only that account can see its statistics, download its image, or delete it. Scanning a
code never needs an account.

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000, create an account, paste a link, optionally upload a logo, and click **Create QR code**.

## How the scan tracking works

The QR code doesn't contain your link directly. It contains a short tracking link
on this app (`/r/<code>`). When a phone scans it, the app saves the scan
(time, device, OS, browser, and an anonymous visitor ID) and then instantly
redirects to your real link. The person scanning never notices.

**This means the app must be reachable by the phones scanning it.**

- **Testing on your Wi-Fi:** find your PC's local IP (`ipconfig` on Windows),
  then open the app at `http://192.168.x.x:5000` *before* generating codes,
  so the QR points to that address. Phones on the same Wi-Fi can then scan it.
- **Real use (printed flyers, posts):** deploy it so it has a public address
  (see *Deploy to Vercel* below).

## Deploy to Vercel

1. In Vercel, go to **Add New → Project**, import this GitHub repo, and click **Deploy**
   (no build settings to change; Vercel detects the Flask `app` in `app.py`).
2. Open the project, go to **Storage**, choose **Neon (Postgres)**, create a free database, and connect it
   to the project. That sets `DATABASE_URL` for you.
3. In **Settings → Environment Variables**, add:
   - `QR_SALT`: any long random text (it anonymizes visitor IPs)
   - `PUBLIC_BASE_URL`: your final address, e.g. `https://qr-tracker.vercel.app`
4. **Redeploy** (Deployments → ⋯ → Redeploy) so the new variables take effect.

Without step 2 the app still runs, but it shows a red warning and data is lost,
because Vercel's disk is temporary. Locally, with no `DATABASE_URL`, it uses a
SQLite file instead.

> If you move the app to a new address later, codes you already printed still point
> to the old one — so pick your final address before printing.

## Analytics you get

- Total scans and unique scanners
- Scans per day (last 30 days)
- Breakdown by device, operating system, and browser/app
- The 25 most recent scans

Raw IP addresses are never stored — only a salted hash used to count unique
visitors. Set your own `QR_SALT` environment variable in production.

## Accounts and security

- Passwords are stored hashed (PBKDF2-SHA256), never in readable form.
- Statistics, QR images and delete are limited to the account that created the code.
  Anyone else gets "Page not found".
- Every form carries a per-session token, so other websites can't submit forms for a logged-in user.
- After 10 failed log-ins in 15 minutes, further attempts from that address are paused.
- The key that signs log-in cookies is created automatically and kept in the database.
  To manage it yourself, set a `SECRET_KEY` environment variable.
- Codes made before accounts existed are given to the **first account that signs up**.
- There is no password reset or email verification yet; both need an email-sending service.

## Logo tips

- The QR uses the highest error-correction level (H), and the logo is capped at
  about 22% of the width, so it stays scannable.
- Square logos with a transparent background look best.
- Always test-scan with a couple of phones before printing.

## Files

- `app.py`: the whole app (Flask; Postgres when `DATABASE_URL` is set, SQLite otherwise)
- `templates/`: the pages
- Logos are stored in the database, so nothing depends on the server's disk
