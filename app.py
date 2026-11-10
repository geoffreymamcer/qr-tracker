"""
QR Tracker — turn a link into a QR code (optionally with a logo in the center)
and count how many people scan it.

How tracking works:
  The QR code does NOT contain your link directly. It contains a short link on
  this server (e.g. https://yourserver.com/r/ab12cd). When someone scans it,
  this server records the scan and immediately redirects them to your real link.

Accounts:
  People sign up with an email and password. A QR code belongs to the account
  that created it: only that account can see its statistics, download its
  image, or delete it. Scanning a code never needs an account.
"""
import hashlib
import io
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse

import qrcode
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from PIL import Image, ImageDraw
from qrcode.constants import ERROR_CORRECT_H
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Postgres when deployed (Vercel + Neon sets DATABASE_URL / POSTGRES_URL),
# otherwise a local SQLite file.
DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
USE_PG = bool(DATABASE_URL)
ON_VERCEL = bool(os.environ.get("VERCEL"))
# Vercel's filesystem is read-only except /tmp (and /tmp is wiped often),
# so SQLite there is only a temporary fallback until Postgres is connected.
_default_sqlite = "/tmp/qr_tracker.db" if ON_VERCEL else os.path.join(BASE_DIR, "qr_tracker.db")
DB_PATH = os.environ.get("QR_DB", _default_sqlite)
NO_PERSISTENT_DB = ON_VERCEL and not USE_PG
# Public address people's phones will reach, e.g. https://qr.mysite.com
# If not set, the address you opened the app with is used.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
SALT = os.environ.get("QR_SALT", "change-me")  # used to anonymize IPs

PASSWORD_MIN = 8
PASSWORD_MAX = 200
PASSWORD_METHOD = "pbkdf2:sha256:600000"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Failed log-ins allowed per 15 minutes before we pause further attempts
MAX_FAILS_PER_IP = 10
MAX_FAILS_PER_EMAIL = 20
FAIL_WINDOW = timedelta(minutes=15)

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,  # 4 MB (Vercel's request limit is 4.5 MB)
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=ON_VERCEL,     # HTTPS-only cookie when deployed
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)


# ---------------------------------------------------------------- database
class DB:
    """Tiny wrapper so the same SQL ('?' placeholders) runs on SQLite and Postgres."""

    def __init__(self):
        if USE_PG:
            import psycopg
            from psycopg.rows import dict_row
            self.conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        else:
            self.conn = sqlite3.connect(DB_PATH)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")

    def execute(self, sql, params=()):
        if USE_PG:
            sql = sql.replace("?", "%s")
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


def db():
    if "db" not in g:
        g.db = DB()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn:
        conn.close()


SCHEMA = """
    CREATE TABLE IF NOT EXISTS users (
        id            {pk},
        email         TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at    TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS codes (
        id          {pk},
        user_id     INTEGER REFERENCES users(id),
        slug        TEXT UNIQUE NOT NULL,
        name        TEXT,
        target_url  TEXT NOT NULL,
        logo_png    {blob},
        fg_color    TEXT DEFAULT '#000000',
        bg_color    TEXT DEFAULT '#ffffff',
        created_at  TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scans (
        id          {pk},
        code_id     INTEGER NOT NULL REFERENCES codes(id) ON DELETE CASCADE,
        scanned_at  TEXT NOT NULL,
        visitor     TEXT,
        device      TEXT,
        os          TEXT,
        browser     TEXT,
        referrer    TEXT
    );
    CREATE TABLE IF NOT EXISTS settings (
        name  TEXT PRIMARY KEY,
        val   TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS login_fails (
        id   {pk},
        who  TEXT NOT NULL,
        at   TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_scans_code ON scans(code_id, scanned_at);
    CREATE INDEX IF NOT EXISTS idx_login_fails ON login_fails(who, at)
"""


def init_db():
    """Create tables, and upgrade databases made by earlier versions."""
    if USE_PG:
        sql = SCHEMA.format(pk="SERIAL PRIMARY KEY", blob="BYTEA")
    else:
        sql = SCHEMA.format(pk="INTEGER PRIMARY KEY AUTOINCREMENT", blob="BLOB")
    conn = DB()
    for stmt in sql.split(";"):
        if stmt.strip():
            conn.execute(stmt)

    # Upgrades: codes made before accounts existed have no owner column
    if USE_PG:
        conn.execute("ALTER TABLE codes ADD COLUMN IF NOT EXISTS"
                     " user_id INTEGER REFERENCES users(id)")
    else:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(codes)").fetchall()}
        if "user_id" not in cols:
            conn.execute("ALTER TABLE codes ADD COLUMN user_id INTEGER REFERENCES users(id)")
        if "logo_png" not in cols:  # very first version kept logos as files
            conn.execute("ALTER TABLE codes ADD COLUMN logo_png BLOB")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_codes_user ON codes(user_id)")
    conn.commit()
    conn.close()


def load_secret_key():
    """Key that signs log-in cookies. Uses SECRET_KEY if set; otherwise a random
    key is created once and kept in the database, so there is nothing to configure."""
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    conn = DB()
    conn.execute("INSERT INTO settings (name, val) VALUES (?, ?) ON CONFLICT (name) DO NOTHING",
                 ("secret_key", secrets.token_hex(32)))
    conn.commit()
    key = conn.execute("SELECT val FROM settings WHERE name = ?", ("secret_key",)).fetchone()["val"]
    conn.close()
    return key


# ---------------------------------------------------------------- helpers
def now_utc():
    return datetime.now(timezone.utc)


def now_iso():
    return now_utc().isoformat(timespec="seconds")


def normalize_url(url):
    url = (url or "").strip()
    if url and not urlparse(url).scheme:
        url = "https://" + url
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.netloc or len(url) > 2000:
        return None
    return url


def public_base():
    return PUBLIC_BASE_URL or request.host_url.rstrip("/")


def client_ip():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    return ip.split(",")[0].strip()


def hashed(*parts):
    raw = "|".join((SALT,) + parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def parse_user_agent(ua):
    ua_l = (ua or "").lower()
    if "ipad" in ua_l or "tablet" in ua_l:
        device = "Tablet"
    elif any(k in ua_l for k in ("mobi", "iphone", "android")):
        device = "Mobile"
    elif ua_l:
        device = "Desktop"
    else:
        device = "Unknown"

    if "iphone" in ua_l or "ipad" in ua_l or "ios" in ua_l:
        os_name = "iOS"
    elif "android" in ua_l:
        os_name = "Android"
    elif "windows" in ua_l:
        os_name = "Windows"
    elif "mac os" in ua_l or "macintosh" in ua_l:
        os_name = "macOS"
    elif "linux" in ua_l:
        os_name = "Linux"
    else:
        os_name = "Other"

    if "edg/" in ua_l:
        browser = "Edge"
    elif "fbav" in ua_l or "fban" in ua_l:
        browser = "Facebook app"
    elif "instagram" in ua_l:
        browser = "Instagram app"
    elif "samsungbrowser" in ua_l:
        browser = "Samsung Internet"
    elif "chrome" in ua_l or "crios" in ua_l:
        browser = "Chrome"
    elif "firefox" in ua_l or "fxios" in ua_l:
        browser = "Firefox"
    elif "safari" in ua_l:
        browser = "Safari"
    else:
        browser = "Other"
    return device, os_name, browser


def visitor_id():
    """Anonymous visitor fingerprint (hashed IP + user agent), used to count
    unique scanners without storing raw IP addresses."""
    return hashed(client_ip(), request.headers.get("User-Agent", ""))


def hex_to_rgb(h, fallback):
    h = (h or "").lstrip("#")
    try:
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    except (ValueError, IndexError):
        return fallback


def clean_color(value, fallback):
    return value if re.fullmatch(r"#[0-9a-fA-F]{6}", value or "") else fallback


def make_qr_image(data, logo_bytes=None, fg="#000000", bg="#ffffff", box=12):
    # High error correction (H ≈ 30%) so the logo can cover the middle
    qr = qrcode.QRCode(error_correction=ERROR_CORRECT_H, box_size=box, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    fg_rgb = hex_to_rgb(fg, (0, 0, 0))
    bg_rgb = hex_to_rgb(bg, (255, 255, 255))
    img = qr.make_image(fill_color=fg_rgb, back_color=bg_rgb).convert("RGB")

    if logo_bytes:
        logo = Image.open(io.BytesIO(bytes(logo_bytes))).convert("RGBA")
        # Keep the logo at ~22% of the QR width — safely inside what level H can recover
        size = int(img.size[0] * 0.22)
        logo.thumbnail((size, size), Image.LANCZOS)
        # White rounded "pad" behind the logo keeps it readable
        pad = int(size * 0.12)
        pw, ph = logo.size[0] + pad * 2, logo.size[1] + pad * 2
        plate = Image.new("RGBA", (pw, ph), (0, 0, 0, 0))
        ImageDraw.Draw(plate).rounded_rectangle(
            (0, 0, pw - 1, ph - 1), radius=int(pw * 0.18), fill=bg_rgb + (255,))
        plate.paste(logo, (pad, pad), logo)
        pos = ((img.size[0] - pw) // 2, (img.size[1] - ph) // 2)
        img.paste(plate, pos, plate)
    return img


def png_response(img, **kwargs):
    buf = io.BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png", **kwargs)


def brand_mark_png():
    """The site's own mark (a QR 'finder' square), used as the logo in the sample code."""
    s = 240
    im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((0, 0, s - 1, s - 1), radius=44, fill=(14, 90, 67, 255))
    d.rounded_rectangle((44, 44, s - 45, s - 45), radius=18, fill=(255, 255, 255, 255))
    d.rounded_rectangle((82, 82, s - 83, s - 83), radius=8, fill=(14, 90, 67, 255))
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


# ---------------------------------------------------------------- accounts
def current_user():
    if "user" not in g:
        g.user = None
        uid = session.get("uid")
        if uid:
            g.user = db().execute("SELECT id, email FROM users WHERE id = ?", (uid,)).fetchone()
            if not g.user:
                session.clear()
    return g.user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            nxt = request.full_path.rstrip("?") if request.method == "GET" else None
            return redirect(url_for("login", next=nxt))
        return view(*args, **kwargs)
    return wrapped


def start_session(user_id):
    session.clear()            # new session and new form token on every log-in
    session["uid"] = user_id
    session.permanent = True


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def safe_next(target):
    """Only allow redirects back into this site after logging in."""
    if target and target.startswith("/") and not target.startswith(("//", "/\\")):
        return target
    return None


def too_many_fails(who, limit):
    since = (now_utc() - FAIL_WINDOW).isoformat(timespec="seconds")
    n = db().execute("SELECT COUNT(*) AS n FROM login_fails WHERE who = ? AND at >= ?",
                     (who, since)).fetchone()["n"]
    return n >= limit


def record_fail(*whos):
    cutoff = (now_utc() - FAIL_WINDOW).isoformat(timespec="seconds")
    db().execute("DELETE FROM login_fails WHERE at < ?", (cutoff,))
    for who in whos:
        db().execute("INSERT INTO login_fails (who, at) VALUES (?, ?)", (who, now_iso()))
    db().commit()


def get_own_code(slug):
    """The code with this slug, only if the logged-in user created it.
    Anything else is a 404, so nobody can tell which codes exist."""
    user = current_user()
    if not user:
        abort(404)
    row = db().execute("SELECT * FROM codes WHERE slug = ? AND user_id = ?",
                       (slug, user["id"])).fetchone()
    if not row:
        abort(404)
    return row


@app.before_request
def protect_forms():
    # Every form carries a secret token tied to the visitor's session, so another
    # website can't submit forms (delete a code, log out…) on someone's behalf.
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400)


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return resp


@app.context_processor
def inject_globals():
    return {"no_persistent_db": NO_PERSISTENT_DB, "user": current_user(),
            "csrf_token": csrf_token}


ERROR_TEXT = {
    400: ("This form expired", "Go back, refresh the page, and try again."),
    404: ("Page not found", "This page doesn't exist, or it belongs to another account."),
    413: ("That file is too large", "Logos can be up to 4 MB. Go back and choose a smaller image."),
}


@app.errorhandler(HTTPException)
def http_error(e):
    title, detail = ERROR_TEXT.get(e.code, ("Something went wrong", "Go back and try again."))
    return render_template("error.html", title=title, detail=detail), e.code


# ---------------------------------------------------------------- pages
@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/sample-qr.png")
def sample_qr():
    """A real, scannable code for the home page. It opens this site and is not tracked."""
    img = make_qr_image(public_base() + "/", brand_mark_png(), "#10231c", "#ffffff", box=10)
    resp = png_response(img)
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user():
        return redirect(url_for("dashboard"))
    error, email = None, ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        if not EMAIL_RE.match(email) or len(email) > 254:
            error = "Enter a valid email address."
        elif len(password) < PASSWORD_MIN:
            error = f"Use a password with at least {PASSWORD_MIN} characters."
        elif len(password) > PASSWORD_MAX:
            error = f"Use a password shorter than {PASSWORD_MAX} characters."
        elif password != (request.form.get("confirm") or ""):
            error = "The two passwords don't match."
        elif db().execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            error = "An account with this email already exists. Log in instead."
        else:
            db().execute("INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                         (email, generate_password_hash(password, method=PASSWORD_METHOD), now_iso()))
            uid = db().execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()["id"]
            # Codes made before accounts existed go to the first account created
            if db().execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 1:
                db().execute("UPDATE codes SET user_id = ? WHERE user_id IS NULL", (uid,))
            db().commit()
            start_session(uid)
            flash("Your account is ready. Create your first QR code below.")
            return redirect(url_for("dashboard"))
    return render_template("signup.html", error=error, email=email,
                           password_min=PASSWORD_MIN)


# Compared against when the email is unknown, so both cases take the same time
_DUMMY_HASH = generate_password_hash("not-a-real-password", method=PASSWORD_METHOD)


@app.route("/login", methods=["GET", "POST"])
def login():
    nxt = safe_next(request.values.get("next"))
    if current_user():
        return redirect(nxt or url_for("dashboard"))
    error, email, status = None, "", 200
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "")[:PASSWORD_MAX]
        ip_key, email_key = "ip:" + hashed(client_ip()), "em:" + hashed(email)
        if too_many_fails(ip_key, MAX_FAILS_PER_IP) or too_many_fails(email_key, MAX_FAILS_PER_EMAIL):
            error, status = "Too many failed attempts. Wait 15 minutes, then try again.", 429
        else:
            row = db().execute("SELECT id, password_hash FROM users WHERE email = ?",
                               (email,)).fetchone()
            ok = check_password_hash(row["password_hash"] if row else _DUMMY_HASH, password)
            if row and ok:
                start_session(row["id"])
                return redirect(nxt or url_for("dashboard"))
            record_fail(ip_key, email_key)
            error = "That email and password don't match an account."
    return render_template("login.html", error=error, email=email, next=nxt), status


@app.post("/logout")
def logout():
    session.clear()
    flash("You're logged out.")
    return redirect(url_for("index"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    user = current_user()
    error = None
    if request.method == "POST":
        target = normalize_url(request.form.get("url"))
        if not target:
            error = "Enter a valid link, for example https://example.com"
        else:
            slug = secrets.token_urlsafe(5)
            logo_png = None
            f = request.files.get("logo")
            if f and f.filename:
                try:
                    im = Image.open(f.stream)
                    im.load()
                    im = im.convert("RGBA")
                    im.thumbnail((512, 512), Image.LANCZOS)  # plenty for a QR logo
                    buf = io.BytesIO()
                    im.save(buf, "PNG", optimize=True)
                    logo_png = buf.getvalue()
                except Exception:
                    error = "That logo couldn't be read. Use a PNG, JPG or WEBP image."
            if not error:
                db().execute(
                    "INSERT INTO codes (user_id, slug, name, target_url, logo_png, fg_color,"
                    " bg_color, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (user["id"], slug, (request.form.get("name") or "").strip()[:120] or None,
                     target, logo_png, clean_color(request.form.get("fg"), "#000000"),
                     clean_color(request.form.get("bg"), "#ffffff"), now_iso()))
                db().commit()
                flash("QR code created. Download it, then scan it once to test.")
                return redirect(url_for("stats", slug=slug))

    codes = db().execute("""
        SELECT c.id, c.slug, c.name, c.target_url, c.created_at,
               COUNT(s.id) AS total, COUNT(DISTINCT s.visitor) AS uniques,
               MAX(s.scanned_at) AS last_scan
        FROM codes c LEFT JOIN scans s ON s.code_id = c.id
        WHERE c.user_id = ?
        GROUP BY c.id ORDER BY c.id DESC
    """, (user["id"],)).fetchall()
    return render_template("dashboard.html", codes=codes, error=error,
                           form=request.form if error else {})


@app.route("/r/<slug>")
def track(slug):
    """The address inside the QR code: log the scan, then redirect. Public."""
    code = db().execute("SELECT id, target_url FROM codes WHERE slug = ?", (slug,)).fetchone()
    if not code:
        abort(404)
    device, os_name, browser = parse_user_agent(request.headers.get("User-Agent"))
    db().execute(
        "INSERT INTO scans (code_id, scanned_at, visitor, device, os, browser, referrer)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (code["id"], now_iso(), visitor_id(), device, os_name, browser,
         request.referrer))
    db().commit()
    return redirect(code["target_url"], code=302)


@app.route("/qr/<slug>.png")
def qr_png(slug):
    code = get_own_code(slug)
    img = make_qr_image(f"{public_base()}/r/{slug}", code["logo_png"],
                        code["fg_color"], code["bg_color"])
    resp = png_response(img, as_attachment=request.args.get("download") == "1",
                        download_name=f"qr-{slug}.png")
    resp.headers["Cache-Control"] = "private, max-age=300"
    return resp


@app.route("/stats/<slug>")
@login_required
def stats(slug):
    code = get_own_code(slug)
    q = lambda sql, *a: db().execute(sql, (code["id"], *a)).fetchall()

    totals = db().execute(
        "SELECT COUNT(*) AS total, COUNT(DISTINCT visitor) AS uniques,"
        " MAX(scanned_at) AS last_scan FROM scans WHERE code_id = ?",
        (code["id"],)).fetchone()

    # Last 30 days, filling empty days with 0
    since = (now_utc() - timedelta(days=29)).date()
    per_day = {r["d"]: r["n"] for r in q(
        "SELECT substr(scanned_at,1,10) AS d, COUNT(*) AS n FROM scans"
        " WHERE code_id = ? AND scanned_at >= ? GROUP BY d", since.isoformat())}
    days = [(since + timedelta(days=i)).isoformat() for i in range(30)]
    daily = [{"day": d, "n": per_day.get(d, 0),
              "label": datetime.strptime(d, "%Y-%m-%d").strftime("%b %d").replace(" 0", " ")}
             for d in days]

    breakdown = {
        col: q(f"SELECT {col} AS label, COUNT(*) AS n FROM scans WHERE code_id = ?"
               f" GROUP BY {col} ORDER BY n DESC")
        for col in ("device", "os", "browser")
    }
    recent = q("SELECT * FROM scans WHERE code_id = ? ORDER BY scanned_at DESC, id DESC LIMIT 15")

    return render_template(
        "stats.html", code=code, totals=totals, daily=daily,
        max_day=max([d["n"] for d in daily] + [1]), breakdown=breakdown,
        recent=recent, short_url=f"{public_base()}/r/{slug}")


@app.post("/delete/<slug>")
@login_required
def delete(slug):
    code = get_own_code(slug)
    db().execute("DELETE FROM scans WHERE code_id = ?", (code["id"],))
    db().execute("DELETE FROM codes WHERE id = ?", (code["id"],))
    db().commit()
    flash(f"Deleted “{code['name'] or code['slug']}” and its scan history.")
    return redirect(url_for("dashboard"))


init_db()
app.secret_key = load_secret_key()

if __name__ == "__main__":
    # host 0.0.0.0 lets phones on the same Wi-Fi reach it for testing
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG") == "1")
