"""
QR Tracker — turn a link into a QR code (optionally with a logo in the center)
and count how many people scan it.

How tracking works:
  The QR code does NOT contain your link directly. It contains a short link on
  this server (e.g. https://yourserver.com/r/ab12cd). When someone scans it,
  this server records the scan and immediately redirects them to your real link.
"""
import hashlib
import io
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import qrcode
from flask import (Flask, abort, g, redirect, render_template, request,
                   send_file, url_for)
from PIL import Image, ImageDraw
from qrcode.constants import ERROR_CORRECT_H

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

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # 4 MB (Vercel's request limit is 4.5 MB)


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


@app.context_processor
def inject_flags():
    return {"no_persistent_db": NO_PERSISTENT_DB}


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn:
        conn.close()


SCHEMA = """
    CREATE TABLE IF NOT EXISTS codes (
        id          {pk},
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
    CREATE INDEX IF NOT EXISTS idx_scans_code ON scans(code_id, scanned_at)
"""


def init_db():
    if USE_PG:
        sql = SCHEMA.format(pk="SERIAL PRIMARY KEY", blob="BYTEA")
    else:
        sql = SCHEMA.format(pk="INTEGER PRIMARY KEY AUTOINCREMENT", blob="BLOB")
    conn = DB()
    for stmt in sql.split(";"):
        if stmt.strip():
            conn.execute(stmt)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- helpers
def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_url(url):
    url = (url or "").strip()
    if url and not urlparse(url).scheme:
        url = "https://" + url
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    return url


def public_base():
    return PUBLIC_BASE_URL or request.host_url.rstrip("/")


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
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    ip = ip.split(",")[0].strip()
    raw = f"{SALT}|{ip}|{request.headers.get('User-Agent', '')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def hex_to_rgb(h, fallback):
    h = (h or "").lstrip("#")
    try:
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    except (ValueError, IndexError):
        return fallback


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


def get_code(slug):
    row = db().execute("SELECT * FROM codes WHERE slug = ?", (slug,)).fetchone()
    if not row:
        abort(404)
    return row


# ---------------------------------------------------------------- routes
@app.route("/", methods=["GET", "POST"])
def index():
    error = None
    if request.method == "POST":
        target = normalize_url(request.form.get("url"))
        if not target:
            error = "Please enter a valid link (e.g. https://example.com)."
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
                    error = "That logo file couldn't be read. Use PNG, JPG or WEBP."
            if not error:
                db().execute(
                    "INSERT INTO codes (slug, name, target_url, logo_png, fg_color, bg_color, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (slug, (request.form.get("name") or "").strip() or None, target,
                     logo_png, request.form.get("fg") or "#000000",
                     request.form.get("bg") or "#ffffff", now_iso()))
                db().commit()
                return redirect(url_for("stats", slug=slug))

    codes = db().execute("""
        SELECT c.id, c.slug, c.name, c.target_url, c.created_at,
               COUNT(s.id) AS total, COUNT(DISTINCT s.visitor) AS uniques,
               MAX(s.scanned_at) AS last_scan
        FROM codes c LEFT JOIN scans s ON s.code_id = c.id
        GROUP BY c.id ORDER BY c.id DESC
    """).fetchall()
    return render_template("index.html", codes=codes, error=error)


@app.route("/r/<slug>")
def track(slug):
    """The address inside the QR code: log the scan, then redirect."""
    code = get_code(slug)
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
    code = get_code(slug)
    img = make_qr_image(f"{public_base()}/r/{slug}", code["logo_png"],
                        code["fg_color"], code["bg_color"])
    buf = io.BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    download = request.args.get("download") == "1"
    return send_file(buf, mimetype="image/png", as_attachment=download,
                     download_name=f"qr-{slug}.png")


@app.route("/stats/<slug>")
def stats(slug):
    code = get_code(slug)
    q = lambda sql, *a: db().execute(sql, (code["id"], *a)).fetchall()

    totals = db().execute(
        "SELECT COUNT(*) AS total, COUNT(DISTINCT visitor) AS uniques,"
        " MAX(scanned_at) AS last_scan FROM scans WHERE code_id = ?",
        (code["id"],)).fetchone()

    # Last 30 days, filling empty days with 0
    since = (datetime.now(timezone.utc) - timedelta(days=29)).date()
    per_day = {r["d"]: r["n"] for r in q(
        "SELECT substr(scanned_at,1,10) AS d, COUNT(*) AS n FROM scans"
        " WHERE code_id = ? AND scanned_at >= ? GROUP BY d", since.isoformat())}
    days = [(since + timedelta(days=i)).isoformat() for i in range(30)]
    daily = [{"day": d, "n": per_day.get(d, 0)} for d in days]

    breakdown = {
        col: q(f"SELECT {col} AS label, COUNT(*) AS n FROM scans WHERE code_id = ?"
               f" GROUP BY {col} ORDER BY n DESC")
        for col in ("device", "os", "browser")
    }
    recent = q("SELECT * FROM scans WHERE code_id = ? ORDER BY id DESC LIMIT 25")

    return render_template(
        "stats.html", code=code, totals=totals, daily=daily,
        max_day=max([d["n"] for d in daily] + [1]), breakdown=breakdown,
        recent=recent, short_url=f"{public_base()}/r/{slug}")


@app.post("/delete/<slug>")
def delete(slug):
    code = get_code(slug)
    db().execute("DELETE FROM scans WHERE code_id = ?", (code["id"],))
    db().execute("DELETE FROM codes WHERE id = ?", (code["id"],))
    db().commit()
    return redirect(url_for("index"))


init_db()

if __name__ == "__main__":
    # host 0.0.0.0 lets phones on the same Wi-Fi reach it for testing
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
