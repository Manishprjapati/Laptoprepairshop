from datetime import datetime, timedelta
from functools import wraps
import hmac
import os
import re
import secrets
import sqlite3

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from markupsafe import Markup

app = Flask(__name__)

# ==========================================
# APP CONFIGURATION
# ==========================================
app.config.update(
    # Fixed Secret Key so sessions don't expire automatically on server restart
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", "ghaziabad_laptop_repair_secret_key_v1_secure"),
    MAX_CONTENT_LENGTH=3 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
)
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
LOGIN_ATTEMPTS = {}
PHONE_RE = re.compile(r"^[0-9+()\-\s]{8,20}$")


# ==========================================
# DATABASE & SECURITY FUNCTIONS
# ==========================================
def get_db():
    conn = sqlite3.connect(os.path.join(app.root_path, "database.db"))
    conn.row_factory = sqlite3.Row
    return conn


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.context_processor
def inject_security_helpers():
    return {
        "csrf_token": csrf_token,
        "csrf_field": lambda: Markup('<input type="hidden" name="csrf_token" value="%s">' % csrf_token())
    }


@app.before_request
def protect_requests():
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(submitted, expected):
            abort(400, "Invalid or expired form token. Please refresh and try again.")


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store" if session.get("admin_logged_in") else "no-cache"
    return response


def init_db():
    with get_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS bookings
                        (
                            id
                            INTEGER
                            PRIMARY
                            KEY
                            AUTOINCREMENT,
                            name
                            TEXT
                            NOT
                            NULL,
                            phone
                            TEXT
                            NOT
                            NULL,
                            device
                            TEXT
                            NOT
                            NULL,
                            service_mode
                            TEXT
                            NOT
                            NULL,
                            address
                            TEXT
                            NOT
                            NULL,
                            problem
                            TEXT
                            NOT
                            NULL
                        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS feedback
                        (
                            id
                            INTEGER
                            PRIMARY
                            KEY
                            AUTOINCREMENT,
                            name
                            TEXT
                            NOT
                            NULL,
                            rating
                            TEXT
                            NOT
                            NULL,
                            review
                            TEXT
                            NOT
                            NULL
                        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS admin
                        (
                            id
                            INTEGER
                            PRIMARY
                            KEY
                            AUTOINCREMENT,
                            username
                            TEXT
                            UNIQUE
                            NOT
                            NULL,
                            password
                            TEXT
                            NOT
                            NULL,
                            recovery_key
                            TEXT
                            NOT
                            NULL
                        )""")

        for admin in conn.execute("SELECT id, password, recovery_key FROM admin").fetchall():
            password = admin["password"]
            recovery_key = admin["recovery_key"]
            if not password.startswith(("pbkdf2:", "scrypt:")):
                conn.execute("UPDATE admin SET password=? WHERE id=?", (generate_password_hash(password), admin["id"]))
            if not recovery_key.startswith(("pbkdf2:", "scrypt:")):
                conn.execute("UPDATE admin SET recovery_key=? WHERE id=?",
                             (generate_password_hash(recovery_key), admin["id"]))

        if not conn.execute("SELECT 1 FROM admin LIMIT 1").fetchone():
            username = os.environ.get("ADMIN_INITIAL_USERNAME")
            password = os.environ.get("ADMIN_INITIAL_PASSWORD")
            recovery_key = os.environ.get("ADMIN_RECOVERY_KEY")
            if username and password and recovery_key:
                conn.execute("INSERT INTO admin (username,password,recovery_key) VALUES (?,?,?)",
                             (username, generate_password_hash(password), generate_password_hash(recovery_key)))


def require_admin(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def clean_text(value, maximum, minimum=1):
    value = " ".join((value or "").strip().split())
    return value if minimum <= len(value) <= maximum else None


def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


# ==========================================
# DYNAMIC SERVICES DATA
# ==========================================
repair_services = [
    {
        "slug": "custom-pc-build", "name": "Custom PC Build", "desc": "High-performance custom PC building.",
        "icon": "fas fa-desktop",
        "details": "We build custom high-performance PCs tailored to your work, play and creativity.",
        "features": [
            {'title': 'Gaming PC Build',
             'text': 'High FPS gaming setups with RGB, liquid cooling, and powerful Graphic Cards.'},
            {'title': 'Office & Home Workstation',
             'text': 'Reliable, fast, and budget-friendly PCs for day-to-day office work or study.'},
            {'title': 'Video Editing & Graphic Design',
             'text': 'Heavy rendering machines for Premiere Pro, After Effects, AutoCAD, and 3D modeling.'},
            {'title': 'Multi-OS & Software Setup',
             'text': 'Windows 10/11, Linux (Ubuntu/Kali), or Dual Boot setups with all necessary softwares.'}
        ]
    },
    {
        "slug": "laptop-repair", "name": "Laptop Repair", "desc": "Hardware and software solutions.",
        "icon": "fas fa-laptop-medical",
        "details": "Complete diagnosis and repair for all major laptop brands.",
        "features": [
            {'title': 'Hardware Fixing', 'text': 'Keyboard, Touchpad, Battery, and Speaker replacements.'},
            {'title': 'Overheating Issues', 'text': 'Laptop cleaning, thermal paste replacement, and fan repair.'},
            {'title': 'Body & Hinge Repair', 'text': 'Broken laptop body fabrication and tight hinge loosening.'},
            {'title': 'Power Issues', 'text': 'Laptop not turning on or battery not charging solutions.'}
        ]
    },
    {
        "slug": "tv-repair", "name": "LED/LCD TV Repair", "desc": "Expert repair for Smart TVs.", "icon": "fas fa-tv",
        "details": "Display, backlight, motherboard and audio solutions for Smart and Android TVs.",
        "features": [
            {'title': 'Backlight Replacement',
             'text': 'Fixing sound-but-no-picture issues by replacing faulty LED backlights.'},
            {'title': 'Motherboard Repair', 'text': 'Resolving power issues, HDMI port faults, and dead TV problems.'},
            {'title': 'Display Panel Issues',
             'text': 'Solutions for screen lines, color distortion, or double image issues.'},
            {'title': 'Smart TV Software',
             'text': 'Fixing software glitches, stuck-on-logo, and WiFi connectivity problems.'}
        ]
    },
    {
        "slug": "accessories", "name": "Accessories",
        "desc": "Batteries, chargers, keyboards and more.", "icon": "fas fa-keyboard",
        "details": "Best quality batteries, adapters, SSD upgrades and replacement keyboards.",
        "features": [
            {'title': 'Batteries & Chargers',
             'text': 'Original and compatible adapters and long-lasting batteries for all brands.'},
            {'title': 'Keyboards & Mice', 'text': 'Internal laptop keyboards and external wireless/wired combo sets.'},
            {'title': 'Storage & Memory',
             'text': 'High-speed NVMe/SATA SSDs, HDDs, and RAM upgrades for smooth performance.'},
            {'title': 'Other Components', 'text': 'Cooling pads, laptop screens, display cables, and Wi-Fi cards.'}
        ]
    },
    {
        "slug": "chip-level-repairing", "name": "Chip Level Repairing", "desc": "Advanced motherboard repair.",
        "icon": "fas fa-microchip",
        "details": "Advanced board-level repair for liquid damage, short circuits, IC replacements and power-section faults.",
        "features": [
            {'title': 'Motherboard Dead Issue',
             'text': 'Step-by-step IC level tracing and repairing for dead motherboards.'},
            {'title': 'Liquid/Water Damage',
             'text': 'Chemical wash and short-circuit repair for tea/coffee or water spills.'},
            {'title': 'Display Graphic IC',
             'text': 'Fixing dim display, no display, or white screen issues from the motherboard.'},
            {'title': 'Port Repairing', 'text': 'Broken USB, HDMI, Charging jack, or Audio jack replacement.'}
        ]
    },
    {
        "slug": "display-replacement", "name": "Display Replacement", "desc": "High-quality screen replacement.",
        "icon": "fas fa-tablet-alt",
        "details": "Fast, safe replacement for cracked or damaged laptop and monitor displays with quality-tested panels.",
        "features": [
            {'title': 'Laptop Screen Replacement',
             'text': 'HD, FHD, and IPS display panels for Dell, HP, Lenovo, Mac, etc.'},
            {'title': 'Broken Glass Fix', 'text': 'Fixing physically damaged or cracked laptop and monitor screens.'},
            {'title': 'Flickering/Line Issues',
             'text': 'Screen cable (flex cable) replacement and display flickering fixes.'},
            {'title': 'Touch Screen Repair', 'text': 'Replacement of touch digitizers for 2-in-1 convertible laptops.'}
        ]
    },
    {
        "slug": "printer-repair", "name": "Printer Repair", "desc": "Laser printer servicing.", "icon": "fas fa-print",
        "details": "Professional diagnosis for paper jams, print-quality issues and offline errors across leading printer brands.",
        "features": [
            {'title': 'Paper Jam Solutions',
             'text': 'Resolving roller, gear, and sensor issues causing frequent paper jams.'},
            {'title': 'Ink & Toner Issues',
             'text': 'Fixing faded prints, blank pages, and replacing empty toner cartridges.'},
            {'title': 'Hardware & Power Fix',
             'text': 'Repairing dead printers, scanner faults, and logic board issues.'},
            {'title': 'Network & Connectivity',
             'text': 'Setup and troubleshooting for Wi-Fi, LAN, and USB printer connections.'}
        ]
    },
    {
        "slug": "cctv-installation", "name": "CCTV Installation", "desc": "CCTV setup and maintenance.",
        "icon": "fas fa-video",
        "details": "Secure home and business camera setup with reliable installation, cabling and mobile monitoring configuration.",
        "features": [
            {'title': 'Home & Office Setup',
             'text': 'Professional installation of HD and IP cameras tailored for your security.'},
            {'title': 'DVR/NVR Configuration',
             'text': 'Setup of recording devices with adequate hard drive storage for long backups.'},
            {'title': 'Mobile Monitoring',
             'text': 'Configure your CCTV setup to view live footage directly on your smartphone.'},
            {'title': 'Repair & Maintenance',
             'text': 'Fixing blurry vision, night-vision failure, cut wires, and power supply issues.'}
        ]
    }
]


# ==========================================
# PUBLIC ROUTES
# ==========================================
@app.route("/")
def home():
    with get_db() as conn:
        reviews = conn.execute("SELECT name, rating, review FROM feedback ORDER BY id DESC LIMIT 6").fetchall()
    return render_template("index.html", services=repair_services, reviews=reviews)


@app.route("/about")
def about():
    has_founder_dp = os.path.exists(os.path.join(UPLOAD_FOLDER, "founder_dp.jpg"))
    return render_template("about.html", has_founder_dp=has_founder_dp, t=int(datetime.utcnow().timestamp()))


@app.route("/service/<slug>")
def service_detail(slug):
    service = next((item for item in repair_services if item["slug"] == slug), None)
    if not service:
        abort(404)
    return render_template("service.html", service=service)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = clean_text(request.form.get("name"), 80, 2)
        phone = clean_text(request.form.get("phone"), 20, 8)
        device = request.form.get("device")
        mode = request.form.get("serviceMode")
        address = clean_text(request.form.get("address"), 250, 5)
        problem = clean_text(request.form.get("problem"), 1000, 5)

        valid_devices = {"Laptop", "Desktop PC", "Smart TV", "Printer", "CCTV", "Other"}
        valid_modes = {"Store Visit", "Home Pickup"}

        if not all((name, phone, address, problem)) or not PHONE_RE.fullmatch(
                phone) or device not in valid_devices or mode not in valid_modes:
            flash("Please check the submitted details and try again.", "error")
        else:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO bookings (name,phone,device,service_mode,address,problem) VALUES (?,?,?,?,?,?)",
                    (name, phone, device, mode, address, problem)
                )
            flash("Your repair request was received. Our team will contact you soon.", "success")
            return redirect(url_for("contact"))

    return render_template("contact.html")


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        name = clean_text(request.form.get("customer_name"), 50, 3)
        review = clean_text(request.form.get("review"), 1200, 10)
        rating = request.form.get("rating")

        if not name or not re.fullmatch(r"[A-Za-z ]+", name) or not review or rating not in {"1", "2", "3", "4", "5"}:
            flash("Please provide a valid name, rating and review.", "error")
        else:
            with get_db() as conn:
                conn.execute("INSERT INTO feedback (name,rating,review) VALUES (?,?,?)", (name, rating, review))
            flash("Thank you—your feedback has been submitted.", "success")
            return redirect(url_for("feedback"))

    return render_template("Feedback.html")


# ==========================================
# AUTHENTICATION ROUTES
# ==========================================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        address = request.remote_addr or "unknown"
        now = datetime.utcnow()
        attempts = [t for t in LOGIN_ATTEMPTS.get(address, []) if now - t < timedelta(minutes=15)]

        if len(attempts) >= 5:
            error = "Too many attempts. Please wait 15 minutes before trying again."
        else:
            username = clean_text(request.form.get("username"), 80)
            password = request.form.get("password", "")

            with get_db() as conn:
                admin = conn.execute("SELECT * FROM admin WHERE username=?",
                                     (username,)).fetchone() if username else None

            if admin and check_password_hash(admin["password"], password):
                session.clear()
                session["admin_logged_in"] = True
                session["admin_id"] = admin["id"]
                csrf_token()
                LOGIN_ATTEMPTS.pop(address, None)
                return redirect(url_for("admin"))

            attempts.append(now)
            LOGIN_ATTEMPTS[address] = attempts
            error = "Invalid username or password."

    return render_template("Login.html", error=error)


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    error = success = None
    if request.method == "POST":
        username = clean_text(request.form.get("username"), 80)
        recovery = request.form.get("recovery_key", "")
        password = request.form.get("new_password", "")

        with get_db() as conn:
            admin = conn.execute("SELECT * FROM admin WHERE username=?", (username,)).fetchone() if username else None

        if not admin or not check_password_hash(admin["recovery_key"], recovery):
            error = "Unable to verify the recovery details."
        elif len(password) < 12:
            error = "Use a password with at least 12 characters."
        else:
            with get_db() as conn:
                conn.execute("UPDATE admin SET password=? WHERE id=?", (generate_password_hash(password), admin["id"]))
            success = "Password updated. You can now sign in."

    return render_template("forgot_password.html", error=error, success=success)


@app.post("/logout")
@require_admin
def logout():
    session.clear()
    return redirect(url_for("home"))


# ==========================================
# ADMIN ROUTES
# ==========================================
@app.route("/admin")
@require_admin
def admin():
    with get_db() as conn:
        bookings = conn.execute("SELECT * FROM bookings ORDER BY id DESC").fetchall()
        feedbacks = conn.execute("SELECT * FROM feedback ORDER BY id DESC").fetchall()

    has_dp = os.path.exists(os.path.join(UPLOAD_FOLDER, "admin_dp.jpg"))
    has_founder_dp = os.path.exists(os.path.join(UPLOAD_FOLDER, "founder_dp.jpg"))

    return render_template("admin.html", bookings=bookings, feedbacks=feedbacks,
                           has_dp=has_dp, has_founder_dp=has_founder_dp,
                           t=int(datetime.utcnow().timestamp()))


@app.post("/delete_booking/<int:id>")
@require_admin
def delete_booking(id):
    with get_db() as conn:
        conn.execute("DELETE FROM bookings WHERE id=?", (id,))
    flash("Booking deleted.", "success")
    return redirect(url_for("admin"))


@app.post("/delete_feedback/<int:id>")
@require_admin
def delete_feedback(id):
    with get_db() as conn:
        conn.execute("DELETE FROM feedback WHERE id=?", (id,))
    flash("Feedback deleted.", "success")
    return redirect(url_for("admin"))


@app.post("/update_dp")
@require_admin
def update_dp():
    file = request.files.get("profile_pic")
    if not file or not file.filename or not allowed_image(file.filename):
        flash("Upload a PNG, JPG, JPEG or WEBP image only.", "error")
    else:
        filename = secure_filename(file.filename)
        if not filename:
            abort(400)
        file.save(os.path.join(UPLOAD_FOLDER, "admin_dp.jpg"))
        flash("Profile photo updated.", "success")
    return redirect(url_for("admin"))


@app.post("/delete_dp")
@require_admin
def delete_dp():
    filepath = os.path.join(UPLOAD_FOLDER, "admin_dp.jpg")
    if os.path.exists(filepath):
        os.remove(filepath)
    flash("Profile photo removed.", "success")
    return redirect(url_for("admin"))


@app.post("/update_founder_dp")
@require_admin
def update_founder_dp():
    file = request.files.get("founder_pic")
    if not file or not file.filename or not allowed_image(file.filename):
        flash("Upload a PNG, JPG, JPEG or WEBP image only.", "error")
    else:
        filename = secure_filename(file.filename)
        if not filename:
            abort(400)
        file.save(os.path.join(UPLOAD_FOLDER, "founder_dp.jpg"))
        flash("About page founder photo updated.", "success")
    return redirect(url_for("admin"))


@app.post("/delete_founder_dp")
@require_admin
def delete_founder_dp():
    filepath = os.path.join(UPLOAD_FOLDER, "founder_dp.jpg")
    if os.path.exists(filepath):
        os.remove(filepath)
    flash("About page founder photo removed.", "success")
    return redirect(url_for("admin"))


@app.errorhandler(413)
def too_large(error):
    return "Upload is too large. Maximum allowed size is 3 MB.", 413


# Initialize Database
init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1" and os.environ.get("FLASK_ENV") != "production")