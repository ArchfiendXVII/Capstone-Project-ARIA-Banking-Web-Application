from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from functools import wraps
from uuid import uuid4

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from transfer_service import process_transfer

from compliance.routes import compliance_bp


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "aria_bank.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = "aria-bank-dev-secret"
app.register_blueprint(compliance_bp)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_: Exception | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query_one(sql: str, args: tuple = ()) -> sqlite3.Row | None:
    return get_db().execute(sql, args).fetchone()


def query_all(sql: str, args: tuple = ()) -> list[sqlite3.Row]:
    return get_db().execute(sql, args).fetchall()


def execute(sql: str, args: tuple = ()) -> None:
    db = get_db()
    db.execute(sql, args)
    db.commit()


def current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    return query_one("SELECT * FROM users WHERE id = ?", (user_id,))


@app.context_processor
def inject_globals() -> dict:
    return {"current_user": current_user()}


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def staff_or_admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        if user["role"] not in ("staff", "admin"):
            log_event(
                user["id"],
                "UNAUTHORIZED_ACCESS_ATTEMPT",
                f"Blocked access attempt to {request.path}",
                "High",
            )
            abort(403)
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        if user["role"] != "admin":
            log_event(
                user["id"],
                "UNAUTHORIZED_ACCESS_ATTEMPT",
                f"Blocked admin-only access attempt to {request.path}",
                "High",
            )
            abort(403)
        return view(*args, **kwargs)

    return wrapped_view


def log_event(
    user_id: int | None,
    event_type: str,
    description: str,
    severity: str | None = "Low",
    include_ip: bool = True,
) -> None:
    ip_address = request.remote_addr if include_ip and request else None
    get_db().execute(
        """
        INSERT INTO audit_logs (timestamp, user_id, event_type, description, ip_address, severity)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (datetime.utcnow().isoformat(timespec="seconds"), user_id, event_type, description, ip_address, severity),
    )
    get_db().commit()


def _table_columns(db: sqlite3.Connection, table: str) -> set[str]:
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return {row[1] for row in rows}


def _ensure_column(db: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    if column not in _table_columns(db, table):
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def migrate_schema() -> None:
    db = get_db()
    _ensure_column(db, "accounts", "balance_cents", "INTEGER")
    _ensure_column(db, "transactions", "amount_cents", "INTEGER")
    db.execute(
        """
        UPDATE accounts
        SET balance_cents = CAST(ROUND(balance * 100) AS INTEGER)
        WHERE balance_cents IS NULL
        """
    )
    db.execute(
        """
        UPDATE transactions
        SET amount_cents = CAST(ROUND(amount * 100) AS INTEGER)
        WHERE amount_cents IS NULL
        """
    )
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS rejected_transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            sender_account_id INTEGER NOT NULL,
            recipient_lookup TEXT,
            recipient_account_id INTEGER,
            amount_cents INTEGER,
            idempotency_key TEXT,
            reason_code TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'rejected',
            request_context TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (sender_account_id) REFERENCES accounts (id)
        );

        CREATE TABLE IF NOT EXISTS transfer_idempotency (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_account_id INTEGER NOT NULL,
            idempotency_key TEXT NOT NULL,
            recipient_account_id INTEGER,
            amount_cents INTEGER,
            description TEXT,
            status TEXT NOT NULL,
            transaction_id INTEGER,
            created_at TEXT NOT NULL,
            UNIQUE(sender_account_id, idempotency_key),
            FOREIGN KEY (sender_account_id) REFERENCES accounts (id),
            FOREIGN KEY (transaction_id) REFERENCES transactions (id)
        );

        CREATE TABLE IF NOT EXISTS compliance_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_timestamp TEXT NOT NULL,
            scan_type TEXT NOT NULL DEFAULT 'manual',
            triggered_by INTEGER,
            kpi_snapshot TEXT NOT NULL,
            check_results TEXT NOT NULL,
            tool_results TEXT,
            compliance_score_owasp REAL,
            compliance_score_iso REAL,
            compliance_score_nist REAL,
            compliance_score_gdpr REAL,
            findings_open INTEGER,
            findings_resolved INTEGER,
            iteration_count INTEGER DEFAULT 0,
            shared_state TEXT,
            status TEXT NOT NULL DEFAULT 'completed',
            FOREIGN KEY (triggered_by) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS compliance_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            report_markdown TEXT NOT NULL,
            verdicts_json TEXT,
            disclosure_gaps_json TEXT,
            llm_model TEXT,
            human_reviewed INTEGER NOT NULL DEFAULT 0,
            reviewed_by INTEGER,
            reviewed_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES compliance_scans (id),
            FOREIGN KEY (reviewed_by) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS compliance_control_verdicts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_id TEXT NOT NULL,
            scan_id INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            score REAL,
            evidence_json TEXT,
            last_verified_at TEXT NOT NULL,
            verdict_expires_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES compliance_scans (id)
        );
        """
    )
    _ensure_column(db, "compliance_reports", "report_html", "TEXT")
    _ensure_column(db, "compliance_reports", "report_sections_json", "TEXT")
    _ensure_column(db, "compliance_reports", "executive_summary", "TEXT")
    _ensure_column(db, "compliance_scans", "investigation_json", "TEXT")
    db.commit()


def init_db() -> None:
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            phone TEXT,
            address TEXT,
            role TEXT NOT NULL DEFAULT 'customer',
            account_status TEXT NOT NULL DEFAULT 'Active',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            account_number TEXT NOT NULL UNIQUE,
            account_type TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_account_id INTEGER,
            recipient_account_id INTEGER,
            amount REAL NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'Completed',
            flagged INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_account_id) REFERENCES accounts (id),
            FOREIGN KEY (recipient_account_id) REFERENCES accounts (id)
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            description TEXT,
            ip_address TEXT,
            severity TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS support_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject TEXT,
            message TEXT,
            status TEXT NOT NULL DEFAULT 'Open',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS customer_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            document_type TEXT,
            content_preview TEXT,
            file_size INTEGER DEFAULT 0,
            uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        """
    )
    db.commit()
    migrate_schema()
    seed_data()
    seed_banking_content()


def seed_data() -> None:
    db = get_db()
    if query_one("SELECT id FROM users LIMIT 1"):
        return

    users = [
        ("John Carter", "john@aria.local", "password123", "+1 416 555 0131", "120 King Street W, Toronto, ON", "customer", "Active"),
        ("Sara Ahmed", "sara@aria.local", "123456", "+1 416 555 0188", "44 Queen Street E, Toronto, ON", "customer", "Active"),
        ("Demo Business", "business@aria.local", "business123", "+1 416 555 0199", "200 Bay Street, Toronto, ON", "customer", "Active"),
        ("Teller User", "teller@aria.local", "teller123", "+1 416 555 0120", "ARIA Bank Branch Desk", "staff", "Active"),
        ("Admin User", "admin@aria.local", "admin123", "+1 416 555 0100", "ARIA Bank Operations Office", "admin", "Active"),
    ]
    db.executemany(
        """
        INSERT INTO users (full_name, email, password, phone, address, role, account_status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        users,
    )

    accounts = [
        (1, "ARIA-1000-2401-9001", "Everyday Chequing", 4500.00, 450000),
        (2, "ARIA-1000-2401-9002", "Everyday Chequing", 8200.00, 820000),
        (3, "ARIA-2000-8800-3120", "Business Operating", 25000.00, 2500000),
    ]
    db.executemany(
        "INSERT INTO accounts (user_id, account_number, account_type, balance, balance_cents) VALUES (?, ?, ?, ?, ?)",
        accounts,
    )

    transactions = [
        (1, 2, 250.00, "Rent share reimbursement", "Completed", 0),
        (2, 1, 75.50, "Dinner transfer", "Completed", 0),
        (3, 1, 1200.00, "Vendor payment", "Completed", 1),
        (1, 3, 315.25, "Consulting invoice", "Completed", 0),
        (2, 3, 50.00, "Subscription payment", "Completed", 0),
    ]
    db.executemany(
        """
        INSERT INTO transactions (sender_account_id, recipient_account_id, amount, description, status, flagged)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        transactions,
    )

    audit_logs = [
        (datetime.utcnow().isoformat(timespec="seconds"), 5, "SEED_DATA_CREATED", "Initial users and accounts created.", "127.0.0.1", "Low"),
        (datetime.utcnow().isoformat(timespec="seconds"), 1, "TRANSFER_CREATED", "Seed transaction data created.", None, None),
    ]
    db.executemany(
        """
        INSERT INTO audit_logs (timestamp, user_id, event_type, description, ip_address, severity)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        audit_logs,
    )
    db.commit()


def seed_banking_content() -> None:
    db = get_db()
    db.execute(
        """
        UPDATE support_messages
        SET message = 'Can support review the pending wire transfer note?'
        WHERE message LIKE '%jndi:%'
        """
    )
    if not query_one("SELECT id FROM support_messages LIMIT 1"):
        db.executemany(
            """
            INSERT INTO support_messages (user_id, subject, message, status)
            VALUES (?, ?, ?, ?)
            """,
            [
                (1, "Wire transfer question", "Can support review the pending wire transfer note?", "Open"),
                (2, "Login problem", "I can sign in with 123456 but the page sometimes redirects slowly.", "Open"),
            ],
        )
    db.commit()

    if not query_one("SELECT id FROM customer_documents LIMIT 1"):
        db.executemany(
            """
            INSERT INTO customer_documents (user_id, filename, document_type, content_preview, file_size)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (1, "john_statement_q1.pdf", "Statement", "Payroll deposit, rent transfer, debit purchases", 20480),
                (2, "sara_id_scan.png", "Identity", "Driver licence image preview and address verification", 11740),
                (3, "business_tax_return.xlsx", "Business", "Vendor payments, tax numbers, operating account summary", 38920),
            ],
        )
    db.commit()


def get_user_account(user_id: int) -> sqlite3.Row | None:
    return query_one(
        """
        SELECT accounts.*, users.full_name, users.email
        FROM accounts
        JOIN users ON users.id = accounts.user_id
        WHERE users.id = ?
        """,
        (user_id,),
    )


def role_home(role: str) -> str:
    if role in ("admin", "staff"):
        return "admin_dashboard"
    return "dashboard"


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()

        if not full_name or not email or not password:
            flash("Name, email, and password are required.", "danger")
            return render_template("register.html")

        try:
            db = get_db()
            cursor = db.execute(
                """
                INSERT INTO users (full_name, email, password, phone, address, role, account_status)
                VALUES (?, ?, ?, ?, ?, 'customer', 'Active')
                """,
                (full_name, email, password, phone, address),
            )
            user_id = cursor.lastrowid
            account_number = f"ARIA-NEW-{1000 + user_id}-{9000 + user_id}"
            db.execute(
                """
                INSERT INTO accounts (user_id, account_number, account_type, balance, balance_cents)
                VALUES (?, ?, 'Everyday Chequing', 100.00, 10000)
                """,
                (user_id, account_number),
            )
            db.commit()
            log_event(user_id, "REGISTER", f"New customer registered: {email}", "Low")
            flash("Registration complete. You can sign in now.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email is already registered.", "danger")

    return render_template("register.html")


@app.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = query_one("SELECT * FROM users WHERE email = ?", (email,))

        if user and user["password"] == password and user["account_status"] == "Active":
            session.clear()
            session["user_id"] = user["id"]
            log_event(user["id"], "LOGIN_SUCCESS", f"{user['email']} signed in.", "Low")
            return redirect(url_for(role_home(user["role"])))

        if user:
            log_event(user["id"], "LOGIN_FAILED", f"Failed login for {email}", None, include_ip=False)
        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    user_id = session.get("user_id")
    log_event(user_id, "LOGOUT", "User signed out.", "Low")
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    target_user_id = request.args.get("user_id", user["id"], type=int)
    account = get_user_account(target_user_id)
    if not account:
        abort(404)
    transactions = query_all(
        """
        SELECT t.*, sa.account_number AS sender_number, ra.account_number AS recipient_number,
               su.full_name AS sender_name, ru.full_name AS recipient_name
        FROM transactions t
        LEFT JOIN accounts sa ON sa.id = t.sender_account_id
        LEFT JOIN accounts ra ON ra.id = t.recipient_account_id
        LEFT JOIN users su ON su.id = sa.user_id
        LEFT JOIN users ru ON ru.id = ra.user_id
        WHERE t.sender_account_id = ? OR t.recipient_account_id = ?
        ORDER BY t.created_at DESC
        LIMIT 5
        """,
        (account["id"], account["id"]),
    )
    if target_user_id != user["id"]:
        log_event(user["id"], "ACCOUNT_VIEW", f"Dashboard view requested for user_id={target_user_id}", "Medium")
    return render_template("dashboard.html", account=account, transactions=transactions)


@app.route("/transfer", methods=("GET", "POST"))
@login_required
def transfer():
    user = current_user()
    sender_account = get_user_account(user["id"])
    if not sender_account:
        flash("Transfers are available only for customer accounts.", "warning")
        return redirect(url_for("admin_dashboard"))

    recipients = query_all(
        """
        SELECT accounts.*, users.full_name, users.email
        FROM accounts
        JOIN users ON users.id = accounts.user_id
        WHERE users.id != ?
        ORDER BY users.full_name
        """,
        (user["id"],),
    )

    if request.method == "POST":
        recipient_lookup = request.form.get("recipient", "").strip()
        description = request.form.get("description", "").strip()
        amount_raw = request.form.get("amount", "0").strip()
        idempotency_key = request.form.get("idempotency_key", "").strip()
        request_context = {
            "ip_address": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            "path": request.path,
        }
        result = process_transfer(
            get_db(),
            user_id=user["id"],
            sender_account_id=sender_account["id"],
            sender_status=user["account_status"],
            recipient_lookup=recipient_lookup,
            amount_raw=amount_raw,
            description=description,
            idempotency_key=idempotency_key,
            request_context=request_context,
        )
        if result.success:
            flash(result.message, "success" if not result.idempotent_replay else "info")
            return redirect(url_for("transactions"))
        flash(result.message, "danger")

    idempotency_key = str(uuid4())
    return render_template(
        "transfer.html",
        account=sender_account,
        recipients=recipients,
        idempotency_key=idempotency_key,
    )


@app.route("/transactions")
@login_required
def transactions():
    user = current_user()
    target_user_id = request.args.get("user_id", user["id"], type=int)
    search = request.args.get("q", "")
    account = get_user_account(target_user_id)
    if not account:
        abort(404)

    sql = """
        SELECT t.*, sa.account_number AS sender_number, ra.account_number AS recipient_number,
               su.full_name AS sender_name, ru.full_name AS recipient_name
        FROM transactions t
        LEFT JOIN accounts sa ON sa.id = t.sender_account_id
        LEFT JOIN accounts ra ON ra.id = t.recipient_account_id
        LEFT JOIN users su ON su.id = sa.user_id
        LEFT JOIN users ru ON ru.id = ra.user_id
        WHERE (t.sender_account_id = ? OR t.recipient_account_id = ?)
    """
    params = [account["id"], account["id"]]
    if search:
        sql += " AND (t.description LIKE ? OR t.status LIKE ?)"
        like_term = f"%{search}%"
        params.extend([like_term, like_term])
    sql += " ORDER BY t.created_at DESC"
    rows = query_all(sql, tuple(params))

    if target_user_id != user["id"]:
        log_event(user["id"], "UNAUTHORIZED_ACCESS_ATTEMPT", f"Transaction history view user_id={target_user_id}", "Medium")
    return render_template("transactions.html", transactions=rows, search=search, account=account)

@app.route("/profile", methods=("GET", "POST"))
@login_required
def profile():
    user = current_user()
    account = get_user_account(user["id"])
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        if request.form.get("role"):
            log_event(user["id"], "SUSPICIOUS_ROLE_SUBMISSION", f"Customer submitted role parameter: {request.form.get('role')}", "High")
        db = get_db()
        db.execute(
            """
            UPDATE users SET full_name = ?, phone = ?, address = ?
            WHERE id = ?
            """,
            (full_name, phone, address, user["id"]),
        )
        db.commit()
        log_event(user["id"], "PROFILE_UPDATED", "Customer profile updated.", "Low")
        flash("Profile updated.", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user, account=account)


@app.route("/support", methods=("GET", "POST"))
@login_required
def support():
    user = current_user()
    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        execute(
            """
            INSERT INTO support_messages (user_id, subject, message, status)
            VALUES (?, ?, ?, 'Open')
            """,
            (user["id"], subject, message),
        )
        log_event(user["id"], "SUPPORT_MESSAGE_CREATED", f"Support message stored: {subject} | {message}", "Low")
        flash("Support message submitted.", "success")
        return redirect(url_for("support"))

    messages = query_all(
        """
        SELECT support_messages.*, users.full_name, users.email
        FROM support_messages
        JOIN users ON users.id = support_messages.user_id
        WHERE support_messages.user_id = ?
        ORDER BY support_messages.created_at DESC
        """,
        (user["id"],),
    )
    return render_template("support.html", messages=messages)


@app.route("/documents", methods=("GET", "POST"))
@login_required
def documents():
    user = current_user()
    if request.method == "POST":
        uploaded = request.files.get("document")
        document_type = request.form.get("document_type", "Statement")
        note = request.form.get("note", "")
        if not uploaded or not uploaded.filename:
            flash("Choose a document to upload.", "danger")
        else:
            data = uploaded.read()
            preview = (data[:220].decode("utf-8", errors="ignore") or note or "Binary document preview unavailable").strip()
            execute(
                """
                INSERT INTO customer_documents (user_id, filename, document_type, content_preview, file_size)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user["id"], uploaded.filename, document_type, preview, len(data)),
            )
            log_event(user["id"], "DOCUMENT_UPLOADED", f"Uploaded {uploaded.filename} with note {note}", "Low")
            flash("Document uploaded.", "success")
            return redirect(url_for("documents"))

    docs = query_all(
        """
        SELECT customer_documents.*, users.full_name, users.email
        FROM customer_documents
        JOIN users ON users.id = customer_documents.user_id
        WHERE customer_documents.user_id = ?
        ORDER BY customer_documents.uploaded_at DESC
        """,
        (user["id"],),
    )
    return render_template("documents.html", documents=docs)


@app.route("/statements")
@login_required
def statements():
    user = current_user()
    q = request.args.get("q", "")
    owner = request.args.get("user_id", user["id"], type=int)
    sql = """
        SELECT customer_documents.*, users.full_name, users.email
        FROM customer_documents
        JOIN users ON users.id = customer_documents.user_id
        WHERE customer_documents.user_id = ?
    """
    params = [owner]
    if q:
        sql += " AND (filename LIKE ? OR content_preview LIKE ? OR document_type LIKE ?)"
        like_term = f"%{q}%"
        params.extend([like_term, like_term, like_term])
    sql += " ORDER BY uploaded_at DESC"
    docs = query_all(sql, tuple(params))
    if owner != user["id"]:
        log_event(user["id"], "UNAUTHORIZED_ACCESS_ATTEMPT", f"Statement search viewed user_id={owner}", "Medium")
    return render_template("statements.html", documents=docs, q=q, owner=owner)


@app.route("/employee-portal")
@login_required
def employee_portal():
    user = current_user()
    if user["role"] == "customer":
        log_event(user["id"], "EMPLOYEE_PORTAL_VIEW", "Employee portal viewed by customer account.", "High")
        abort(403)
    users = query_all(
        """
        SELECT users.id, users.full_name, users.email, users.role, users.account_status,
               accounts.account_number, accounts.balance
        FROM users
        LEFT JOIN accounts ON accounts.user_id = users.id
        ORDER BY users.id
        """
    )
    documents = query_all(
        """
        SELECT customer_documents.*, users.full_name
        FROM customer_documents
        JOIN users ON users.id = customer_documents.user_id
        ORDER BY customer_documents.uploaded_at DESC
        LIMIT 12
        """
    )
    return render_template("employee_portal.html", users=users, documents=documents)


@app.route("/admin")
@login_required
def admin_dashboard():
    user = current_user()
    if user["role"] == "customer":
        log_event(user["id"], "ADMIN_DASHBOARD_VIEW", "Admin dashboard viewed by customer account.", "High")
        abort(403)
    stats = {
        "users": query_one("SELECT COUNT(*) AS count FROM users")["count"],
        "transactions": query_one("SELECT COUNT(*) AS count FROM transactions")["count"],
        "documents": query_one("SELECT COUNT(*) AS count FROM customer_documents")["count"],
        "support": query_one("SELECT COUNT(*) AS count FROM support_messages WHERE status = 'Open'")["count"],
        "failed_logins": query_one("SELECT COUNT(*) AS count FROM audit_logs WHERE event_type = 'LOGIN_FAILED'")["count"],
    }
    high_value = query_all(
        """
        SELECT t.*, su.full_name AS sender_name, ru.full_name AS recipient_name
        FROM transactions t
        LEFT JOIN accounts sa ON sa.id = t.sender_account_id
        LEFT JOIN accounts ra ON ra.id = t.recipient_account_id
        LEFT JOIN users su ON su.id = sa.user_id
        LEFT JOIN users ru ON ru.id = ra.user_id
        WHERE t.amount >= 1000
        ORDER BY t.created_at DESC
        LIMIT 5
        """
    )
    recent_logs = query_all(
        """
        SELECT audit_logs.*, users.full_name
        FROM audit_logs
        LEFT JOIN users ON users.id = audit_logs.user_id
        ORDER BY audit_logs.timestamp DESC
        LIMIT 6
        """
    )
    return render_template("admin_dashboard.html", stats=stats, high_value=high_value, recent_logs=recent_logs)


@app.route("/admin/users", methods=("GET", "POST"))
@admin_required
def admin_users():
    if request.method == "POST":
        user_id = request.form.get("user_id", type=int)
        role = request.form.get("role", "customer")
        account_status = request.form.get("account_status", "Active")
        execute("UPDATE users SET role = ?, account_status = ? WHERE id = ?", (role, account_status, user_id))
        log_event(session.get("user_id"), "ADMIN_ROLE_CHANGE", f"Updated user {user_id} to role={role}, status={account_status}", "High")
        flash("User access settings updated.", "success")
        return redirect(url_for("admin_users"))

    users = query_all(
        """
        SELECT users.*, accounts.account_number, accounts.balance
        FROM users
        LEFT JOIN accounts ON accounts.user_id = users.id
        ORDER BY users.created_at DESC
        """
    )
    log_event(session.get("user_id"), "ADMIN_VIEW_USERS", "Admin viewed user management table.", "Low")
    return render_template("admin_users.html", users=users)


@app.route("/admin/transactions", methods=("GET", "POST"))
@staff_or_admin_required
def admin_transactions():
    if request.method == "POST":
        tx_id = request.form.get("transaction_id", type=int)
        execute("UPDATE transactions SET flagged = 1 WHERE id = ?", (tx_id,))
        log_event(session.get("user_id"), "ADMIN_FLAG_TRANSACTION", f"Flagged transaction {tx_id} as suspicious.", "Medium")
        flash("Transaction flagged for review.", "success")
        return redirect(url_for("admin_transactions"))

    user_filter = request.args.get("user", "")
    amount_filter = request.args.get("amount", "")
    sql = """
        SELECT t.*, su.full_name AS sender_name, ru.full_name AS recipient_name,
               sa.account_number AS sender_number, ra.account_number AS recipient_number
        FROM transactions t
        LEFT JOIN accounts sa ON sa.id = t.sender_account_id
        LEFT JOIN accounts ra ON ra.id = t.recipient_account_id
        LEFT JOIN users su ON su.id = sa.user_id
        LEFT JOIN users ru ON ru.id = ra.user_id
        WHERE 1 = 1
    """
    args: list = []
    if user_filter:
        sql += " AND (su.full_name LIKE ? OR ru.full_name LIKE ?)"
        args.extend([f"%{user_filter}%", f"%{user_filter}%"])
    if amount_filter:
        sql += " AND t.amount >= ?"
        args.append(amount_filter)
    sql += " ORDER BY t.created_at DESC"
    rows = query_all(sql, tuple(args))
    return render_template("admin_transactions.html", transactions=rows, user_filter=user_filter, amount_filter=amount_filter)


@app.route("/admin/audit-logs")
@staff_or_admin_required
def audit_logs():
    rows = query_all(
        """
        SELECT audit_logs.*, users.full_name, users.email
        FROM audit_logs
        LEFT JOIN users ON users.id = audit_logs.user_id
        ORDER BY audit_logs.timestamp DESC
        LIMIT 200
        """
    )
    return render_template("audit_logs.html", audit_logs=rows)


@app.route("/admin/rejected-transfers")
@staff_or_admin_required
def admin_rejected_transfers():
    rows = query_all(
        """
        SELECT rejected_transfers.*, users.full_name, users.email,
               accounts.account_number AS sender_account_number
        FROM rejected_transfers
        JOIN users ON users.id = rejected_transfers.user_id
        JOIN accounts ON accounts.id = rejected_transfers.sender_account_id
        ORDER BY rejected_transfers.created_at DESC
        LIMIT 200
        """
    )
    log_event(session.get("user_id"), "ADMIN_VIEW_REJECTED_TRANSFERS", "Staff viewed rejected transfer log.", "Low")
    return render_template("admin_rejected_transfers.html", rejected_transfers=rows)


@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="Access denied for this route."), 403


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="The requested ARIA Bank page was not found."), 404


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
