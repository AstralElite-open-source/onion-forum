import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Optional

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup
from markdown_it import MarkdownIt
import bleach

def _get_persistent_secret() -> str:
    """Return a stable secret key.

    Priority:
    1) SECRET_KEY env var if provided and non-empty.
    2) Read from a file located alongside the database file (e.g., /data/secret_key).
    3) Generate a new one, write it to that file, and use it.
    If file operations fail, fall back to an in-memory random key (sessions will reset on restart).
    """
    sk = os.environ.get("SECRET_KEY", "").strip()
    if sk:
        return sk

    db_path_str = os.environ.get("FORUM_DB_PATH", "forum.db")
    try:
        base = Path(db_path_str).parent if Path(db_path_str).parent else Path(".")
        secret_file = base / "secret_key"
        if secret_file.exists():
            try:
                return secret_file.read_text(encoding="utf-8").strip()
            except Exception:
                pass

        # Generate and persist
        new_sk = secrets.token_hex(32)
        try:
            base.mkdir(parents=True, exist_ok=True)
            secret_file.write_text(new_sk, encoding="utf-8")
            try:
                os.chmod(secret_file, 0o600)  # best-effort
            except Exception:
                pass
        except Exception:
            # Could not persist; return volatile key
            return new_sk
        return new_sk
    except Exception:
        return secrets.token_hex(32)


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )

    # Configuration
    app.config.update(
        DATABASE=os.environ.get("FORUM_DB_PATH", "forum.db"),
        SECRET_KEY=_get_persistent_secret(),
        MAX_CONTENT_LENGTH=256 * 1024,  # 256 KB per request
        TEMPLATES_AUTO_RELOAD=True,
    )

    # Ensure data folder exists if using a nested path
    db_path = Path(app.config["DATABASE"])  # type: ignore[index]
    if db_path.parent and not db_path.parent.exists():
        db_path.parent.mkdir(parents=True, exist_ok=True)

    # Database helpers
    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            conn = sqlite3.connect(app.config["DATABASE"])  # type: ignore[index]
            conn.row_factory = sqlite3.Row
            # Conservative pragmas suited for Tor hidden services (durable, but still performant)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            g.db = conn
        return g.db  # type: ignore[return-value]

    def close_db(_: Optional[BaseException] = None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    app.teardown_appcontext(close_db)

    def init_db() -> None:
        db = get_db()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS categories (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                slug    TEXT UNIQUE NOT NULL,
                name    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS threads (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                title           TEXT NOT NULL,
                posts_count     INTEGER NOT NULL DEFAULT 0,
                created_at      INTEGER NOT NULL,
                last_activity_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS posts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                thread_id   INTEGER NOT NULL,
                author      TEXT,
                content     TEXT NOT NULL,
                created_at  INTEGER NOT NULL,
                FOREIGN KEY(thread_id) REFERENCES threads(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_threads_last_activity ON threads(last_activity_at DESC);
            CREATE INDEX IF NOT EXISTS idx_posts_thread_id ON posts(thread_id);

            CREATE TABLE IF NOT EXISTS comments (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id     INTEGER NOT NULL,
                author      TEXT,
                content     TEXT NOT NULL,
                created_at  INTEGER NOT NULL,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id);
            """
        )
        # Migrations: add category_id to threads if missing
        cur = db.execute("PRAGMA table_info(threads)")
        cols = {row[1] for row in cur.fetchall()}
        if "category_id" not in cols:
            db.execute("ALTER TABLE threads ADD COLUMN category_id INTEGER")
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_threads_category ON threads(category_id)"
            )
        db.commit()

        # Seed default categories
        existing = db.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
        if existing == 0:
            defaults = [
                ("technology", "Technology"),
                ("learning", "Learning"),
                ("politics", "Politics"),
                ("secret", "Secret"),
            ]
            db.executemany(
                "INSERT INTO categories (slug, name) VALUES (?, ?)", defaults
            )
            db.commit()

        # Ensure existing threads have a category (default to first category)
        row = db.execute("SELECT id FROM categories ORDER BY id ASC LIMIT 1").fetchone()
        if row:
            default_cat_id = row[0]
            db.execute(
                "UPDATE threads SET category_id = COALESCE(category_id, ?) WHERE category_id IS NULL",
                (default_cat_id,),
            )
            db.commit()

    # CSRF protection minimal and session bootstrap
    @app.before_request
    def csrf_and_session_bootstrap() -> None:  # pragma: no cover - trivial
        # Initialize CSRF token
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)

        # Enforce CSRF on POSTs
        if request.method == "POST":
            token_form = request.form.get("csrf_token", "")
            token_sess = session.get("csrf_token", "")
            if not token_form or token_form != token_sess:
                abort(400, description="Invalid CSRF token")

    @app.after_request
    def set_security_headers(resp):  # pragma: no cover - trivial
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        # CSP allows only same-origin resources
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'none'",
        )
        return resp

    # Utilities
    def now_ts() -> int:
        return int(time.time())

    def clamp_text(s: str, max_len: int) -> str:
        return s if len(s) <= max_len else s[: max_len - 1].rstrip() + "…"

    # Routes
    def get_categories_list():
        db = get_db()
        return db.execute(
            "SELECT id, slug, name FROM categories ORDER BY name ASC"
        ).fetchall()

    @app.route("/")
    def index():
        db = get_db()
        categories = get_categories_list()
        cat_slug = request.args.get("cat")
        cat = None
        if cat_slug:
            cat = db.execute(
                "SELECT id, slug, name FROM categories WHERE slug = ?",
                (cat_slug,),
            ).fetchone()
        try:
            page = max(int(request.args.get("page", "1")), 1)
        except ValueError:
            page = 1
        per_page = 20
        offset = (page - 1) * per_page

        if cat is None:
            total_threads = db.execute("SELECT COUNT(*) FROM threads").fetchone()[0]
            threads = db.execute(
                """
                SELECT t.id, t.title, t.posts_count, t.created_at, t.last_activity_at,
                       c.name AS category_name, c.slug AS category_slug
                FROM threads t
                LEFT JOIN categories c ON c.id = t.category_id
                ORDER BY t.last_activity_at DESC, t.id DESC
                LIMIT ? OFFSET ?
                """,
                (per_page, offset),
            ).fetchall()
        else:
            total_threads = db.execute(
                "SELECT COUNT(*) FROM threads WHERE category_id = ?",
                (cat["id"],),
            ).fetchone()[0]
            threads = db.execute(
                """
                SELECT t.id, t.title, t.posts_count, t.created_at, t.last_activity_at,
                       c.name AS category_name, c.slug AS category_slug
                FROM threads t
                LEFT JOIN categories c ON c.id = t.category_id
                WHERE t.category_id = ?
                ORDER BY t.last_activity_at DESC, t.id DESC
                LIMIT ? OFFSET ?
                """,
                (cat["id"], per_page, offset),
            ).fetchall()

        total_pages = max((total_threads + per_page - 1) // per_page, 1)
        # Recent posts (global)
        recent_posts = db.execute(
            """
            SELECT p.id as post_id, p.created_at, p.author, p.content,
                   t.id as thread_id, t.title as thread_title,
                   c.name as category_name, c.slug as category_slug
            FROM posts p
            JOIN threads t ON t.id = p.thread_id
            LEFT JOIN categories c ON c.id = t.category_id
            ORDER BY p.id DESC
            LIMIT 10
            """
        ).fetchall()
        return render_template(
            "index.html",
            threads=threads,
            categories=categories,
            cat=cat,
            recent_posts=recent_posts,
            page=page,
            total_pages=total_pages,
        )

    @app.route("/thread/<int:thread_id>")
    def thread_view(thread_id: int):
        db = get_db()
        thread = db.execute(
            """
            SELECT t.id, t.title, t.posts_count, t.created_at, t.last_activity_at,
                   c.name AS category_name, c.slug AS category_slug
            FROM threads t
            LEFT JOIN categories c ON c.id = t.category_id
            WHERE t.id = ?
            """,
            (thread_id,),
        ).fetchone()
        if not thread:
            abort(404)

        try:
            page = max(int(request.args.get("page", "1")), 1)
        except ValueError:
            page = 1
        per_page = 50
        offset = (page - 1) * per_page

        total_posts = db.execute(
            "SELECT COUNT(*) FROM posts WHERE thread_id = ?",
            (thread_id,),
        ).fetchone()[0]

        posts = db.execute(
            """
            SELECT id, author, content, created_at
            FROM posts
            WHERE thread_id = ?
            ORDER BY id ASC
            LIMIT ? OFFSET ?
            """,
            (thread_id, per_page, offset),
        ).fetchall()

        # Fetch comments for posts on this page in one query
        post_ids = [p["id"] for p in posts]
        comments_map = {}
        if post_ids:
            q_marks = ",".join(["?"] * len(post_ids))
            comments = db.execute(
                f"SELECT id, post_id, author, content, created_at FROM comments WHERE post_id IN ({q_marks}) ORDER BY id ASC",
                post_ids,
            ).fetchall()
            for c in comments:
                comments_map.setdefault(c["post_id"], []).append(c)

        total_pages = max((total_posts + per_page - 1) // per_page, 1)
        return render_template(
            "thread.html",
            thread=thread,
            posts=posts,
            comments_map=comments_map,
            page=page,
            total_pages=total_pages,
        )

    @app.route("/thread", methods=["POST"])
    def create_thread():
        db = get_db()
        title = (request.form.get("title") or "").strip()
        author = (request.form.get("author") or "").strip() or "anon"
        content = (request.form.get("content") or "").strip()
        cat_id_raw = request.form.get("category_id")

        if not title or not content:
            abort(400, description="Title and content are required")

        title = clamp_text(title, 140)
        author = clamp_text(author, 32)
        content = clamp_text(content, 5000)

        # Resolve category; default to first category if not supplied or invalid
        cat_row = None
        if cat_id_raw and cat_id_raw.isdigit():
            cat_row = db.execute(
                "SELECT id FROM categories WHERE id = ?",
                (int(cat_id_raw),),
            ).fetchone()
        if not cat_row:
            cat_row = db.execute(
                "SELECT id FROM categories ORDER BY id ASC LIMIT 1"
            ).fetchone()
        if not cat_row:
            abort(400, description="No categories configured")
        category_id = cat_row[0]

        ts = now_ts()
        cur = db.execute(
            "INSERT INTO threads (title, posts_count, created_at, last_activity_at, category_id) VALUES (?, 0, ?, ?, ?)",
            (title, ts, ts, category_id),
        )
        thread_id = cur.lastrowid
        db.execute(
            "INSERT INTO posts (thread_id, author, content, created_at) VALUES (?, ?, ?, ?)",
            (thread_id, author, content, ts),
        )
        db.execute(
            "UPDATE threads SET posts_count = posts_count + 1, last_activity_at=? WHERE id=?",
            (ts, thread_id),
        )
        db.commit()
        return redirect(url_for("thread_view", thread_id=thread_id))

    @app.route("/thread/<int:thread_id>/reply", methods=["POST"])
    def reply(thread_id: int):
        db = get_db()
        # Ensure thread exists
        exists = db.execute("SELECT 1 FROM threads WHERE id=?", (thread_id,)).fetchone()
        if not exists:
            abort(404)

        author = (request.form.get("author") or "").strip() or "anon"
        content = (request.form.get("content") or "").strip()
        if not content:
            abort(400, description="Content is required")

        author = clamp_text(author, 32)
        content = clamp_text(content, 5000)

        ts = now_ts()
        db.execute(
            "INSERT INTO posts (thread_id, author, content, created_at) VALUES (?, ?, ?, ?)",
            (thread_id, author, content, ts),
        )
        db.execute(
            "UPDATE threads SET posts_count = posts_count + 1, last_activity_at=? WHERE id=?",
            (ts, thread_id),
        )
        db.commit()
        return redirect(url_for("thread_view", thread_id=thread_id))

    @app.route("/post/<int:post_id>/comment", methods=["POST"])
    def comment(post_id: int):
        db = get_db()
        # Resolve post and thread for redirect and validation
        post = db.execute(
            "SELECT id, thread_id FROM posts WHERE id=?",
            (post_id,),
        ).fetchone()
        if not post:
            abort(404)

        author = (request.form.get("author") or "").strip() or "anon"
        content = (request.form.get("content") or "").strip()
        if not content:
            abort(400, description="Content is required")

        author = clamp_text(author, 32)
        content = clamp_text(content, 2000)

        ts = now_ts()
        db.execute(
            "INSERT INTO comments (post_id, author, content, created_at) VALUES (?, ?, ?, ?)",
            (post_id, author, content, ts),
        )
        # Bump thread activity on comment as well
        db.execute(
            "UPDATE threads SET last_activity_at=? WHERE id=?",
            (ts, post["thread_id"]),
        )
        db.commit()
        return redirect(url_for("thread_view", thread_id=post["thread_id"]) + f"#p{post_id}")

    # Health check (useful for quick smoke test)
    @app.route("/healthz")
    def healthz():  # pragma: no cover - trivial
        return {"ok": True}, 200

    # Initialize DB on first run
    with app.app_context():
        init_db()

    # Expose helpers for tests
    app.get_db = get_db  # type: ignore[attr-defined]
    app.init_db = init_db  # type: ignore[attr-defined]

    # Jinja filters
    def datetimeformat(value: int) -> str:
        try:
            ts = int(value)
        except Exception:
            return ""
        # UTC for consistency on Tor
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))

    def nl2br(value: str) -> Markup:
        """Render text with line breaks safely.

        Input is expected to be already HTML-escaped in templates (we use `| e | nl2br`).
        We then:
        - Normalize newlines (\r\n/\r -> \n)
        - Convert escaped `<br>` variants (e.g. `&lt;br&gt;`, `&lt;br/&gt;`, `&lt;br /&gt;`) into real <br>
          so users who type literal `<br>` see a break, without allowing other HTML.
        - Convert remaining newlines to `<br>`.
        """
        s = (value or "")
        # Normalize Windows/Mac newlines
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        # Allow only the <br> tag if it was typed literally (escaped by `|e|` earlier)
        s = (
            s.replace("&lt;br&gt;", "<br>")
            .replace("&lt;br/&gt;", "<br>")
            .replace("&lt;br /&gt;", "<br>")
        )
        # Convert newline characters to <br>
        s = s.replace("\n", "<br>")
        return Markup(s)

    # Markdown renderer (commonmark + breaks)
    md = MarkdownIt("commonmark", {
        "breaks": True,  # newlines -> <br>
    })

    # Allowed tags/attributes for sanitization
    _ALLOWED_TAGS = [
        "p", "br", "strong", "em", "code", "pre", "blockquote",
        "ul", "ol", "li", "a", "h1", "h2", "h3", "h4", "h5", "h6",
    ]
    _ALLOWED_ATTRS = {"a": ["href", "title", "rel"]}

    def markdown_to_html(text: str) -> Markup:
        raw = text or ""
        # Render to HTML with Markdown
        html = md.render(raw)
        # Sanitize to prevent XSS
        cleaned = bleach.clean(
            html,
            tags=_ALLOWED_TAGS,
            attributes=_ALLOWED_ATTRS,
            protocols=["http", "https", "mailto"],
            strip=True,
        )
        return Markup(cleaned)

    app.jinja_env.filters["datetimeformat"] = datetimeformat
    app.jinja_env.filters["nl2br"] = nl2br
    app.jinja_env.filters["markdown"] = markdown_to_html

    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    # Bind to localhost by default; Tor will proxy to this if configured as a hidden service
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    app.run(host=host, port=port, debug=False)
