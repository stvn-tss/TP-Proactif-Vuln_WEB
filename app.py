"""HelpDesk ESIEA - petite application de ticketing INTENTIONNELLEMENT VULNERABLE.

Projet pedagogique (TP Proactif - Vulnerabilites WEB). NE JAMAIS DEPLOYER EN PRODUCTION.
Les failles sont listees dans VULNERABILITIES.md.
"""
import base64
import hashlib
import os
import pickle
import sqlite3

import requests
import yaml
from flask import (Flask, g, make_response, redirect, render_template,
                   request, send_file, session)

app = Flask(__name__)
app.secret_key = "supersecret123"  # VULN: secret hardcode

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "helpdesk.db")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


# --------------------------------------------------------------------------- DB
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # VULN: MD5, sans sel


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user');
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT, title TEXT, body TEXT, private INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER, author TEXT, content TEXT);
        """
    )
    if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        db.executemany(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            [
                ("admin", hash_password("admin123"), "admin"),  # VULN: creds par defaut
                ("alice", hash_password("password1"), "user"),
            ],
        )
        db.executemany(
            "INSERT INTO tickets (owner, title, body, private) VALUES (?, ?, ?, ?)",
            [
                ("alice", "Imprimante en panne", "L'imprimante du couloir B ne repond plus.", 0),
                ("admin", "Rotation des mots de passe", "Mot de passe root du serveur : FLAG{sqli_union_select_ftw}", 1),
            ],
        )
    db.commit()
    db.close()


# ------------------------------------------------------------------------- Auth
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        app.logger.info("Nouvelle inscription : %s / %s", username, password)  # VULN: mot de passe en clair dans les logs
        try:
            get_db().execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hash_password(password)),
            )
            get_db().commit()
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Nom d'utilisateur deja pris")
        return redirect("/login")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # VULN: injection SQL (concatenation) -> bypass d'authentification
        query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
            username,
            hash_password(password),
        )
        user = get_db().execute(query).fetchone()
        if user:
            session["user"] = user["username"]
            resp = make_response(redirect(request.args.get("next", "/")))  # VULN: open redirect
            resp.set_cookie("role", user["role"])  # VULN: role controle cote client
            return resp
        return render_template("login.html", error="Identifiants invalides")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


def current_user():
    return session.get("user")


# ---------------------------------------------------------------------- Tickets
@app.route("/")
def index():
    if not current_user():
        return redirect("/login")
    tickets = get_db().execute(
        "SELECT * FROM tickets WHERE owner = ?", (current_user(),)
    ).fetchall()
    return render_template("index.html", tickets=tickets, user=current_user())


@app.route("/ticket/new", methods=["GET", "POST"])
def new_ticket():
    if not current_user():
        return redirect("/login")
    if request.method == "POST":
        get_db().execute(
            "INSERT INTO tickets (owner, title, body) VALUES (?, ?, ?)",
            (current_user(), request.form["title"], request.form["body"]),
        )
        get_db().commit()
        return redirect("/")
    return render_template("new_ticket.html", user=current_user())


@app.route("/ticket/<int:ticket_id>", methods=["GET", "POST"])
def ticket(ticket_id):
    if not current_user():
        return redirect("/login")
    db = get_db()
    if request.method == "POST":  # VULN: pas de jeton CSRF
        db.execute(
            "INSERT INTO comments (ticket_id, author, content) VALUES (?, ?, ?)",
            (ticket_id, current_user(), request.form["content"]),
        )
        db.commit()
    # VULN: IDOR - aucune verification que le ticket appartient a l'utilisateur
    t = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    comments = db.execute(
        "SELECT * FROM comments WHERE ticket_id = ?", (ticket_id,)
    ).fetchall()
    return render_template("ticket.html", ticket=t, comments=comments, user=current_user())


@app.route("/search")
def search():
    if not current_user():
        return redirect("/login")
    q = request.args.get("q", "")
    # VULN: injection SQL (UNION possible) + XSS reflechi dans search.html (|safe)
    rows = get_db().execute(
        "SELECT id, title, owner FROM tickets WHERE private = 0 AND title LIKE '%" + q + "%'"
    ).fetchall()
    return render_template("search.html", q=q, rows=rows, user=current_user())


# ---------------------------------------------------------------------- Fichiers
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not current_user():
        return redirect("/login")
    message = None
    if request.method == "POST":
        f = request.files["file"]
        # VULN: aucune validation d'extension/type, nom de fichier non assaini
        f.save(os.path.join(UPLOAD_DIR, f.filename))
        message = "Fichier envoye : " + f.filename
    files = os.listdir(UPLOAD_DIR)
    return render_template("upload.html", message=message, files=files, user=current_user())


@app.route("/download")
def download():
    if not current_user():
        return redirect("/login")
    name = request.args.get("file", "")
    # VULN: path traversal (../../etc/passwd)
    return send_file(os.path.join(UPLOAD_DIR, name))


@app.route("/uploads/<path:name>")
def serve_upload(name):
    # VULN: les fichiers deposes (html, svg...) sont servis tels quels -> XSS stocke
    return send_file(os.path.join(UPLOAD_DIR, name))


# ----------------------------------------------------------------- Outils admin
@app.route("/admin/diagnostic", methods=["GET", "POST"])
def diagnostic():
    # VULN: controle d'acces base sur un cookie modifiable par le client
    if request.cookies.get("role") != "admin":
        return "Acces refuse", 403
    output = None
    if request.method == "POST":
        host = request.form["host"]
        # VULN: injection de commande (shell=True / os.popen)
        output = os.popen("ping -c 1 " + host).read()
    return render_template("diagnostic.html", output=output, user=current_user())


@app.route("/preview")
def preview():
    if not current_user():
        return redirect("/login")
    url = request.args.get("url", "")
    content = None
    if url:
        # VULN: SSRF - l'URL est fournie par l'utilisateur sans filtrage
        content = requests.get(url, timeout=5).text[:2000]
    return render_template("preview.html", url=url, content=content, user=current_user())


@app.route("/import", methods=["GET", "POST"])
def import_tickets():
    if not current_user():
        return redirect("/login")
    result = None
    if request.method == "POST":
        data = request.form["data"]
        if request.form.get("format") == "pickle":
            # VULN: deserialisation pickle non sure -> RCE
            obj = pickle.loads(base64.b64decode(data))
        else:
            # VULN: yaml.load avec le Loader complet -> RCE
            obj = yaml.load(data, Loader=yaml.Loader)
        result = repr(obj)
    return render_template("import.html", result=result, user=current_user())


@app.errorhandler(500)
def handle_500(e):
    import traceback
    return "<pre>" + traceback.format_exc() + "</pre>", 500  # VULN: fuite d'informations


if __name__ == "__main__":
    init_db()
    # VULN: mode debug actif (console Werkzeug) et ecoute sur toutes les interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
