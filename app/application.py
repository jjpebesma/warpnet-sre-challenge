import sqlite3
import logging
import secrets
import os
from flask import Flask, session, redirect, url_for, request, render_template, abort


app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", default=secrets.token_hex()).encode()
app.logger.setLevel(logging.INFO)


def get_db_connection():
    connection = sqlite3.connect("database.db")
    connection.row_factory = sqlite3.Row
    return connection

def init_sqlite():
    password = os.getenv("ADMIN_PASSWORD")
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL)")
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", password))
        connection.commit()
    except sqlite3.IntegrityError as e:
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        if "NOT NULL" in str(e):
            if not users:
                exit(e)
            else:
                app.logger.info(e)
        else:
            app.logger.warning(e)
    connection.close()
init_sqlite()

def is_authenticated():
    if "username" in session:
        return True
    return False


def authenticate(username, password):
    connection = get_db_connection()
    users = connection.execute("SELECT * FROM users").fetchall()
    connection.close()

    for user in users:
        if user["username"] == username and user["password"] == password:
            app.logger.info(f"the user '{username}' logged in successfully")
            session["username"] = username
            return True

    app.logger.warning(f"the user '{ username }' failed to log in")
    abort(401)


@app.route("/")
def index():
    return render_template("index.html", is_authenticated=is_authenticated())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if authenticate(username, password):
            return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
