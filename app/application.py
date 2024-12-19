import sqlite3
import logging
import secrets
import os
import bcrypt
from flask import Flask, session, redirect, url_for, request, render_template, abort


app = Flask(__name__)
# Read the FLASK_SECRET_KEY environment variable and assign it to the app.secret_key variable
# If this environment variable is not set, generate one
app.secret_key = os.getenv("FLASK_SECRET_KEY", default=secrets.token_hex()).encode()
app.logger.setLevel(logging.INFO)


def get_db_connection():
    """
    Connects to the sqlite database and creates it if it doesn't exist. Returns the database connection so it can be used.
    """
    connection = sqlite3.connect("database.db")
    connection.row_factory = sqlite3.Row
    return connection

def init_sqlite():
    """
    Initializes the sqlite database to be used by the application. Creates appropriate tables and an admin user if they don't already exist.
    """
    # Read the ADMIN_PASSWORD environment variable and assign it to the password variable
    password = os.getenv("ADMIN_PASSWORD")
    # Deletes it after assigning it to a python variable to prevent it from being read
    del os.environ["ADMIN_PASSWORD"]
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, hash BLOB NOT NULL)")
    try:
        # Try to hash the password with a randomly generated salt
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        # Add the admin user and the password hash to the database
        cursor.execute("INSERT INTO users (username, hash) VALUES (?, ?)", ("admin", pw_hash))
        connection.commit()
    except sqlite3.IntegrityError as e:
        # If sqlite returns an Integrity Error this means the admin user already exists, it can be safely ignored
        app.logger.warning(f"{e} - A user with this username already exists. The password has not been changed.")
    except AttributeError as e:
        # If an AttributeError is returned, it means that bcrypt tried to hash a password of type NULL, this means the environment variable wasn't set
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()   
        if users:
            # If the Admin user is already in the database, this can be safely ignored
            app.logger.debug(e)
        else:
            # If the admin user is not yet in the database, exit and return an error to set the password.
            app.logger.error(e)
            exit()
    connection.close()
# Run the function before starting the webapplication
init_sqlite()

def is_authenticated():
    """
    This function checks if the user currently has a session.
    """
    if "username" in session:
        return True
    return False

def authenticate(username, password, ip):
    """
    This function is run when a user logs in. It takes the username, password and ip-address of the login attempt. If the username matches a user in the database
    and the password matches the hashed password in the database, the user gets a session. The IP address of the login attempts is being logged.
    """
    connection = get_db_connection()
    # Fetch all users in the database
    users = connection.execute("SELECT * FROM users").fetchall()
    connection.close()

    for user in users:
        # If the username is in the database and the password matches the password hashed by bcrypt
        if user["username"] == username and bcrypt.checkpw(password.encode('utf-8'),user['hash']) == True:
            # Give the user a session and log it
            app.logger.info(f"the user '{username}' logged in successfully from { ip }")
            session["username"] = username
            return True
    # Else, log and refuse the login attempt
    app.logger.warning(f"the user '{ username }' failed to log in from { ip }")
    abort(401)


@app.route("/")
def index():
    return render_template("index.html", is_authenticated=is_authenticated())


@app.route("/login", methods=["GET", "POST"])
"""
Attempts to authenticate with the requested username and password
"""
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        ip = request.remote_addr
        if authenticate(username, password, ip):
            return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout")
"""
Removes the user from the session list
"""
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
