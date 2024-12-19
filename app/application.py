import sqlite3
import logging
import secrets
import os
import bcrypt
from flask import Flask, session, redirect, url_for, request, render_template, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix


app = Flask(__name__)
# Create a limiter that limits requests based on source address, set the default to 60/min/page and store data in memory.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per minute"],
    storage_uri="memory://",
)
# Read FLASK_SECRET_KEY environment variable if it exists, if it doesn't generate one.
app.secret_key = os.getenv("FLASK_SECRET_KEY", default=secrets.token_hex()).encode()
# Set the log level to info
app.logger.setLevel(logging.INFO)
# Read the environment variable PROXY, if it reads "true", configure the application to read proxy headers.
if os.getenv("PROXY") == "true":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    app.logger.info("Configured application to run behind a proxy")
else:
    app.logger.warn("Configured application to run without a proxy")


def get_db_connection():
    """
    Create the database if it doesn't exist and return the connection.
    """
    connection = sqlite3.connect("data/database.db")
    connection.row_factory = sqlite3.Row
    return connection

def init_sqlite():
    """
    Initializes the sqlite database to be used by the application. Creates appropriate tables and an admin user if they don't already exist.
    """
    # Read the ADMIN_PASSWORD environment variable and assign it to the password variable
    password = os.getenv("ADMIN_PASSWORD")
    # Try to create the data directory
    try:
        os.makedirs("data")
    except OSError as e:
        app.logger.debug(e)
    # Deletes the ADMIN_PASSWORD environment variable after assigning it to a python variable to prevent it from being read
    del os.environ["ADMIN_PASSWORD"]
    connection = get_db_connection()
    cursor = connection.cursor()
    # Create a users table containing a username and a password-generated hash
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
# Ratelimit the login page to 5 requests per user per minute to avoid brute-forcing attacks
@limiter.limit("5/minute", override_defaults=False)
def login():
    """
    Attempts to authenticate with the requested username and password
    """
    if request.method == "POST":
        # Read the username and password from the requests
        username = request.form.get("username")
        password = request.form.get("password")
        ip = request.remote_addr
        # If the username and password combination authenticates correctly
        if authenticate(username, password, ip):
            # Log the user in
            return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    """
    Removes the user from the session list
    """
    session.pop("username", None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
