from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///notes.db")


@app.route("/new_note", methods=["GET", "POST"])
@login_required
def new_note():
    """Add a new note to the database"""
    # if user reached via a form by post
    if request.method == "POST":
        # assign variables to the user's input
        tag = request.form.get("tag")
        note = request.form.get("note")
        # check if the user provided valid inputs
        if not note or not tag:
            return apology("You must provide a note and a tag")
        # if the user provided valid input, insert it into database
        db.execute("INSERT INTO notes (note, tag, user_id) VALUES (:note, :tag, :id)",
                   note=note, tag=tag, id=session["user_id"])
        # return a JSON response that note was saved successfully
        return jsonify(True)
    # if the user reached by clicking a link
    else:
        return render_template("new_note.html")


@app.route("/about")
@login_required
def about():
    """Render the about me page"""
    return render_template("about.html")


@app.route("/delete_note", methods=["POST"])
@login_required
def delete_note():
    """Delete the note and return True if successful in JSON"""
    note_id = request.form.get("id")
    db.execute("DELETE FROM notes WHERE id = :id", id=note_id)
    return jsonify(True)


@app.route("/search_note", methods=["POST"])
@login_required
def search_note():
    """Search for the note in database and return the result"""
    # get the user's input and assign it variables
    search_query = '%' + request.form.get("search_query") + '%'
    search_by = request.form.get("search_by")
    # check if user provided a valid input
    if not search_query or not search_by:
        return apology("You must provide a search query")
    # if user wants to search note's text
    if search_by == "note":
        notes = db.execute("SELECT note, tag, id FROM notes WHERE note LIKE :note AND user_id = :id",
                           id=session["user_id"], note=search_query)
        return jsonify(notes)
    # if user wants to search by the tag
    else:
        notes = db.execute("SELECT note, tag, id FROM notes WHERE tag LIKE :tag AND user_id = :id",
                           id=session["user_id"], tag=search_query)
        return jsonify(notes)


@app.route("/")
@login_required
def index():
    """Display all the notes the user has"""

    # get all the user's notes from the database
    notes = db.execute("SELECT note, tag, id FROM notes WHERE user_id = :user_id ORDER BY id DESC", user_id=session["user_id"])

    # pass in all the notes to html webpage to display
    return render_template("index.html", notes = notes, user_id = session["user_id"])


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    # get the username
    username = request.args.get("username")

    # check if the user already exists
    rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)
    if rows or not username:
        return jsonify(False)

    return jsonify(True)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # check if user is already logged in
    try:
        session["user_id"]
    except:
        # Forget any user_id
        session.clear()

        # User reached route via POST (as by submitting a form via POST)
        if request.method == "POST":

            # Ensure username was submitted
            if not request.form.get("username"):
                return apology("must provide username", 403)

            # Ensure password was submitted
            elif not request.form.get("password"):
                return apology("must provide password", 403)

            # Query database for username
            rows = db.execute("SELECT * FROM users WHERE username = :username",
                            username=request.form.get("username"))

            # Ensure username exists and password is correct
            if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
                return apology("invalid username and/or password", 403)

            # Remember which user has logged in
            session["user_id"] = rows[0]["id"]

            # Redirect user to home page
            return redirect("/")

        # User reached route via GET (as by clicking a link or via redirect)
        else:
            return render_template("login.html")
    
    # if a user is already logged-in
    return redirect("/")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # assign varibles to username and password
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")

        # confirm that the user entered a username, password
        if not username:
            return apology("must provide username")
        if not password:
            return apology("must provide password")
        if not confirm_password:
            return apology("must confirm password",)
        # confirm that the user entered correct passwords
        if password != confirm_password:
            return apology("passwords do not match")

        # check the length of password is atleast 8
        if len(password) < 8:
            return apology("passwords must be atleast 8 characters long")

        # check if the user already exists
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)
        if rows:
            return apology("this username is already taken")

        # add user to the database
        db.execute("INSERT INTO users ('username','hash') VALUES (:username,:password)",
                   username=username, password=generate_password_hash(password))

        # Remember which user has logged in
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


# run flask app by running the python file
if __name__ == "__main__":
	app.run()
