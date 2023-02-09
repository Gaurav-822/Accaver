import os

from cs50 import SQL
# import psycopg2
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# To ignore warnings
import warnings
warnings.filterwarnings('ignore')

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
# db = SQL("sqlite:///data.db")
# conn = psycopg2.connect(database="data_rodq", user = "gaurav", password = "EVH8zrygwNmSvdzcf6yowvQE3yk8To63", host = "dpg-cen85tp4reb386762n1g-a", port = "5432")
# db = conn.cursor()

uri = os.getenv("postgres://gaurav:EVH8zrygwNmSvdzcf6yowvQE3yk8To63@dpg-cen85tp4reb386762n1g-a/data_rodq")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://")
db = SQL(uri)

db.execute("CREATE TABLE tablename (colname SERIAL);")
db.execute("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY NOT NULL, username TEXT NOT NULL, hash TEXT NOT NULL, cash INT, spent INT, gains INT, income INT);")
# db.execute("CREATE UNIQUE INDEX IF NOT EXISTS username ON users (username);")
db.execute("CREATE TABLE IF NOT EXISTS history(id INT NOT NULL, description TEXT, cashflow INT);")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Requires Change
@app.route("/", methods=['GET', 'POST'])
@login_required
def index():
    bank = db.execute("SELECT cash, spent, income, gains FROM users WHERE id=?;", session['user_id'])
    cash = bank[0]['cash']
    spent = bank[0]['spent']
    income = bank[0]['income']
    gains = bank[0]['gains']
    
    return render_template('index.html', cash=cash, spent=spent, income=income, gains=gains)

# Status: DONE
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

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
        rows = db.execute("SELECT * FROM users WHERE username = ?;", request.form.get("username"))

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

# Status: DONE
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

# Status: Done
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    if request.method == "GET":
        return render_template("register.html")
    username = request.form.get('username')
    password = request.form.get('password')
    confirmation = request.form.get('confirmation')

    u = db.execute('SELECT username FROM users;')
    u_l = []
    for i in u:
        u_l.append(i['username'])
    if username == '' or username in u_l:
        return apology('input is blank or the username already exists.')
    u_l = []
    if password == '' or password != confirmation:
        return apology('Password input is blank or the passwords do not match.')

    id = db.execute('INSERT INTO users(username, hash) VALUES(?, ?);', username, generate_password_hash(password))
    session["user_id"] = id

    # Set all values to 0 by default
    db.execute("UPDATE users SET cash = 0, spent = 0, gains = 0, income = 0 WHERE id = ?;", session['user_id'])

    return redirect("/")

@app.route("/about")
@login_required
def about():
    return render_template('about.html')

@app.route("/cashflow", methods=["GET", "POST"])
@login_required
def cashflow():
    if request.method == 'GET':
        return render_template('cashflow.html')
    
    try:
        cash = int(request.form.get('cashflow'))
    except:
        cash = 0
    d = db.execute('SELECT cash FROM users WHERE id = ?;', session['user_id'])
    i_cash = int(d[0]['cash'])
    db.execute('UPDATE users SET cash = ?, income = ? WHERE id = ?;',cash + i_cash , cash, session['user_id'])

    return redirect('/')


@app.route("/delete")
@login_required
def delete():
    db.execute('DELETE FROM users WHERE id = ?;', session['user_id'])
    db.execute('DELETE FROM history WHERE id = ?;', session['user_id'])

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/spent", methods=["GET", "POST"])
@login_required
def spent():
    if request.method == 'GET':
        return render_template('spent.html')

    try:
        pay = int(request.form.get('spent'))
        description = request.form.get('description')
    except:
        pay = 0
    if pay < 0:
        return apology("Set your gains via Gains Section.")

    d = db.execute("SELECT cash, spent FROM users WHERE id = ?;", session['user_id'])
    check = d[0]['cash']
    i_spent = d[0]['spent']

    if pay > check:
        return apology("You Don't Have Enough Money to make this transactions")

    new_cash = check - pay
    new_spent = i_spent + pay
    db.execute("UPDATE users SET cash = ?, spent = ? WHERE id = ?;", new_cash, new_spent, session['user_id'])

    if description == None:
        description = "QUICK PAY"

    db.execute("INSERT INTO history VALUES(?, ?, ?);", session['user_id'], description, -pay)
    return redirect("/")
 

@app.route("/reset")
@login_required
def reset():
    db.execute("UPDATE users SET cash = 0, spent = 0, gains = 0, income = 0 WHERE id = ?;", session['user_id'])
    db.execute("INSERT INTO history VALUES(?, ?, ?);", session['user_id'], "RESET", 0)
    return redirect('/')


@app.route("/gain", methods=["GET", "POST"])
@login_required
def gain():
    if request.method == 'GET':
        return render_template("gain.html")
    
    try:
        gain = int(request.form.get("gain"))
        description = request.form.get("description")
    except:
        gain = 0
    
    if gain < 0:
        return apology("Your Gains cannot be Negative. Register this via Spent Section.")
    d = db.execute("SELECT cash, gains FROM users WHERE id = ?;", session['user_id'])
    i_cash = d[0]['cash']
    i_gains = d[0]['gains']
    db.execute("UPDATE users SET cash = ?, gains = ? WHERE id = ?;", i_cash+gain,i_gains+gain, session['user_id'])
    db.execute("INSERT INTO history VALUES(?, ?, ?);", session['user_id'], description, gain)

    return redirect('/')


@app.route("/history")
@login_required
def history():
    check = db.execute('SELECT username FROM users WHERE id = ?;', session['user_id'])
    if check[0]['username'] == 'admin':
        users = db.execute('SELECT id, username, cash, spent, gains, income FROM users;')
        loop = len(users)
        ids = []
        usernames = []
        cashes = []
        spents = []
        gains = []
        incomes = []

        for i in range(loop):
            ids.append(users[i]['id'])
            usernames.append(users[i]['username'])
            cashes.append(users[i]['cash'])
            spents.append(users[i]['spent'])
            gains.append(users[i]['gains'])
            incomes.append(users[i]['income'])

        return render_template("admin_user_his.html", ids=ids, usernames=usernames, cashes=cashes, spents=spents, gains=gains, incomes=incomes, loop=loop)


    history = db.execute('SELECT description, cashflow FROM history WHERE id = ?;', session['user_id'])
    loop = len(history)
    jinga_loop = 0
    descriptions = []
    cashflows = []

    for i in range(loop):
        his = history[loop - i - 1]['description']
        if his == "RESET":
            break
        descriptions.append(his)
        cashflows.append(history[loop - i - 1]['cashflow'])

        jinga_loop += 1
    return render_template("history.html", jinga_loop=jinga_loop, descriptions=descriptions, cashflows=cashflows)

