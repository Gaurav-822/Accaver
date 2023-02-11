import os

from sqlalchemy import create_engine, MetaData, Table, Column, Integer, Text, text, delete, insert
from sqlalchemy.sql.expression import update
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Make Connection to the database
engine = create_engine('postgresql://gaurav:sytApgILs5xeFSw2dHPPMUjOfbRlJPU4@dpg-cfjgb31a6gductijtfgg-a.singapore-postgres.render.com/database_li2o', echo = False)
conn = engine.connect()

# Make Tables:
meta = MetaData()
users = Table(
    'users', meta,
    Column('id', Integer, primary_key = True),
    Column('username', Text),
    Column('hash', Text),
    Column('cash', Integer),
    Column('spent', Integer),
    Column('gains', Integer),
    Column('income', Integer),
)

history = Table(
    'history', meta,
    Column('id', Integer),
    Column('descript', Text),
    Column('cashflow', Integer),
)

meta.create_all(engine)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# STATUS: Done
@app.route("/", methods=['GET', 'POST'])
@login_required
def index():
    user = text("SELECT id, cash, spent, income, gains FROM users")
    result = conn.execute(user)
    for row in result:
        if row[0] == session["user_id"]:
            cash = row[1]
            spent = row[2]
            income = row[3]
            gains = row[4]

            return render_template('index.html', cash=cash, spent=spent, income=income, gains=gains)
            
    return apology('Something Unexpected Happened')

# STATUS: Done
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
        #Can make better
        user = text('SELECT username, hash, id FROM users')
        result = conn.execute(user)
        u_l = []
        id = 0
        for row in result:
            if row[0] == request.form.get("username"):
                if check_password_hash(row[1], request.form.get("password")):
                    session['user_id'] = row[2]
                    return redirect("/")
        
        return apology('Sorry We cannot find you right now')

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

# STATUS: Done
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

# STATUS: Done
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

    user = text('SELECT username, id FROM users')
    result = conn.execute(user)
    u_l = []
    id = 0
    for row in result:
        u_l.append(row[0])
        id = row[1]
    if username == '' or username in u_l:
        return apology('input is blank or the username already exists.')
    u_l = []
    if password == '' or password != confirmation:
        return apology('Password input is blank or the passwords do not match.')

    # id = db.execute('INSERT INTO users(username, hash) VALUES(?, ?)', username, generate_password_hash(password))
    ins = users.insert().values(username = username, hash = generate_password_hash(password), cash = 0, spent = 0, gains = 0, income = 0,)
    conn.execute(ins)

    # To remember the signed in user
    if id >= 0:
        session['user_id'] = id + 1
    else:
        return apology('Something Went Wrong')

    return redirect("/")

# STATUS: Done
@app.route("/about")
@login_required
def about():
    return render_template('about.html')

# STATUS: Done
@app.route("/cashflow", methods=["GET", "POST"])
@login_required
def cashflow():
    if request.method == 'GET':
        return render_template('cashflow.html')
    
    try:
        cash = int(request.form.get('cashflow'))
        if cash < 0:
            return apology("Your Income cannot be negative!")
    except:
        cash = 0

    user = text("SELECT id, cash FROM users")
    result = conn.execute(user)
    for row in result:
        if row[0] == session["user_id"]:
            i_cash = row[1]
            stmt = users.update().where(users.c.id == session['user_id']).values(cash = cash + i_cash, income = cash)
            conn.execute(stmt)

            return redirect('/')
    return apology('Something Went Wrong')


# STATUS: Done
@app.route("/delete")
@login_required
def delete():
    d_u = users.delete().where(users.c.id == session['user_id'])
    conn.execute(d_u)

    # d_h = history.delete().where(history.c.id == session['user_id'])
    # conn.execute(d_h)

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


# STATUS: Done
@app.route("/spent", methods=["GET", "POST"])
@login_required
def spent():
    if request.method == 'GET':
        return render_template('spent.html')

    try:
        pay = int(request.form.get('spent'))
        descript = request.form.get('descript')
    except:
        pay = 0
    if pay < 0:
        return apology("Set your gains via Gains Section.")

    user = text("SELECT id, cash, spent FROM users")
    result = conn.execute(user)
    for row in result:
        if row[0] == session["user_id"]:
            check = row[1]
            i_spent = row[2]

            if pay > check:
                return apology('You Don\'t Have Enough Money to make this transactions')

            new_cash = check - pay
            new_spent = i_spent + pay
            up=users.update().where(users.c.id==session['user_id']).values(cash = new_cash, spent = new_spent)
            conn.execute(up)

            if descript == None:
                descript = "Quick Pay"

            # ins = history.insert().values(id = session['user_id'], descript = descript, cashflow = -pay)
            # conn.execute(ins)

            return redirect("/")
    return apology("Something Went Wrong")
 

# STATUS: Done
@app.route("/reset")
@login_required
def reset():
    user = text("SELECT id FROM users")
    result = conn.execute(user)
    for row in result:
        if row[0] == session["user_id"]:
            stmt = users.update().where(users.c.id == session['user_id']).values(cash = 0, spent = cash, gain = 0, income = 0)
            conn.execute(stmt)

            # ins = history.insert().values(id = session['user_id'], descript = 'RESET', cashflow = 0)
            # conn.execute(ins)

            return redirect('/')
    return apology('Something Went Wrong')


# STATUS: Done
@app.route("/gain", methods=["GET", "POST"])
@login_required
def gain():
    if request.method == 'GET':
        return render_template("gain.html")
    
    try:
        gain = int(request.form.get("gain"))
        descript = request.form.get("descript")
    except:
        gain = 0
        descript = 'Something Went Wrong!'
    
    if gain < 0:
        return apology("Your Gains cannot be Negative. Register this via Spent Section.")

    
    user = text("SELECT id, cash, gains FROM users")
    result = conn.execute(user)
    for row in result:
        if row[0] == session["user_id"]:
            i_cash = row[1]
            i_gains = row[2]

            stmt = users.update().where(users.c.id == session['user_id']).values(cash = i_cash+gain, gains = i_gains+gain,)
            conn.execute(stmt)

            # ins = history.insert().values(id = session["user_id"], descript = descript, cashflow = gain,)
            # conn.execute(ins)

            return redirect('/')
    return apology('Something Went Wrong')


# STATUS: TBD
@app.route("/history")
@login_required
def history():
    return apology('WILL BE AVAILABLE IN FEW DAYS!')
    # history = db.execute('SELECT descript, cashflow FROM history WHERE id = ?', session['user_id'])
    # loop = len(history)
    # jinga_loop = 0
    # descripts = []
    # cashf = []

    # for i in range(loop):
    #     his = history[loop - i - 1]['descript']
    #     if his == "RESET":
    #         break
    #     descripts.append(his)
    #     cashf.append(history[loop - i - 1]['cashflow'])

    #     jinga_loop += 1
    # return render_template("history.html", jinga_loop=jinga_loop, descripts=descripts, cashf=cashf)

