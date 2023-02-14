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
# postgresql://gaurav:sytApgILs5xeFSw2dHPPMUjOfbRlJPU4@dpg-cfjgb31a6gductijtfgg-a.singapore-postgres.render.com/database_li2o
engine = create_engine('postgresql://gaurav:sytApgILs5xeFSw2dHPPMUjOfbRlJPU4@dpg-cfjgb31a6gductijtfgg-a.singapore-postgres.render.com/database_li2o', echo = False)    # , connect_args={"check_same_thread": False} for sqlite3 only
conn = engine.connect()

# Make Tables:
meta = MetaData()
acc_users = Table(
    'acc_users', meta,
    Column('id', Integer, primary_key = True),
    Column('username', Text),
    Column('hash', Text),
    Column('cash', Integer),
    Column('spent', Integer),
    Column('gains', Integer),
    Column('income', Integer),
)

history_t = Table(
    'acc_history', meta,
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
    user = text("SELECT id, cash, spent, income, gains FROM acc_users")
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
        user = text('SELECT username, hash, id FROM acc_users')
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

    user = text('SELECT username, id FROM acc_users')
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

    # id = db.execute('INSERT INTO acc_users(username, hash) VALUES(?, ?)', username, generate_password_hash(password))
    ins = acc_users.insert().values(username = username, hash = generate_password_hash(password), cash = 0, spent = 0, gains = 0, income = 0,)
    conn.execute(ins)

    # To remember the signed in user
    # s = acc_users.select().where(acc_users.c.username == username)
    # result = conn.execute(s)
    # for row in result:
    #     session['user_id'] = row[0]
    if id >= 0:
        session['user_id'] = id + 1
    else:
        return apology('Account Created, Failed to go to the main page, please Login in now.')

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

    user = text("SELECT id, cash FROM acc_users")
    result = conn.execute(user)
    for row in result:
        if row[0] == session["user_id"]:
            i_cash = row[1]
            stmt = acc_users.update().where(acc_users.c.id == session['user_id']).values(cash = cash + i_cash, income = cash)
            conn.execute(stmt)

            return redirect('/')
    return apology('Something Went Wrong')

'''
# STATUS: Done
@app.route("/delete")
@login_required
def delete():
    d_u = acc_users.delete().where(acc_users.c.id == session['user_id'])
    conn.execute(d_u)

    # d_h = history_t.delete().where(acc_history.c.id == session['user_id'])
    # conn.execute(d_h)

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")
'''


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

    user = text("SELECT id, cash, spent FROM acc_users")
    result = conn.execute(user)
    for row in result:
        if row[0] == session["user_id"]:
            check = row[1]
            i_spent = row[2]

            if pay > check:
                return apology('You Don\'t Have Enough Money to make this transactions')

            new_cash = check - pay
            new_spent = i_spent + pay
            up=acc_users.update().where(acc_users.c.id==session['user_id']).values(cash = new_cash, spent = new_spent)
            conn.execute(up)

            if descript == None:
                descript = "Quick Pay"

            ins_s = history_t.insert().values(id = session['user_id'], descript = descript, cashflow = -pay,)
            conn.execute(ins_s)

            return redirect("/")
    return apology("Something Went Wrong")
 

# STATUS: Done
@app.route("/reset")
@login_required
def reset():
    user = text("SELECT id FROM acc_users")
    result = conn.execute(user)
    for row in result:
        if row[0] == session["user_id"]:
            reset = acc_users.update().where(acc_users.c.id == session['user_id']).values(cash = 0, spent = 0, gains = 0, income = 0)
            conn.execute(reset)

            ins = history_t.insert().values(id = session['user_id'], descript = 'RESET', cashflow = 0)
            conn.execute(ins)

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

    
    user = text("SELECT id, cash, gains FROM acc_users")
    result = conn.execute(user)
    for row in result:
        if row[0] == session["user_id"]:
            i_cash = row[1]
            i_gains = row[2]

            stmt = acc_users.update().where(acc_users.c.id == session['user_id']).values(cash = i_cash+gain, gains = i_gains+gain,)
            conn.execute(stmt)

            ins = history_t.insert().values(id = session["user_id"], descript = descript, cashflow = gain,)
            conn.execute(ins)

            return redirect('/')
    return apology('Something Went Wrong')


# STATUS: Done
@app.route("/acc_history")
@login_required
def acc_history():
    # return apology('WILL BE AVAILABLE IN FEW DAYS!')
    # acc_history = db.execute('SELECT descript, cashflow FROM acc_history WHERE id = ?', session['user_id'])
    s = history_t.select().where(history_t.c.id == session['user_id'])
    acc_history = conn.execute(s)
    all_data = []
    for row in acc_history:
        all_data.append(row)
    loop = len(all_data)
    jinga_loop = 0
    descripts = []
    cashf = []

    for i in range(loop):
        his = all_data[loop - i - 1][1]
        if his == "RESET":
            break
        descripts.append(his)
        cashf.append(all_data[loop - i - 1][2])

        jinga_loop += 1
    
    return render_template("acc_history.html", jinga_loop=jinga_loop, descripts=descripts, cashf=cashf)

