import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Query users table for username and cash balance
    userdata = db.execute(
        "SELECT username, cash FROM users WHERE id = ?",
        session["user_id"]
    )

    # Query transactions table for user's share data
    stocks = db.execute(
        "SELECT symbol, SUM(shares) AS shares FROM transactions WHERE user_id = ? GROUP BY symbol",
        session["user_id"]
    )

    total_stocks = 0
    for stock in stocks:
        stock["price"] = lookup(stock["symbol"])["price"]
        stock["total_value"] = stock["shares"] * stock["price"]
        total_stocks = total_stocks + stock["total_value"]
        # Format values after calculations
        stock["price"] = usd(stock["price"])
        stock["total_value"] = usd(stock["total_value"])

    return render_template(
        "index.html",
        username=userdata[0]["username"],
        cash=usd(userdata[0]["cash"]),
        stocks=stocks,
        grand_total=usd(total_stocks + userdata[0]["cash"])
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # POST
    if request.method == "POST":
        # Lookup stock symbol
        quote = lookup(request.form.get("symbol"))
        # Return apology if symbol is not valid
        if quote == None:
            return apology("must provide a valid symbol")

        # Refresh if number of shares is not entered
        if not request.form.get("shares"):
            return redirect("/buy")

        # Convert shares input to integer for further operations
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("must enter a positive integer")

        # Return apology if number of shares is not a positive integer
        if shares < 1:
            return apology("must enter a positive integer")

        # Get user's current cash balance
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        # Render apology if the user cannot afford the number of shares at the current price
        if shares * quote["price"] > cash:
            return apology("insufficient cash")

        # Update users and transactions tables and return apologies for selected exceptions
        try:
            db.execute(
                "INSERT INTO transactions (user_id, symbol, type, shares, price, datetime) VALUES(?, ?, 'Buy', ?, ?, ?)",
                session["user_id"],
                quote["symbol"],
                shares,
                quote["price"],
                str(datetime.now())
            )

            db.execute(
                "UPDATE users SET cash = ? WHERE id = ?",
                cash - shares * quote["price"],
                session["user_id"]
            )
        except Exception as e:
            exc = type(e).__name__
            if exc == "DatabaseError":
                return apology("database error")
            elif exc == "DataError":
                return apology("invalid entry")
            elif exc == "OperationalError":
                return apology("could not be processed")
            elif exc == "IntegrityError":
                return apology("database integrity error")
            else:
                return apology("something has gone wrong")

        # Redirect user to home page
        return redirect("/")

    # GET
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Query transactions table
    transactions = db.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY datetime",
        session["user_id"]
    )

    return render_template(
        "history.html",
        transactions=transactions,
    )


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote"""

    # POST
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide a valid symbol")

        # Lookup entered symbol
        quote = lookup(request.form.get("symbol"))

        # Return apology if symbol is not valid
        if quote == None:
            return apology("must provide a valid symbol")

        # Return quote for queried symbol
        return render_template("quoted.html", quote=quote)

    # GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # POST
    if request.method == "POST":

        # Render an apology if the user’s input is blank
        if not request.form.get("username"):
            return apology("must provide username")

        # Render an apology if any of the password inputs is blank
        if not request.form.get("password"):
            return apology("must provide password")

        if not request.form.get("confirmation"):
            return apology("must repeat password")

        # Render an apology if the passwords do not match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must be the same")

        # Insert the new user into users, storing a hash of the user’s password, not the password itself.
        try:
            db.execute(
                "INSERT INTO users (username, hash) VALUES(?, ?)",
                request.form.get("username"),
                # Hash the user’s password with generate_password_hash
                generate_password_hash(request.form.get("password"),
                                       method='pbkdf2', salt_length=16)
            )
        # Render an apology if the username already exists
        except ValueError:
            return apology("user name already exists")

        return redirect("/")

    # GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        # Lookup stock symbol
        quote = lookup(request.form.get("symbol"))
        # Return apology if symbol is not valid
        if quote == None:
            return apology("must provide a valid symbol")

        # Query transactions table for owned shares
        stocks = db.execute(
            "SELECT symbol, SUM(shares) AS shares FROM transactions WHERE user_id = ? GROUP BY symbol",
            session["user_id"]
        )

        for stock in stocks:
            if stock["symbol"] == request.form.get("symbol").upper():
                # Return apology if no shares of that stock owned
                if stock["shares"] == 0:
                    return apology("you don't own any shares of that stock")
                # Return apology if number of shares is not entered
                elif not request.form.get("shares"):
                    return redirect("/sell")
                # Convert shares input to integer for further operations
                shares = int(request.form.get("shares"))
                # Return apology if number of shares is not a positive integer
                if shares < 1:
                    return apology("must enter a positive number")
                # Return apology if number of shares entered is above quantity owned
                elif shares > stock["shares"]:
                    return apology("you don't have enough shares")

                # Get user's current cash balance
                cash = db.execute("SELECT cash FROM users WHERE id = ?",
                                  session["user_id"])[0]["cash"]

                # Update users and transactions tables and return apologies for selected exceptions
                try:
                    db.execute(
                        "INSERT INTO transactions (user_id, symbol, type, shares, price, datetime) VALUES(?, ?, 'Sell', ?, ?, ?)",
                        session["user_id"],
                        quote["symbol"],
                        0 - shares,
                        quote["price"],
                        str(datetime.now())
                    )

                    db.execute(
                        "UPDATE users SET cash = ? WHERE id = ?",
                        cash + shares * quote["price"],
                        session["user_id"]
                    )
                except Exception as e:
                    exc = type(e).__name__
                    if exc == "DatabaseError":
                        return apology("database error")
                    elif exc == "DataError":
                        return apology("invalid entry")
                    elif exc == "OperationalError":
                        return apology("could not be processed")
                    elif exc == "IntegrityError":
                        return apology("database integrity error")
                    else:
                        return apology("something has gone wrong")

                return redirect("/")

        # Return apology if no transactions found for the entered symbol
        return apology("you don't own any shares of that stock")

    else:
        # Query transactions table for owned shares
        stocks = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol",
                            session["user_id"])

        return render_template("sell.html", stocks=stocks)


@app.route("/account")
@login_required
def account():
    """Display account information"""

    # Query users table for username
    userdata = db.execute(
        "SELECT username, hash FROM users WHERE id = ?",
        session["user_id"]
    )

    return render_template("account.html", username=userdata[0]["username"])


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change password"""

    # POST
    if request.method == "POST":
        # Render an apology if any of the password inputs is blank
        if not request.form.get("password"):
            return apology("must provide password", 403)

        if not request.form.get("new_password"):
            return apology("must provide new password", 403)

        if not request.form.get("confirmation"):
            return apology("must repeat new password", 403)

        # Query database for username
        userdata = db.execute(
            "SELECT hash FROM users WHERE id = ?", session["user_id"]
        )

        # Ensure current password is correct
        if not check_password_hash(
            userdata[0]["hash"], request.form.get("password")
        ):
            return apology("invalid password", 403)

        # Render an apology if the passwords do not match
        if request.form.get("new_password") != request.form.get("confirmation"):
            return apology("new passwords must be the same", 403)

        # Insert the new user into users, storing a hash of the user’s password, not the password itself.
        try:
            db.execute(
                "UPDATE users SET hash = ?",
                # Hash the user’s password
                generate_password_hash(request.form.get("new_password"),
                                       method='pbkdf2', salt_length=16)
            )
        except Exception as e:
            exc = type(e).__name__
            if exc == "DatabaseError":
                return apology("database error")
            elif exc == "DataError":
                return apology("invalid entry")
            elif exc == "OperationalError":
                return apology("could not be processed")
            elif exc == "IntegrityError":
                return apology("database integrity error")
            else:
                return apology("something has gone wrong")

        return redirect("/")

    # GET
    else:
        return render_template("password.html")


@app.route("/deposit", methods=["GET", "POST"])
def deposit():
    """Deposit additional cash"""

    # POST
    if request.method == "POST":

        # Get user's current cash balance
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        # Update users table with amount deposited
        try:
            db.execute(
                "UPDATE users SET cash = ? WHERE id = ?",
                cash + float(request.form.get("amount")),
                session["user_id"]
            )
        except Exception as e:
            exc = type(e).__name__
            if exc == "DatabaseError":
                return apology("database error")
            elif exc == "DataError":
                return apology("invalid entry")
            elif exc == "OperationalError":
                return apology("could not be processed")
            elif exc == "IntegrityError":
                return apology("database integrity error")
            else:
                return apology("something has gone wrong")

        return redirect("/")

    # GET
    else:
        return render_template("deposit.html")
