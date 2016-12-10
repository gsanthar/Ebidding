from flask import Flask, session, render_template, redirect, url_for, request, flash, json, g
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import login_user, logout_user, current_user, login_required
from werkzeug import generate_password_hash, check_password_hash
from datetime import date, datetime
from flask.ext.login import LoginManager
import datetime as dt


app = Flask(__name__)

app.secret_key = "super secret key"
app.config["DEBUG"] = True

SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="gsanthar",
    password="ganesh123",
    hostname="gsanthar.mysql.pythonanywhere-services.com",
    databasename="gsanthar$encheres",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299

db = SQLAlchemy(app)

# Flask Login
login_manager = LoginManager()
login_manager.init_app(app)


class User(db.Model):
    """This table is used to store User model in the database.
    One User has MANY Book
    One User has MANY Book_Complaints
    One User has MANY Book_Comments
    One User has MANY Book_Ratings
    One User has MANY Bids

    """
    __tablename__ = 'tbl_user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    email = db.Column(db.String(64), unique=True, nullable=False)
    pwdhash = db.Column(db.String(100))
    num_bids = db.Column(db.Integer, default=0)
    num_purchases = db.Column(db.Integer, default=0)
    last_login = db.Column(db.DateTime)
    last_logout = db.Column(db.DateTime)
    num_logins = db.Column(db.Integer, default = 0)
    products = db.relationship('Product', backref='owner', lazy='dynamic')
    bids = db.relationship('Bid', backref='bidder', lazy='dynamic')

    def __init__(self, username, first_name, last_name, email, password):
        self.username = username
        self.first_name = first_name.title()
        self.last_name = last_name.title()
        self.email = email.lower()
        self.set_password(password)

    def set_password(self, password):
        """This method generates SHA-1 string from given input, password."""
        self.pwdhash = generate_password_hash(password)

    def check_password(self, password):
        """This method compares generated SHA-1 Hash to hash in database."""
        return check_password_hash(self.pwdhash, password)

    def increment_login(self):
        """increments User login_count"""
        self.num_logins += 1

    def is_active(self):
        return True

    def get_id(self):
        """returns User's primary key id."""
        return str(self.id)

    def is_authenticated(self):
        """returns False when Users are not logged in."""
        return True



class Product(db.Model):
    """  """
    __tablename__ = "tbl_product"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('tbl_user.id'), nullable=False)
    title = db.Column(db.String(256))
    product_type = db.Column(db.String(256))
    saleDuration = db.Column(db.Integer)
    biddable = db.Column(db.Boolean, nullable=False) # if True, Product can be bid on.
    sale_price = db.Column(db.Float)
    current_bid = db.Column(db.Float)
    starting_bid = db.Column(db.Float)
    date_added = db.Column(db.DateTime)
    sold = db.Column(db.Boolean, default=False)
    bids = db.relationship('Bid', backref='product', lazy='dynamic')


    def get_owner(self):
        return self.owner_id

    def get_saleDuration(self):
        return self.saleDuration

    def get_id(self):
        return self.id

    def get_title(self):
        return self.title

    def get_producttype(self):
        return self.product_type

    def get_biddable(self):
        return self.biddable

    def get_current_bid(self):
        return self.current_bid

    def get_starting_bid(self):
        return self.starting_bid

    def get_date_added(self):
        return self.date_added

    def get_expr_date(self):
        """return date when book should run out of time.
        Assuming that saleDuration is in days. """
        return self.date_added + dt.timedelta(days = self.saleDuration)


    def until_expire_in_mins(self):
        """returns time until book expires in minutes"""
        expr_date = self.get_expr_date()
        delta = expr_date - datetime.utcnow()
        delta_in_mins = int(delta.total_seconds() / 60 )
        return delta_in_mins

    def until_expire_in_hrs(self):
        """returns time until book expires in hours"""
        return (self.until_expire_in_mins() / 60)

    def __init__(self, title=None, saleDuration=None,bookType=None, biddable=None,
            current_bid=None,starting_bid=None, date_added=None, owner=None):
        '''init method. so this only runs during the creation of book object.'''
        self.title = title
        self.saleDuration = saleDuration
        self.bookType = bookType
        self.biddable = biddable
        # force starting_bid to be current_bid
        self.current_bid = current_bid
        self.starting_bid = starting_bid
        self.date_added = datetime.utcnow()
        self.owner = owner






class Bid(db.Model):
    """Table used to track ALL bids created for ALL books."""
    __tablename__ = "bid"
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('tbl_product.id'), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('tbl_user.id'), nullable=False)
    timestamp = db.Column(db.DateTime)
    bid_price = db.Column(db.Float, nullable=False)


    def __init__(self, product, bidder, bid_price):
        self.bidder = bidder
        self.product = product
        self.bid_price = bid_price
        self.timestamp = datetime.utcnow()


@app.before_request
def before_request():
    g.user = current_user


@login_manager.user_loader
def load_user(id):
    '''method used by Flask-Login to get
    key for login user. query.get is for primary keys'''
    return User.query.get(int(id))


@app.route('/')
def main():
    #return 'Hello ganesh from Flask!'
    if 'user_id' in session:
        user = User.query.filter_by(id = session['user_id']).first()
        username_session = user.username
        return render_template('index.html', session_user_name=username_session)
    return render_template('index.html')

@app.route('/showSignUp')
def showSignUp():
    return render_template('signup.html')

@app.route('/login' ,methods=['POST','GET'])
def login():
    if 'user_id' in session:
        user = User.query.filter_by(id = session['user_id']).first()
        username_session = user.username
        return render_template('index.html', session_user_name=username_session)
    if request.method == 'POST':
        try:
            name = request.form['inputName']
            password = request.form['inputPassword']

            # validate the received values
            if name and password:
                    u = User.query.filter_by(username = name.lower()).first()
                    if not u:
                        flash('Username not right: Try Again')
                        return redirect(url_for('login'))
                    if not u.check_password(password):
                        flash('Password not right: Try Again')
                        return redirect(url_for('login'))
                    else:
                        user = User.query.filter_by(username = name.lower()).first()
                        login_user(user)
                        user.last_login = datetime.utcnow()
                        user.increment_login()
                        session['user_id'] = user.id
                        db.session.add(user)
                        db.session.commit()
                        msg = "Welcome TO Ebidding  %s ." % user.first_name
                        flash(msg)
                        return redirect(request.args.get('next') or url_for('main'))
                        #return redirect(url_for('main'))
            else:
                flash('Enter all the Required Fields')
                return redirect(url_for('login'))

        except Exception as e:
            return json.dumps({'error':str(e)})

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    '''
    This function signs the user out of the system
    '''
    user = User.query.filter_by(id = session['user_id']).first()
    user.last_logout = datetime.utcnow()
    # put user_id in session for later use
    db.session.commit()
    # delete session created during login
    del session['user_id']
    logout_user()
    msg = "%s Logged out." % user.first_name
    flash(msg)
    return redirect(url_for('main'))


@app.route('/products' ,methods=['POST','GET'])
def products():
    p = Product()
    query = p.query.order_by(p.owner_id).all()
    numOfRows = len(query)
    print("%d",numOfRows)
    user = User.query.filter_by(id = session['user_id']).first()
    username_session = user.username
    return render_template('products.html',obj=query,session_user_name=username_session)
    #return render_template('products.html')

@app.route('/Register',methods=['POST','GET'])
def Register():
    if request.method == 'POST':
        try:
            fname = request.form['inputFName']
            lname = request.form['inputLName']
            uname = request.form['inputUName']
            email = request.form['inputEmail']
            password = request.form['inputPassword']


            # validate the received values
            if fname and lname and uname and email and password:

                email_check = User.query.filter_by(email = email.lower()).first()
                username_check = User.query.filter_by(username = uname.lower()).first()
                if username_check:
                    flash('Entered Username already taken,try a different one')
                    return redirect(url_for('Register'))
                if email_check:
                    flash('Entered Email already taken,try a different one')
                    return redirect(url_for('Register'))

                else:

                    u = User(
                            username = uname,
                            first_name = fname,
                            last_name = lname,
                            email = email,
                            password = password
                            )

                    db.session.add(u)
                    db.session.commit()
                    msg = "New User %s created." % fname
                    flash(msg)
                    return redirect(url_for('main'))

            else:
                flash('Enter all the Required Fields')
                return redirect(url_for('Register'))

        except Exception as e:
            return json.dumps({'error':str(e)})

    return render_template('signup.html')


if __name__ == "__main__":

    app.debug = True
    app.run()

