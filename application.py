from flask import Flask, session, render_template, redirect, url_for, request, flash, json, g
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import login_user, logout_user, current_user, login_required
from werkzeug import generate_password_hash, check_password_hash
from datetime import date, datetime
from flask.ext.login import LoginManager
import datetime as dt
from application import db
from application.models import User, Product, Bid



application = Flask(__name__)

application.secret_key = "super secret key"
application.config["DEBUG"] = True
'''
SQLALCHEMY_DATABASE_URI = "mysql+pymysql://{username}:{password}@{hostname}/{databasename}".format(
    username="flaskdemo",
    password="flaskdemo",
    hostname="flaskdemo.cwsaehb7ywmi.us-east-1.rds.amazonaws.com:3306",
    databasename="flaskdemo",
)
application.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
application.config["SQLALCHEMY_POOL_RECYCLE"] = 299

db = SQLAlchemy(application)
'''
# Flask Login
login_manager = LoginManager()
login_manager.init_app(application)




@application.before_request
def before_request():
    g.user = current_user


@login_manager.user_loader
def load_user(id):
    '''method used by Flask-Login to get
    key for login user. query.get is for primary keys'''
    return User.query.get(int(id))


@application.route('/')
def main():
    #return 'Hello ganesh from Flask!'
    if 'user_id' in session:
        user = User.query.filter_by(id = session['user_id']).first()
        username_session = user.username
        return render_template('index.html', session_user_name=username_session)
    return render_template('index.html')

@application.route('/showSignUp')
def showSignUp():
    return render_template('signup.html')

@application.route('/login' ,methods=['POST','GET'])
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


@application.route('/logout')
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


@application.route('/products' ,methods=['POST','GET'])
def products():
    p = Product()
    query = p.query.order_by(p.owner_id).all()
    numOfRows = len(query)
    print("%d",numOfRows)
    user = User.query.filter_by(id = session['user_id']).first()
    username_session = user.username
    return render_template('products.html',obj=query,session_user_name=username_session)
    #return render_template('products.html')

@application.route('/Register',methods=['POST','GET'])
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

    application.debug = True
    application.run(host='0.0.0.0')

