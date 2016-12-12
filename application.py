from flask import Flask, session, render_template, redirect, url_for, request, flash, json, g
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import login_user, logout_user, current_user, login_required
from werkzeug import generate_password_hash, check_password_hash
from datetime import date, datetime
from flask.ext.login import LoginManager
import datetime as dt
from application import db
from application.models import User, Product, Bid
from flask_socketio import SocketIO, send, emit, join_room, leave_room, rooms, close_room
import functools
from flask_socketio import disconnect

async_mode = None

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
socketio = SocketIO(application, async_mode=async_mode)
thread = None


def background_thread():
    """Example of how to send server generated events to clients."""
    count = 0
    while True:
        socketio.sleep(10)
        p_state = Product()
        query_state = p_state.query.order_by(p_state.id).all()
        for index in range(len(query_state)):
            bid_status = query_state[index].get_bid_status()
            if bid_status == "bidding expired":
               announced = query_state[index].get_sold()
               print(announced)
               if not announced:
                      high_bid = query_state[index].get_highest_bid()
                      if not (high_bid is None):
                         user_high = User.query.filter_by(id = high_bid.get_bidder()).first()
                         username_high = user_high.first_name
                         print('username is', username_high)
                         product_high = query_state[index].get_title()
                         print('product is', product_high)			
                         socketio.emit('my_response',
                         {'data': 'Auction Closed', 'cnt':'for', 'product': product_high, 'wnr':'And the Winner is', 'winner':username_high},
                         broadcast = True,namespace='/test')
                         #query_state[index].sold = True


@application.before_request
def before_request():
    g.user = current_user


@login_manager.user_loader
def load_user(id):
    '''method used by Flask-Login to get
    key for login user. query.get is for primary keys'''
    return User.query.get(int(id))

def authenticated_only(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            disconnect()
        else:
            return f(*args, **kwargs)
    return wrapped

'''
@socketio.on('connect', namespace='/test')
def test_connect():
     print ("connection call")
     #console.log('a user connected');
     emit('my response', {'data': 'Connected'})

#    if current_user.is_authenticated:
#         emit('my response', {'data': 'Connected'})
#    else:
#         return False
'''
@socketio.on('connect', namespace='/test')
def test_connect():
    global thread
    if thread is None:
        thread = socketio.start_background_task(target=background_thread)
    if current_user.is_authenticated:
        user_room = 'user_{}'.format(session['user_id'])
        join_room(user_room)
        emit('my_response', {'data': 'Connected', 'count': 0})

@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected',request.sid)


@socketio.on('my_event', namespace='/test')
def test_msg(message):
    print('Socket id is %s',message['data'])

@authenticated_only
def test_message():
    socketio.emit('my response', {'data': 'You are connected'}, broadcast=True, namespace='/test')
    #emit('new_msg', {msg: 'hello'},broadcast=True);


@socketio.on('send_message')
def handle_source(json_data):
    text = json_data['message'].encode('ascii', 'ignore')
    socketio.emit('myrespone', {'echo': 'Server Says: '+text})


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
                        test_message()
                        msg = "Welcome TO Ebidding  %s ." % user.first_name
                        flash(msg)
                        #return redirect(request.args.get('next') or url_for('main'))
                        return redirect(url_for('main'))
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
    uid = session['user_id']
    if uid in clients:
       del clients[uid]
    del session['user_id']
    logout_user()
    msg = "%s Logged out." % user.first_name
    flash(msg)
    return redirect(url_for('main'))


@login_required
@application.route('/products' ,methods=['POST','GET'])
def products():
    p = Product()
    query = p.query.order_by(p.owner_id).all()
    user = User.query.filter_by(id = session['user_id']).first()
    username_session = user.username
    if request.method == 'POST':
        try:
            pname = request.form['inputPname']
            ptype = request.form['inputPtype']
            sbid = request.form['inputSbid']
            owner = user.get_id()           
            if pname and ptype and sbid :
                    p = Product(
                            owner_id = owner,
                            title = pname,
                            saleDuration = 5,
                            product_type = ptype,
                            starting_bid = sbid,
                            )

                    db.session.add(p)
                    db.session.commit()
                    msg = "New Product %s added." % pname
                    flash(msg)
                    query = p.query.order_by(p.owner_id).all()
                    user = User.query.filter_by(id = session['user_id']).first()
                    username_session = user.username
                    return render_template('products.html',obj=query,session_user_name=username_session)
            else:
                flash('Enter all the Required Fields')
                p = Product()
                user = User.query.filter_by(id = session['user_id']).first()
                username_session = user.username
                return render_template('products.html',obj=query,session_user_name=username_session)

        except Exception as e:
            return json.dumps({'error':str(e)})

                
    return render_template('products.html',obj=query,session_user_name=username_session)
    #return render_template('products.html')

@login_required
@application.route('/bids' ,methods=['POST','GET'])
def bids():
    p_bids = Product()
    query = p_bids.query.order_by(p_bids.owner_id).all()
    user_bids = User.query.filter_by(id = session['user_id']).first()
    username_session = user_bids.username
    if request.method == 'POST':
        try:
            bptype = request.form['inputBptype']
            bprice = request.form['inputBprice']
            owner = user_bids.get_id()           
            if bptype and bprice:
                    b = Bid(
                            bidder = owner,
                            product = bptype,
                            bid_price = bprice,
                            )

                    db.session.add(b)
                    db.session.commit()
                    msg = "New bid added."
                    flash(msg)
                    p = Product()
                    query = p.query.order_by(p.owner_id).all()
                    user = User.query.filter_by(id = session['user_id']).first()
                    username_session = user.username
                    return render_template('products.html',obj=query,session_user_name=username_session)
            else:
                flash('Enter all the Required Fields')
                p = Product()
                user = User.query.filter_by(id = session['user_id']).first()
                username_session = user.username
                return render_template('products.html',obj=query,session_user_name=username_session)

        except Exception as e:
            return json.dumps({'error':str(e)})

    return render_template('products.html',obj=query,session_user_name=username_session)
                
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
    #application.run(host='0.0.0.0')
    socketio.run(application,host='0.0.0.0')
    #socketio.run(application,host='0.0.0.0',logger=True, engineio_logger=True)

