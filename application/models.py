from application import db
from flask import Flask, session, render_template, redirect, url_for, request, flash, json, g
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import login_user, logout_user, current_user, login_required
from werkzeug import generate_password_hash, check_password_hash
from datetime import date, datetime
from flask.ext.login import LoginManager
import datetime as dt




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

