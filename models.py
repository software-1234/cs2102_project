from __main__ import app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import *

from werkzeug.security import generate_password_hash, check_password_hash
import  datetime

db = SQLAlchemy(app)

# Set your classes here.
class Users(db.Model):
    __tablename__ = 'users'
    user_id = Column('user_id', String, primary_key=True)
    display_name = Column('display_name', String)
    password_hash = Column('password_hash', String)
    address = Column('address', String)
    contact_number = Column('contact_number', String)
    admin = Column('is_admin', BOOLEAN, default=False)

    def __init__(self, u, p, a, c):
        self.user_id = u
        self.set_password(p)
        self.address = a
        self.contact_number = c
        self.admin = False

    def set_password(self, p):
        self.password_hash = generate_password_hash(p)

    def check_password(self, p):
        return check_password_hash(self.password_hash, p)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def is_admin(self):
        return self.admin

    def get_id(self):
        return unicode(self.user_id)

    def __repr__(self):
        return "<User(user id='%s')>" % (self.user_id)

class Tasks(db.Model):
    __tablename__ = 'tasks'
    task_id = Column('task_id', Integer, primary_key=True, autoincrement=True)
    employer_user_id = Column('employer_user_id', String, ForeignKey("users.user_id"))
    employee_user_id = Column('employee_user_id', String, ForeignKey("users.user_id"), default = None)
    datetime_start = Column('datetime_start', DateTime)
    datetime_end = Column('datetime_end', DateTime)
    address = Column('address', String)
    title = Column('title', String)
    description = Column('description', String)
    min_bid = Column('min_bid', Numeric)
    datetime_expire = Column('datetime_expire', DateTime)
    last_updated = Column('last_updated', DateTime, default=datetime.datetime.now , onupdate=datetime.datetime.now)

    def __init__(self, ds, de, a, t, d, m, dex):
        self.employer_user_id = current_user.get_id()
        self.datetime_start = ds
        self.datetime_end = de
        self.address = a
        self.title = t
        self.description = d
        self.min_bid = m
        self.datetime_expire = dex

    def __repr__(self):
        return "<Tasks(task_id='%s')>" % (self.task_id)

class Bids(db.Model):
    __tablename__ = 'bids'
    task_id = Column('task_id', Integer, ForeignKey("tasks.task_id"), primary_key=True, nullable=False)
    user_id = Column('user_id', String, ForeignKey("users.user_id"), primary_key=True, nullable=False)
    last_updated = Column('last_updated', DateTime, default=datetime.datetime.now , onupdate=datetime.datetime.now)
    bid_amount = Column('bid_amount', Numeric, default=0.00)
    status = Column('status', BOOLEAN, default=False)
    comment = Column('comment', String)

# Create tables.
db.create_all()