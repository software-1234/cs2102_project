from __main__ import app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import *
import enum
from sqlalchemy.orm import column_property

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, AnonymousUserMixin
import datetime

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

    def __init__(self, u, p, a, c, d):
        self.user_id = u
        self.set_password(p)
        self.address = a
        self.contact_number = c
        self.display_name = d
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

    def get_display_name(self):
        return unicode(self.display_name)

    def get_user(self, uid):
        return Users.query.filter_by(user_id = uid).first()

    def __repr__(self):
        return "<User(user id='%s')>" % (self.user_id)

class Anonymous(AnonymousUserMixin):
    def __init__(self):
        self.user_id = 'Guest'

    def is_admin(self):
        return False

    def is_authenticated(self):
        return False

    def get_user(self, uid):
        return Users.query.filter_by(user_id = uid).first()


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
    last_updated = Column('last_updated', DateTime, default=datetime.datetime.now , onupdate=datetime.datetime.now)

    def __init__(self, ds, de, a, t, d, m):
        self.employer_user_id = current_user.get_id()
        self.datetime_start = ds
        self.datetime_end = de
        self.address = a
        self.title = t
        self.description = d
        self.min_bid = m

    def __repr__(self):
        return "<Tasks(task_id='%s')>" % (self.task_id)

class Bids(db.Model):
    __tablename__ = 'bids'
    bid_id = Column('bid_id', Integer, primary_key=True, autoincrement=True)
    task_id = Column('task_id', Integer, ForeignKey("tasks.task_id"), primary_key=True, nullable=False)
    user_id = Column('user_id', String, ForeignKey("users.user_id"), primary_key=True, nullable=False)
    last_updated = Column('last_updated', DateTime, default=datetime.datetime.now , onupdate=datetime.datetime.now)
    bid_amount = Column('bid_amount', Numeric, default=0.00)
    status = Column('status', db.Enum('Pending','Accepted', 'Rejected', name = 'status'), default='Pending')
    comment = Column('comment', String)
    UniqueConstraint('task_id', 'user_id')

    def __init__(self, ti, ui, ba, co):
        self.task_id = ti
        self.user_id = ui
        self.bid_amount = ba
        self.comment = co

    def __repr__(self):
        return "<Bids(bid_id='%s', task_id='%s', user_id='%s')>" % (self.bid_id, self.task_id, self.user_id)

# Create tables.
def create_db(drop_all):
    if(drop_all):
        db.drop_all()
    db.create_all()

# admin user
def add_admin():
    if Users.query.filter_by(admin=True).first() is None:
        admin_user = Users("admin", "1", "1", "1", "admin")
        admin_user.admin = True
        db.session.add(admin_user)
        db.session.commit()

def add_test_data():
    users = []
    users.append(Users("user1","user1", "Fictitious Street 1", "98765432", "John Doe1"))
    users.append(Users("user2","user2", "Fictitious Street 2", "98765432", "John Doe2"))
    users.append(Users("user3","user3", "Fictitious Street 3", "98765432", "John Doe3"))
    users.append(Users("user4","user4", "Fictitious Street 4", "98765432", "John Doe4"))
    users.append(Users("user5","user5", "Fictitious Street 5", "98765432", "John Doe5"))
    users.append(Users("user6","user6", "Fictitious Street 6", "98765432", "John Doe6"))
    users.append(Users("user7","user7", "Fictitious Street 7", "98765432", "John Doe7"))
    users.append(Users("user8","user8", "Fictitious Street 8", "98765432", "John Doe8"))
    users.append(Users("user9","user9", "Fictitious Street 9", "98765432", "John Doe9"))
    users.append(Users("user10","user10", "Fictitious Street 10", "98765432", "John Doe10"))
    for user in users:
        db.session.add(user)
        db.session.commit()