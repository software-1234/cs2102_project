from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

#----------------------------------------------------------------------------#
# Database schema
#----------------------------------------------------------------------------#

class User(UserMixin, db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.String, primary_key = True)
    password_hash = db.Column(db.String, nullable = False)
    address = db.Column(db.String, nullable = False)
    contact_number = db.Column(db.String, nullable = False)
    is_admin = db.Column(db.Boolean, default = False)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
