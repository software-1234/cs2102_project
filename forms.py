from flask_wtf import Form
from wtforms import TextField, PasswordField, StringField
from wtforms.fields.html5 import TelField, DateTimeLocalField, SearchField, DecimalField, DateTimeField
from wtforms.validators import DataRequired, EqualTo, Length
import datetime

# Set your classes here.


class RegisterForm(Form):
    user_id = StringField(
        'User ID' , validators=[DataRequired(), Length(max=25)]
    )
    password_hash = PasswordField(
        'Password' , validators=[DataRequired(), Length(max=40)]
    )
    confirm = PasswordField(
        'Repeat Password' , [DataRequired(), EqualTo('password_hash', message='Passwords must match')]
    )
    address = StringField(
        'Address' , validators=[DataRequired(), Length(max=40)]
    )
    contact_number = TelField(
        'Contact Number' , validators=[DataRequired(), Length(max=40)]
    )
    display_name = StringField(
        'Display Name' , validators=[DataRequired(), Length(max=40)]
    )


class LoginForm(Form):
    user_id = TextField('User ID', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])


class ForgotForm(Form):
    email = TextField(
        'Email', validators=[DataRequired(), Length(min=6, max=40)]
    )

class AddForm(Form):
    title = StringField(
        'Title' , validators=[DataRequired(), Length(max=50)]
    )
    description = StringField(
        'Description'
    )
    datetime_start = DateTimeField(
        'EX) 2018-04-28 13:00:00' , validators=[DataRequired()], default=datetime.datetime.today
    )
    datetime_end = DateTimeField(
        'EX) 2018-04-28 17:00:00' , validators=[DataRequired()], default=datetime.datetime.today
    )
    address = StringField(
        'Address' , validators=[DataRequired(), Length(max=50)]
    )
    min_bid = DecimalField(
        'Minimun Bid', validators=[DataRequired()]
    )
    datetime_expire = DateTimeField(
        'EX) 2018-04-28 00:00:00' , validators=[DataRequired()], default=datetime.datetime.today
    )

class BidForm(Form):
    bid_amount = DecimalField(
        'Bid at least the minimum amout!' , validators=[DataRequired()]
    )
    comment = StringField(
        'Comment'
    )
