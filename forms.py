from flask_wtf import Form
from wtforms import TextField, PasswordField, StringField
from wtforms.fields.html5 import TelField
from wtforms.validators import DataRequired, EqualTo, Length

# Set your classes here.


class RegisterForm(Form):
    user_id = StringField(
        'User ID' , validators=[DataRequired(), Length(max=25)]
    )
    password_hash = PasswordField(
        'Password' , validators=[DataRequired(), Length(max=40)]
    )
    confirm = PasswordField(
        'Repeat Password' , [DataRequired(), EqualTo('password', message='Passwords must match')]
    )
    address = StringField(
        'Address' , validators=[DataRequired(), Length(max=40)]
    )
    contact_number = StringField(
        'Contact Number' , validators=[DataRequired(), Length(max=40)]
    )


class LoginForm(Form):
    user_id = TextField('User ID', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])


class ForgotForm(Form):
    email = TextField(
        'Email', validators=[DataRequired(), Length(min=6, max=40)]
    )
