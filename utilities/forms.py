from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectMultipleField
from wtforms.widgets import TextArea
from wtforms.validators import InputRequired, Email, Length

# https://subscription.packtpub.com/book/web-development/9781784393656/3/ch03lvl1sec22/flask-wtforms
# WTForms is a library that handles server form validation for you by checking input against common form types.
# Flask WTForms is a Flask extension on top of WTForms that add features, such as Jinja HTML rendering, 
# and protects you against attacks, such as SQL injection and cross-site request forgery.

class RegisterForm(FlaskForm):
		email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
		username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
		password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class LoginForm(FlaskForm):
	username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class EncryptForm(FlaskForm):
	password = PasswordField('password', validators=[InputRequired(), Length(min=16, max=16)])

class NoteForm(FlaskForm):
	content = StringField("content", validators=[InputRequired(), Length(min=1)], widget=TextArea())

class ShareForm(FlaskForm):
	username = StringField("username", validators=[InputRequired()])