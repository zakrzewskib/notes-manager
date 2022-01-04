from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectMultipleField
from wtforms.widgets import TextArea
from wtforms.validators import InputRequired, Email, Length

class RegisterForm(FlaskForm):
		email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
		username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
		password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class LoginForm(FlaskForm):
	username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class EncryptForm(FlaskForm):
	password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class NoteForm(FlaskForm):
	content = StringField("content", validators=[InputRequired()], widget=TextArea())

class ShareForm(FlaskForm):
	username = StringField("username", validators=[InputRequired()])