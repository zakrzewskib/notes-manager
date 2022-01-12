from flask import Flask, render_template, redirect, url_for, flash, session

from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# https://flask-login.readthedocs.io/en/latest/#login-using-authorization-header
# Flask-Login provides user session management for Flask. 
# 
# It handles the common tasks of logging in, logging out, and remembering your users’ sessions over extended periods of time.

# It will:

# Store the active user’s ID in the session, and let you log them in and out easily.
# Let you restrict views to logged-in (or logged-out) users.
# Handle the normally-tricky “remember me” functionality.
# Help protect your users’ sessions from being stolen by cookie thieves.
# Possibly integrate with Flask-Principal or other authorization extensions later on.
# However, it does not:

# Impose a particular database or other storage method on you. You are entirely in charge of how the user is loaded.
# Restrict you to using usernames and passwords, OpenIDs, or any other method of authenticating.
# Handle permissions beyond “logged in or not.”
# Handle user registration or account recovery.

from utilities.forms import RegisterForm, LoginForm, EncryptForm, NoteForm, ShareForm
from utilities.keys import generateSecretKey
from utilities.hashing import checkIfHashedPasswordIsCorrect, hashPassword
from utilities.entropy import calculateEntropy, printHowStrongIsYourPassword
from utilities.checkingInputformat import checkUsername, checkEmail

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = generateSecretKey()

db = SQLAlchemy(app)

Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
		id = db.Column(db.Integer, primary_key=True)
		username = db.Column(db.String(15), unique=True)
		email = db.Column(db.String(50), unique=True)
		password = db.Column(db.String(80))
		notes = db.relationship('Note', backref='user', lazy='dynamic')

class Note(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	content = db.Column(db.String())
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	password = db.Column(db.String())
	isEncrypted = db.Column(db.Boolean())
	isPublic = db.Column(db.Boolean())
	sharedToUser = db.Column(db.String())

@login_manager.user_loader
def load_user(user_id):
		return User.query.get(int(user_id))

@app.route('/logout')
@login_required
def logout():
		session['attempt'] = 0
		logout_user()
		return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
		notes = current_user.notes
		publicNotes = Note.query.filter_by(isPublic=True) # and user_id!=current_user.get_id()
		sharedNotes = Note.query.filter_by(sharedToUser=current_user.username)
		return render_template('index.html', notes=notes, name=current_user.username, publicNotes=publicNotes, sharedNotes=sharedNotes)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
		form = RegisterForm()
	
		if form.validate_on_submit():
				if not checkUsername(form.username.data):
						return '<h1>Wrong username format!</h1>'

				if not checkEmail(form.email.data):
						return '<h1>Wrong email format!</h1>'

				if User.query.filter_by(username=form.username.data).first() != None and form.username.data == User.query.filter_by(username=form.username.data).first().username:
					return '<h1>User with that username already exist!</h1>'

				hashed_password = hashPassword(form.password.data)
				new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)

				db.session.add(new_user)
				db.session.commit()
				flash(printHowStrongIsYourPassword(calculateEntropy(form.password.data)))
				return redirect(url_for('login'))

		return render_template('signup.html', form=form)

import time
@app.route('/login', methods=['GET', 'POST'])
def login():
		form = LoginForm()

		if not 'attempt' in session:
			session['attempt'] = 0
		
		if session['attempt'] >= 3:
			return '<h1>Too many login attempts!</h1>'

		if form.validate_on_submit():
				session['attempt'] = session['attempt'] + 1
				# time.sleep(3)

				if not checkUsername(form.username.data):
					return '<h1>Wrong username format!</h1>'

				user = User.query.filter_by(username=form.username.data).first()
				if user:
						if checkIfHashedPasswordIsCorrect(user.password, form.password.data):
								login_user(user, remember=True)
								return redirect(url_for('index'))

				flash(f"Login attempts: {session['attempt']}")
				return render_template('login.html', form=form), 403
				# A 403 status code indicates that the client cannot access the requested resource. 
				# That might mean that the wrong username and password were sent in the request, 
				# or that the permissions on the server do not allow what was being asked.

		return render_template('login.html', form=form)

from utilities.encryption import encryptMessage, decryptMessage

tag = None
nonce = None
@app.route('/encrypt/<id>', methods=['GET', 'POST'])
@login_required
def encrypt(id):
		note = current_user.notes.filter_by(id=id).first()
		if note == None:
		 		return '<h1>This note does not belong to you!</h1>', 401 # 401 Unauthorized
		if note.isEncrypted == 1:
			return '<h1>This note is already encrypted </h1>', 405 # 405 Method Not Allowed The request method is known by the server but is not supported by the target resource.
		if note.isPublic == 1:
			return '<h1>This note is public, You cannot encrypt it </h1>', 405

		form = EncryptForm()

		if form.validate_on_submit():
			note.isEncrypted = 1
			#  [note.content, tag, nonce] = encryptMessage(note.content, form.password.data)
			note.content = encryptMessage(note.content, form.password.data)
			note.password = hashPassword(form.password.data)
			db.session.commit()
			flash(printHowStrongIsYourPassword(calculateEntropy(form.password.data)))
			return redirect(url_for('index'))

		return render_template('encrypt.html', form=form, note=note)

@app.route('/decrypt/<id>', methods=['GET', 'POST'])
@login_required
def decrypt(id):
		form = EncryptForm()
		note = current_user.notes.filter_by(id=id).first()
		if note == None:
		 		return '<h1>This note does not belong to you!</h1>', 401
		if note.isEncrypted == 0:
			return '<h1>This note is not encrypted!</h1>', 405

		if form.validate_on_submit():
				if checkIfHashedPasswordIsCorrect(note.password, form.password.data):
					note.isEncrypted = 0
					# note.content = decryptMessage(note.content, tag, nonce, form.password.data)
					note.content = decryptMessage(note.content, form.password.data)
					note.password = ''
					db.session.commit()
					return redirect(url_for('index'))
				return '<h1>Invalid password</h1>'

		return render_template('decrypt.html', form=form, note=note)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
		form = NoteForm()

		if form.validate_on_submit():
				note = Note(content=form.content.data, user_id=current_user.get_id(), isEncrypted=False)
				db.session.add(note)
				db.session.commit()
				return redirect(url_for('index'))

		return render_template('create.html', form=form)

@app.route('/makePublic/<id>', methods=['GET'])
@login_required
def makePublic(id):
		note = current_user.notes.filter_by(id=id).first()
		if note == None:
		 		return '<h1>This note does not belong to you!</h1>', 401
		if note.isEncrypted == 1:
			return '<h1>This note is encrypted, You cannot share it </h1>', 405

		note.isPublic = True
		db.session.commit()

		return redirect(url_for('index'))

from utilities.rsa.encryption import encryptWithSomeonesPublicKey, decryptWithPrivateKey
@app.route('/share/<id>', methods=['GET', 'POST'])
@login_required
def share(id):
		note = current_user.notes.filter_by(id=id).first()
		if note == None:
		 		return '<h1>This note does not belong to you!</h1>', 401
		if note.isEncrypted == 1:
			return '<h1>This note is encrypted, You cannot share it </h1>', 405

		form = ShareForm()
		if form.validate_on_submit():
			if not checkUsername(form.username.data):
				return '<h1>Wrong username format!</h1>'
			user = User.query.filter_by(username=form.username.data).first()
			if user != None:
				f = open('key.pub', 'rb')
				public = f.read()
				note.content = encryptWithSomeonesPublicKey(public, note.content)
				note.sharedToUser = form.username.data
				db.session.commit()
				return redirect(url_for('index'))
			return '<h1>User with that name does not exist!</h1>'
					
		return render_template('share.html', form=form, note=note)

if __name__ == "__main__":
		# app.run(debug=True, ssl_context=('utilities/https/certificate-signed.crt', 'utilities/https/key.key'))
		app.run(debug=True)