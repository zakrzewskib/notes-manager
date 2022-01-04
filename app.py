from flask import Flask, render_template, redirect, url_for, flash

from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from utilities.forms import RegisterForm, LoginForm, EncryptForm, NoteForm
from utilities.keys import generateSecretKey
from utilities.hashing import checkIfHashedPasswordIsCorrect, hashPassword
from utilities.entropy import calculateEntropy, printHowStrongIsYourPassword

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

@login_manager.user_loader
def load_user(user_id):
		return User.query.get(int(user_id))

@app.route('/logout')
@login_required
def logout():
		logout_user()
		return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
		notes = current_user.notes
		publicNotes = Note.query.filter_by(isPublic=True) # and user_id!=current_user.get_id()
		return render_template('index.html', notes=notes, name=current_user.username, publicNotes=publicNotes)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
		form = RegisterForm()

		if form.validate_on_submit():
				if User.query.filter_by(username=form.username.data).first() != None and form.username.data == User.query.filter_by(username=form.username.data).first().username:
					return redirect(url_for('signup'))

				hashed_password = hashPassword(form.password.data)
				new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)

				db.session.add(new_user)
				db.session.commit()
				flash(printHowStrongIsYourPassword(calculateEntropy(form.password.data)))
				return redirect(url_for('login'))

		return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
		form = LoginForm()

		if form.validate_on_submit():
				user = User.query.filter_by(username=form.username.data).first()
				if user:
						if checkIfHashedPasswordIsCorrect(user.password, form.password.data):
								login_user(user, remember=True)
								return redirect(url_for('index'))

				return '<h1>Invalid username or password</h1>'

		return render_template('login.html', form=form)

from utilities.encryption import encryptMessage, decryptMessage

@app.route('/encrypt/<id>', methods=['GET', 'POST'])
@login_required
def encrypt(id):
		note = current_user.notes.filter_by(id=id).first()
		if note == None:
		 		return '<h1>This note does not belong to you!</h1>'
		if note.isEncrypted == 1:
			return '<h1>This note is already encrypted </h1>'
		if note.isPublic == 1:
			return '<h1>This note is public, You cannot encrypt it </h1>'

		form = EncryptForm()

		if form.validate_on_submit():
			note.isEncrypted = 1
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
		 		return '<h1>This note does not belong to you!</h1>'
		if note.isEncrypted == 0:
			return '<h1>This note is not encrypted!</h1>'

		if form.validate_on_submit():
				if checkIfHashedPasswordIsCorrect(note.password, form.password.data):
					note.isEncrypted = 0
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
		 		return '<h1>This note does not belong to you!</h1>'
		if note.isEncrypted == 1:
			return '<h1>This note is encrypted, You cannot share it </h1>'

		note.isPublic = True
		db.session.commit()

		return redirect(url_for('index'))

if __name__ == "__main__":
		app.run(debug=True)