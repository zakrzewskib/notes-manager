from flask import Flask, render_template, redirect, url_for

from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from utilities.forms import RegisterForm, LoginForm, EncryptForm
from utilities.keys import generateSecretKey

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
		notes = Note.query.filter(Note.user_id == current_user.id)
		return render_template('index.html', notes=notes, name=current_user.username)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
		form = RegisterForm()

		if form.validate_on_submit():
				hashed_password = generate_password_hash(form.password.data, method='sha256')
				new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
				db.session.add(new_user)
				db.session.commit()
				return redirect(url_for('login'))

		return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
		form = LoginForm()

		if form.validate_on_submit():
				user = User.query.filter_by(username=form.username.data).first()
				if user:
						if check_password_hash(user.password, form.password.data):
								login_user(user)
								return redirect(url_for('index'))

				return '<h1>Invalid username or password</h1>'
				# return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

		return render_template('login.html', form=form)

from utilities.encryption import encryptMessage, decryptMessage

@app.route('/encrypt/<id>', methods=['GET', 'POST'])
@login_required
def encrypt(id):
		form = EncryptForm()
		note = Note.query.filter_by(id=id).first()
		if form.validate_on_submit():
			note.isEncrypted = 1

			note.content = encryptMessage(note.content, form.password.data)
			note.password = generate_password_hash(form.password.data, method='sha256')

			db.session.commit()
			return redirect(url_for('index'))
		return render_template('encrypt.html', form=form, note=note)

@app.route('/decrypt/<id>', methods=['GET', 'POST'])
@login_required
def decrypt(id):
	form = EncryptForm()
	note = Note.query.filter_by(id=id).first()

	if form.validate_on_submit():
			if check_password_hash(note.password, form.password.data):
				note.isEncrypted = 0
				note.content = decryptMessage(note.content, form.password.data)
				note.password = ''
				db.session.commit()
				return redirect(url_for('index'))

	return render_template('decrypt.html', form=form, note=note)

if __name__ == "__main__":
	app.run(debug=True)