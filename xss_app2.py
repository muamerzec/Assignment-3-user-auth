from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
import qrcode
from io import BytesIO
from PIL import Image
import base64



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'secret_key'
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
limiter = Limiter(
    key_func=get_remote_address,
)
limiter.init_app(app)




class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    totp_secret = db.Column(db.String(16))
    

def generate_totp_secret():
    return pyotp.random_base32()

def generate_totp_uri(username, secret, issuer_name='YourApp'):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class PostForm(FlaskForm):
    title = TextAreaField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])

class CommentForm(FlaskForm):
    comment_content = TextAreaField('Comment', validators=[DataRequired()])

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'), nullable=False)




@app.route('/', methods=['GET', 'POST'])
def home():
    post = BlogPost.query.all()
    post_form = PostForm()
    comment_form = CommentForm()
    

    return render_template('home.html', post=post, post_form=post_form, comment_form=comment_form, csrf=csrf)

@app.route('/create_post', methods=['POST'])
@login_required
def create_post():
    post_form = PostForm()
    if post_form.validate_on_submit():
        title = post_form.title.data
        content = post_form.content.data
        new_post = BlogPost(title=title, content=content)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('home'))
    return redirect(url_for('home'))

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
@login_required 
def post(post_id):
    post = BlogPost.query.get_or_404(post_id)

    comment_form = CommentForm()
    if comment_form.validate_on_submit(): 
        comment_content = comment_form.comment_content.data

        print("Submitted Comment Content:", comment_content)
        
        new_comment = Comment(content=comment_content, post=post)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('post', post_id=post_id))

    return render_template('post.html', post=post, comment_form=comment_form)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required 
def delete_post(post_id):
    post = BlogPost.query.get_or_404(post_id)


    db.session.delete(post)
    db.session.commit()

    return redirect(url_for('home'))

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required 
def add_comment(post_id):
    post = BlogPost.query.get_or_404(post_id)

    comment_form = CommentForm(request.form)
    if comment_form.validate():
        comment_content = comment_form.comment_content.data

        new_comment = Comment(content=comment_content, post=post)
        db.session.add(new_comment)
        db.session.commit()

    return redirect(url_for('home'))

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required  # Require login for deleting
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    post = comment.post

    db.session.delete(comment)
    db.session.commit()

    return redirect(url_for('post', post_id=post.id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username is already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        totp_secret = generate_totp_secret()
        user = User(username=form.username.data, password=hashed_password, totp_secret=totp_secret)
        db.session.add(user)
        db.session.commit()

        totp_uri = generate_totp_uri(form.username.data, totp_secret)
        img = qrcode.make(totp_uri)
        img_bytes = BytesIO()
        img.save(img_bytes)
        img_str = base64.b64encode(img_bytes.getvalue()).decode('utf-8')
        flash('Your account has been created! Scan the QR code below with your authenticator app.', 'success')
        return render_template('register.html', form=form, totp_qr_code=img_str)

    return render_template('register.html', form=form)

def correct_login(username, password):
    user = User.query.filter_by(username=username).first()
    return user and bcrypt.check_password_hash(user.password, password)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("3 per minute", exempt_when=lambda: correct_login(request.form.get('username'), request.form.get('password'))) 
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if 'totp' in request.form:
                totp = pyotp.TOTP(user.totp_secret)
                if totp.verify(request.form['totp']):
                    limiter.reset()
                    login_user(user)
                    flash('Login successful!', 'success')
                    return redirect(url_for('home'))
                else:
                    flash('Invalid TOTP. Please try again.', 'danger')
            else:
                flash('Please enter your TOTP.', 'warning')
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    # Use app context to create the database tables
    with app.app_context():
        db.create_all()

    app.run(debug=True)