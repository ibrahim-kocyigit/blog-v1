from flask import Flask, render_template, url_for, request, flash, redirect, abort
from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user, login_required
from flask_ckeditor import CKEditor
from flask_bootstrap import Bootstrap
from flask_gravatar import Gravatar
from flask_migrate import Migrate
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from forms import RegisterForm, LoginForm, CreatePostForm, CommentForm
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from itsdangerous import URLSafeSerializer, BadSignature
from dotenv import load_dotenv
import os

app = Flask(__name__)
load_dotenv()

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = os.getenv("MAIL_PORT")
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

db = SQLAlchemy(app)
migrate = Migrate(app, db)
ckeditor = CKEditor(app)
login_manager = LoginManager()
login_manager.init_app(app)
mail = Mail(app)
serializer = URLSafeSerializer(app.config['SECRET_KEY'])
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None
                    )


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Congigure Tables
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    type = db.Column(db.String(20), nullable=True)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(250), unique=True, nullable=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    category = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String(1000), nullable=False)
    is_approved = db.Column(db.Boolean, nullable=False, default=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")
    parent_post_id = db.Column(db.Integer, db.ForeignKey("posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


# db.create_all()


# Configure extra functions and variables
year = date.today().year


def requires_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            return func(*args, **kwargs)
        else:
            flash("You have to login first.")
            return redirect(url_for('login'))
    return wrapper


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            if current_user.id != 1:
                abort(403)
            return func(*args, **kwargs)
        except AttributeError:
            abort(403)
    return wrapper


# Configure Routes
@app.route('/')
def home():
    requested_posts = BlogPost.query.all()
    category = None
    if request.args.get("category"):
        requested_posts = BlogPost.query.filter_by(
            category=request.args.get("category")).all()
        category = request.args.get("category")
    requested_posts = [post for post in reversed(requested_posts)]
    return render_template('index.html', category=category, requested_posts=requested_posts, title="Home", year=year)


@app.route('/post/<post_url>', methods=["GET", "POST"])
def show_post(post_url):
    requested_post = BlogPost.query.filter_by(url=post_url).first()
    form = CommentForm()
    approved_comments = []
    for comment in requested_post.comments:
        if comment.is_approved == True:
            approved_comments.append(comment)
    if request.method == "GET":
        return render_template('show-post.html', approved_comments=approved_comments, form=form, post=requested_post, title=requested_post.title, year=year)
    if form.validate_on_submit():
        new_comment = Comment(
            author=current_user,
            comment=form.comment.data,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        flash("Thank you for your comment. It will be published after admin's approval.")
        return redirect(url_for('show_post', approved_comments=approved_comments, post_url=requested_post.url))
    else:
        return render_template('show-post.html', approved_comments=approved_comments, form=form, post=requested_post, title=requested_post.title, year=year)


@app.route('/admin-page-82', methods=["GET", "POST"])
@admin_only
def admin():
    comments = Comment.query.all()
    unapproved_comments = [
        comment for comment in comments if comment.is_approved == False]
    if request.method == "GET":
        return render_template('admin.html', unapproved_comments=unapproved_comments, title="Welcome, master!", year=year)


@app.route('/new-post', methods=["GET", "POST"])
@admin_only
def new_post():
    form = CreatePostForm()
    if request.method == "GET":
        return render_template('new-post.html', form=form, title="Add New Post", year=year)
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            url=form.url.data.lower(),
            category=form.category.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('show_post', post_url=new_post.url))
    else:
        return render_template('new-post.html', form=form, title="Add New Post", year=year)


@app.route('/edit-post/<int:post_id>', methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm()
    if request.method == "GET":
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            url=post.url,
            category=post.category,
            body=post.body,
            img_url=post.img_url,
            author=current_user,
        )
        return render_template('new-post.html', form=edit_form, title="Edit Post", year=year)
    elif request.method == "POST" and edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.body = edit_form.body.data
        post.category = edit_form.category.data
        post.img_url = edit_form.img_url.data
        post.url = edit_form.url.data
        db.session.commit()
        return redirect(url_for('show_post', post_url=post.url))
    else:
        return render_template('new-post.html', form=edit_form, title="Edit Post", year=year)


@app.route('/delete-post/<int:post_id>')
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/delete-comment/<int:comment_id>')
@admin_only
def delete_comment(comment_id):
    comment_to_delete = Comment.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('admin'))


@app.route('/approve-comment/<int:comment_id>')
@admin_only
def approve_comment(comment_id):
    comment_to_approve = Comment.query.get(comment_id)
    comment_to_approve.is_approved = 1
    db.session.commit()
    return redirect(url_for('admin'))


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "GET":
        return render_template('login.html', form=form, title="Login", year=year)
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash("There is no user associated with this email. Try again or register.")
            return render_template('login.html', form=form, title="Login", year=year)
        if check_password_hash(user.password, form.password.data):
            login_user(user)
            if user.type == "Pending":
                flash("In order to complete your registration, please click on the confirmation link we've sent to your email address.")
                return redirect(url_for('home'))
            return redirect(url_for('home'))
        else:
            flash("Wrong password. Please try again.")
            return render_template('login.html', form=form, title="Login", year=year)
    else:
        return render_template('login.html', form=form, title="Login", year=year)


@app.route('/logout', methods=["GET", "POST"])
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "GET":
        return render_template('register.html', title="Register", form=form, year=year)
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash("This email has already registered. Try to login instead.")
            return redirect(url_for('login'))
        new_user = User(
            name=form.name.data,
            username=form.username.data,
            email=form.email.data,
            type="Pending",
            password=generate_password_hash(
                form.password.data, method="pbkdf2:sha256", salt_length=8)
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        # Send confirmation link via email
        email = new_user.email
        token = serializer.dumps(email, salt='email-confirm')
        confirm_link = url_for('confirm_email', token=token, _external=True)
        msg = Message('Email Confirmation', sender=(
            'Ibrahim', 'ibrahim.software.development@gmail.com'), recipients=[email])
        msg.html = f"Hello {new_user.name}, <p> Thank you for registering. Here is your email confirmation link:</p><p><a href='{confirm_link}' target='_blank'>{confirm_link}</a></p><p>Ibrahim</p>"
        mail.send(msg)
        # Redirect to homepage with a flask message
        flash("Thank you for signing up. In order to complete your registration, please click on the confirmation link we've sent to your email address.")
        return redirect(url_for('home'))
    else:
        return render_template('register.html', title="Register", form=form, year=year)


@app.route('/confirm_email/<token>')
@requires_login
def confirm_email(token):
    try:
        confirmation = serializer.loads(token, salt='email-confirm')
    except BadSignature:
        flash(
            "Confirmation failed. Please try clicking on the confirmation link again.")
        return redirect(url_for('home'))
    else:
        user = User.query.filter_by(email=current_user.email).first()
        user.type = "Reader"
        db.session.commit()
        flash(
            "Your email address is confirmed. Now you can add comments to the blog posts.")
        return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
    # app.run(host='192.168.1.37', port=5000, debug=True, threaded=True)
