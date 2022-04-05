from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, URL, Length, EqualTo
from flask_ckeditor import CKEditorField


# Configure Forms
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    username = StringField("Username", validators=[Length(
        min=2, max=20, message="2 to 20 characters.")])
    email = StringField("Email", validators=[Email()])
    password = PasswordField("Password", validators=[
                             DataRequired(), Length(min=6, message="At least 6 characters.")])
    confirm_password = PasswordField(
        "Confirm Password", validators=[EqualTo("password", message="Passwords didn't match.")])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class CreatePostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    body = CKEditorField("Post", validators=[DataRequired()])
    category = SelectField("Category", choices=[
        ("Programming"),
        ("Lindy Hop"),
        ("Coffee"),
        ("Novels"),
        ("Miscellaneous"),
    ])
    img_url = StringField("Image URL", validators=[URL()])
    url = StringField("Post Url", validators=[DataRequired()])
    submit = SubmitField("Submit")


class CommentForm(FlaskForm):
    comment = TextAreaField("Comment", validators=[
                            DataRequired(), Length(max=1000)])
    submit = SubmitField("Submit")
