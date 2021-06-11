from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FileField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    username = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    submit = SubmitField("Login")


class UploadFileForm(FlaskForm):
    file = FileField(validators=[DataRequired()])
    submit = SubmitField("Upload")
