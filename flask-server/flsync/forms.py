from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FileField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Length, EqualTo, equal_to


class LoginForm(FlaskForm):
    username = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    submit = SubmitField("Login")


class UploadFileForm(FlaskForm):
    file = FileField(validators=[DataRequired()])
    submit = SubmitField("Upload")

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class ResetRequestForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired()])
    submit = SubmitField('Request Password Reset')
