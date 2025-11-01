
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField

class loginForm(FlaskForm):
    username = StringField("Enter Username")
    password = PasswordField("Password")
    recaptcha = RecaptchaField()
    submit = SubmitField("Login")

class mfaForm(FlaskForm):
    code = StringField("Enter Code")
    submit = SubmitField("Submit")


