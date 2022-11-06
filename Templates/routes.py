@app.route('/signup', methods = ["GET", "POST"])
def signMeUp():
    form = SignUp()
    if request.method == "POST":
        if form.validate():
            username = form.username.data
            email = form.email.data
            password = form.password.data
            my_user = User(username, email, password)
            my_user.saveToDB()
            return redirect(url_for('logMeIn'))
    return render_template('signup.html', s=form)
@app.route('/login', methods = ["GET", "POST"])
def logMeIn():
    form = Login()
    if request.method == "POST":
        print('post method made')
        if form.validate():
            username = form.username.data
            password = form.password.data
            print(username, password)
            user = User.query.filter_by(username=username).first()
            if user:
                if check_password_hash(user.password, password):
                    print('successfully logged in')
                    login_user(user)
                    return redirect(url_for('realHomePage'))
                else:
                    print('incorrect password')
            else:
                print('user does not exist')
    return render_template('login.html', form=form)
@app.route('/logout')
def logMeOut():
    logout_user()
    return redirect(url_for('logMeIn'))
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, EqualTo, InputRequired
class SignUp(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirmpassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField()
class Login(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField()
from werkzeug.security import check_password_hash
from flask_login import login_user, logout_user, current_user, login_required