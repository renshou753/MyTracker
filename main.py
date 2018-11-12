from flask import Flask, url_for, flash, redirect, session, request, logging, render_template
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# config sql
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'tracker'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/accomplishment')
def accomplishment():
    return render_template('accomplishment.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        ## Get Fields
        username = request.form['username']
        password_candidate = request.form['password']

        ## sql cursor
        cur = mysql.connect.cursor()

        result = cur.execute("select * from users where username = %s", [username])

        if result > 0:
            # get hash password
            data = cur.fetchone()
            password = data['password']
    
            # compare password
            if sha256_crypt.verify(password_candidate, password):
                # matched
                session['logged_in'] = True
                session['username'] = username
    
                ## flash message showing logged in
                flash('You are now logged in')
                return redirect(url_for('register'))
            else:
                error = 'Password does not match'
                return render_template('login.html', error=error)
    
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

# register form class
class RegisterForm(Form):
    name = StringField("Name", [validators.Length(min=1, max=30)])
    username = StringField("Username", [validators.Length(min=4, max=20)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [validators.DataRequired(), validators.EqualTo('confirm', message = 'password does not match')])
    confirm = PasswordField('Confirm password')

# User register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        ## sql cursor
        cur = mysql.connection.cursor()
        cur.execute("insert into users(name, email, username, password) values(%s, %s, %s, %s)", (name, email, username, password))
        mysql.connection.commit()
        cur.close()
        
        ## flash message to indicate user has logged in
        flash("you have logged in")
        
        return redirect(url_for('login'))
    return render_template('accomplishment.html', form=form)

# check if logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kargs):
        if 'logged_in' in session:
            return f(*args, **kargs)
        else:
            flash('please log in first')
            return redirect(url_for('login'))
    return wrap

# loutout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('you are now logged out')
    return redirect(url_for('login'))

if __name__=='__main__':
    app.secret_key='secret123'
    app.run(debug=True)


