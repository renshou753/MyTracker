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

@app.route('/about')
def about():
    return render_template('about.html')

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

@app.route('/accomplishment')
@is_logged_in
def accomplishment():
    # sql cursor
    cur = mysql.connection.cursor()
    result = cur.execute("select * from AccItems where author = %s", [session['username']])
    AccItems = cur.fetchall()

    if result > 0:
        return render_template('accomplishment.html', AccItems=AccItems)
    else:
        msg = 'No item found'
        return render_template('accomplishment.html', msg=msg)
    cur.close()

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
                return redirect(url_for('accomplishment'))
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
        try:
            cur.execute("insert into users(name, email, username, password) values(%s, %s, %s, %s)", (name, email, username, password))
            mysql.connection.commit()
            ## flash message to indicate user has logged in
            flash("your account was created, please log in")
        except:
            flash("your username or email already exist")
            return redirect(url_for('register'))
        finally:
            cur.close()

        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# loutout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('you are now logged out')
    return redirect(url_for('login'))

class AccItemForm(Form):
    item = StringField('Item', [validators.Length(min=1, max=200)])
    AccType = StringField('Type_of_Item', [validators.Length(max=200)])
    description = TextAreaField('Description', [validators.Length(max=3000)])

# add item in accomplishment page
@app.route('/add_acc_item', methods = ['GET','POST'])
@is_logged_in
def add_acc_item():
    form = AccItemForm(request.form)
    if request.method == 'POST' and form.validate():
        item = form.item.data
        AccType = form.AccType.data
        description = form.description.data

        # sql cursor
        cur = mysql.connection.cursor()
        cur.execute('insert into AccItems(item, type, description, author) values(%s, %s, %s, %s)', (item, AccType, description, session['username']))
        mysql.connection.commit()
        cur.close()
        flash('Item added', 'success')
        return redirect(url_for('accomplishment'))
    return render_template('add_acc_item.html', form=form)

# edit items in accomplishment tab
@app.route('/edit_acc/<string:id>', methods=['GET','POST'])
@is_logged_in
def edit_acc(id):
    # sql cursor
    cur = mysql.connection.cursor()
    result = cur.execute("select * from AccItems where id = %s", [id])
    AccItem = cur.fetchone()
    cur.close()

    # get form
    form = AccItemForm(request.form)
    form.item.data = AccItem['item']
    form.AccType.data = AccItem['type']
    form.description.data = AccItem['description']

    if request.method == 'POST' and form.validate():
        item = request.form['item']
        AccType = request.form['AccType']
        description = request.form['description']

        # sql cursor
        cur = mysql.connection.cursor()
        app.logger.info(item)
        cur.execute('update AccItems set item = %s, type = %s, description = %s where id = %s', (item, AccType, description, id))
        mysql.connection.commit()
        cur.close()
        flash('Item updated', 'success')
        return redirect(url_for('accomplishment'))
    return render_template('edit_acc.html', form=form)

# Delete accomplishment
@app.route('/delete_acc/<string:id>', methods=['POST'])
@is_logged_in
def delete_acc(id):
    # sql cursor
    cur = mysql.connection.cursor()
    cur.execute("delete from AccItems where id = %s", [id])
    mysql.connection.commit()
    cur.close()

    flash('Item deleted', 'Success')

    return redirect(url_for('accomplishment'))




if __name__=='__main__':
    app.secret_key='secret123'
    app.run(debug=True)


