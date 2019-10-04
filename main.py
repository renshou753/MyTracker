#!/home/tony/miniconda3/bin/python

from flask import Flask, url_for, flash, redirect, session, request, logging, render_template, make_response, jsonify
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, DateField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import pickle
import os.path
import jwt 
import datetime
import requests

app = Flask(__name__)

# config sql
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'tracker'
app.config['MYSQL_PASSWORD'] = 'thisismytracker'
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
    result = cur.execute("select * from AccItems where author = %s order by added_date desc", [session['username']])
    AccItems = cur.fetchall()

    if result > 0:
        return render_template('accomplishment.html', AccItems=AccItems)
    else:
        msg = 'No item found'
        return render_template('accomplishment.html', msg=msg)
    cur.close()

@app.route('/viewByType')
@is_logged_in
def ViewByType():
    # sql cursor
    cur = mysql.connection.cursor()
    result = cur.execute("select * from AccItems where author = %s order by added_date desc", [session['username']])
    AccItems = cur.fetchall()

    if result > 0:
        return render_template('viewByType.html', AccItems=AccItems)
    else:
        msg = 'No item found'
        return render_template('viewByType.html', msg=msg)
    cur.close()

@app.route('/viewByMonth')
@is_logged_in
def ViewByMonth():
    # sql cursor
    cur = mysql.connection.cursor()
    result = cur.execute("select id, item, type, extract(year_month from added_date) as added_date from AccItems where author = %s", [session['username']])
    AccItems = cur.fetchall()

    if result > 0:
        return render_template('viewByMonth.html', AccItems=AccItems)
    else:
        msg = 'No item found'
        return render_template('viewByMonth.html', msg=msg)
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
    AccType = StringField('Categorization', [validators.Length(max=200)])
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


class ToDoItemForm(Form):
    item = StringField('Item', [validators.Length(min=1, max=200)])
    Target_Date = DateField('Target Deadline', format='%Y-%m-%d')
    Type = StringField('Categorization', [validators.Length(max=200)])
    description = TextAreaField('Description', [validators.Length(max=3000)])

# add item in accomplishment page
@app.route('/add_todo_item', methods = ['GET','POST'])
@is_logged_in
def add_todo_item():
    form = ToDoItemForm(request.form)
    if request.method == 'POST' and form.validate():
        item = form.item.data
        TargetDate = form.Target_Date.data
        Type = form.Type.data
        description = form.description.data

        # sql cursor
        cur = mysql.connection.cursor()
        cur.execute('insert into ToDoItems(item, type, description, target_date, author) values(%s, %s, %s, %s, %s)', (item, Type, description, TargetDate, session['username']))
        mysql.connection.commit()
        cur.close()
        flash('Item added', 'success')
        return redirect(url_for('ToDoBoard'))
    return render_template('add_todo_item.html', form=form)

# edit items in to do tab
@app.route('/edit_todo/<string:id>', methods=['GET','POST'])
@is_logged_in
def edit_todo(id):
    # sql cursor
    cur = mysql.connection.cursor()
    result = cur.execute("select * from ToDoItems where id = %s", [id])
    ToDoItem = cur.fetchone()
    cur.close()

    # get form
    form = ToDoItemForm(request.form)
    form.item.data = ToDoItem['item']
    form.Target_Date.data = ToDoItem['target_date']
    form.Type.data = ToDoItem['type']
    form.description.data = ToDoItem['description']

    if request.method == 'POST' and form.validate():
        item = request.form['item']
        TargetDate = request.form['Target_Date']
        Type = request.form['Type']
        description = request.form['description']

        # sql cursor
        cur = mysql.connection.cursor()
        app.logger.info(item)
        cur.execute('update ToDoItems set item = %s, target_date = %s, type = %s, description = %s where id = %s', (item, TargetDate, Type, description, id))
        mysql.connection.commit()
        cur.close()
        flash('Item updated', 'success')
        return redirect(url_for('ToDoBoard'))
    return render_template('edit_todo.html', form=form)

# Delete to do item
@app.route('/delete_todo/<string:id>', methods=['POST'])
@is_logged_in
def delete_todo(id):
    # sql cursor
    cur = mysql.connection.cursor()
    cur.execute("delete from ToDoItems where id = %s", [id])
    mysql.connection.commit()
    cur.close()

    flash('Item deleted', 'Success')

    return redirect(url_for('ToDoBoard'))

# archive to do item
@app.route('/archive_todo/<string:id>', methods=['POST'])
@is_logged_in
def archive_todo(id):
    # sql cursor
    cur = mysql.connection.cursor()
    result = cur.execute("select * from ToDoItems where id = %s", [id])
    ToDoItem = cur.fetchone()
    cur.close()

    Item = ToDoItem['item']
    Type = ToDoItem['type']
    Description = ToDoItem['description']

    # sql cursor
    cur = mysql.connection.cursor()
    cur.execute('insert into AccItems(item, type, description, author) values(%s, %s, %s, %s)', (Item, Type, Description, session['username']))
    cur.execute("delete from ToDoItems where id = %s", [id])
    mysql.connection.commit()
    cur.close()

    flash('Item archived', 'Success')
    return redirect(url_for('ToDoBoard'))

@app.route('/ToDoBoard')
@is_logged_in
def ToDoBoard():
    # sql cursor
    cur = mysql.connection.cursor()
    result = cur.execute("select * from ToDoItems where author = %s order by target_date asc", [session['username']])
    ToDoItems = cur.fetchall()

    if result > 0:
        return render_template('ToDoBoard.html', ToDoItems=ToDoItems)
    else:
        msg = 'No item found'
        return render_template('ToDoBoard.html', msg=msg)
    cur.close()

@app.route('/gantt')
@is_logged_in
def gantt():
    # sql cursor
    cur = mysql.connection.cursor()
    result = cur.execute("select id, item, type, description, added_date, target_date, author, datediff(target_date, added_date) as total_days, datediff(target_date, now()) as left_days from ToDoItems where author = %s order by target_date asc", [session['username']])
    ToDoItems = cur.fetchall()
    return render_template('gantt.html', ToDoItems = ToDoItems)


class WhiteBoardForm(Form):
    content = TextAreaField('Content', [validators.Length(max=3000)])

@app.route('/WhiteBoard', methods = ['GET','POST'])
@is_logged_in
def WhiteBoard():

    if os.path.isfile("content.pickle"):
        pickle_in = open("content.pickle", "rb")
        content = pickle.load(pickle_in)
        pickle_in.close()

        form = WhiteBoardForm(request.form)
        form.content.data = content

    if request.method == 'POST' and form.validate():
        # get form
        form = WhiteBoardForm(request.form)
        content = form.content.data
        pickle_out = open("content.pickle", "wb")
        pickle.dump(content, pickle_out)
        pickle_out.close()
        flash('Saved', 'success')
        return redirect(url_for('WhiteBoard'))
    return render_template('WhiteBoard.html', form=form)

# Create an api log in portal in order to generate and distribute a jwt token
@app.route('/apilogin')
def apilogin():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate':'Log in required'})

    ## sql cursor
    cur = mysql.connect.cursor()

    result = cur.execute("select * from users where username = %s", [auth.username])
    
    if result > 0:
        # get hash password
        data = cur.fetchone()
        cur.close()

        password = data['password']

        # compare password
        if sha256_crypt.verify(auth.password, password):
            # matched
            token = jwt.encode({'username':auth.username, 'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.secret_key)
            return jsonify({'token': token.decode('utf-8')})
        else:
            return make_response('Could not verify', 401, {'WWW-Authenticate':'Log in required'})

    else:
        return make_response('Could not verify', 401, {'WWW-Authenticate':'Log in required'})

# Decorator to decode token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token'] 
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
       
        try:
            data = jwt.decode(token, app.secret_key)
        except:
            return jsonify({'message': 'Token is invalid'}), 403
        
        return f(*args, **kwargs)
    return decorated

# put user activity to the database
@app.route('/user/<username>/<activity>', methods=['POST'])
@token_required
def upload_activity(username, activity):
    r = request.get_json()

    ## sql cursor
    cur = mysql.connection.cursor()
    try:
        cur.execute("insert into activities(name, start_time, end_time, days, minutes, hours, seconds, author) values(%s, %s, %s, %s, %s, %s, %s, %s)", (activity, r['start_time'], r['end_time'], r['days'], r['hours'], r['minutes'], r['seconds'], username))
        mysql.connection.commit()
        return jsonify({'message': 'activity uploaded'})
    except:
        return jsonify({'message': 'uploading failed'})
    finally:
        cur.close()

# query user activities
@app.route('/user/activities/<username>', methods=['GET'])
@token_required
def search_user_activity(username):
    ## sql cursor
    cur = mysql.connection.cursor()
    try:
        result = cur.execute("select * from activities where author = %s order by start_time desc", [username])
        items = cur.fetchall()
        return jsonify(items)
    except:
        return jsonify({'message': 'action failed'})
    finally:
        cur.close()

if __name__=='__main__':
    app.secret_key='aceapisawesome'
    app.run(host='0.0.0.0', port=5050, debug=True)
